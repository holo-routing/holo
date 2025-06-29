//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use derive_new::new;
use holo_utils::ip::IpNetworkKind;

use crate::collections::{
    AreaId, AreaIndex, Areas, Arena, Interfaces, Lsdb, LsdbId,
};
use crate::debug::LsaFlushReason;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::lsdb::{LSA_INFINITY, LsaEntry, LsaEntryFlags};
use crate::northbound::configuration::{AreaCfg, RangeCfg};
use crate::packet::PacketType;
use crate::packet::lsa::{LsaKey, LsaRouterFlagsVersion};
use crate::route::{
    Nexthops, PathType, RouteNetFlags, RouteRtr, SummaryNet, SummaryNetFlags,
    SummaryRtr,
};
use crate::spf::Vertex;
use crate::version::Version;

// OSPF area.
#[derive(Debug)]
pub struct Area<V: Version> {
    // ID.
    pub id: AreaId,
    // Area ID.
    pub area_id: Ipv4Addr,
    // Area configuration data.
    pub config: AreaCfg,
    // Area state data.
    pub state: AreaState<V>,
    // Area ranges.
    pub ranges: HashMap<V::IpNetwork, Range>,
    // Area interfaces.
    pub interfaces: Interfaces<V>,
}

// OSPF area state.
#[derive(Debug)]
pub struct AreaState<V: Version> {
    // LSDB of area-scope LSAs.
    pub lsdb: Lsdb<V>,
    // Indicates whether the area can carry data traffic that neither
    // originates nor terminates in the area itself.
    pub transit_capability: bool,
    // Shortest-path tree.
    pub spt: BTreeMap<V::VertexId, Vertex<V>>,
    // Table of all routers in the area.
    pub routers: BTreeMap<Ipv4Addr, RouteRtr<V>>,
    // Table of summaries originated into this area.
    pub net_summaries: BTreeMap<V::IpNetwork, (u32, SummaryNet<V>)>,
    pub rtr_summaries: BTreeMap<Ipv4Addr, (u32, SummaryRtr<V>)>,
    // Statistics.
    pub spf_run_count: u32,
    pub discontinuity_time: DateTime<Utc>,
    // OSPF version-specific data.
    pub version: V::State,
}

// OSPF area type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AreaType {
    Normal,
    Stub,
    Nssa,
}

// OSPF area range.
#[derive(Debug, Default)]
pub struct Range {
    pub config: RangeCfg,
    pub cost: u32,
}

// Represents the possible locations of the OSPF Options field.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
pub enum OptionsLocation {
    Packet {
        pkt_type: PacketType,
        auth: bool,
        lls: bool,
    },
    Lsa,
}

// OSPF version-specific code.
pub trait AreaVersion<V: Version> {
    // Version-specific area state data.
    type State: Send + Sync + Default + std::fmt::Debug;

    // Return the options associated to the provided area.
    //
    // These options are used for sending OSPF Hello and Database Description
    // packets, as well as for originating specific LSA types.
    fn area_options(
        area: &Area<V>,
        location: OptionsLocation,
    ) -> V::PacketOptions;
}

// ===== impl Area =====

impl<V> Area<V>
where
    V: Version,
{
    // Create new area.
    pub(crate) fn new(id: AreaId, area_id: Ipv4Addr) -> Self {
        Self {
            id,
            area_id,
            config: Default::default(),
            state: Default::default(),
            ranges: Default::default(),
            interfaces: Default::default(),
        }
    }

    // Returns whether this area is active.
    //
    // An area is active as long as it contains at least one operational
    // interface.
    pub(crate) fn is_active(&self, interfaces: &Arena<Interface<V>>) -> bool {
        self.interfaces
            .iter(interfaces)
            .any(|iface| !iface.is_down())
    }

    // Returns whether this is the backbone area.
    pub(crate) fn is_backbone(&self) -> bool {
        self.area_id == Ipv4Addr::UNSPECIFIED
    }

    // Returns the number of ABR routers in this area.
    pub(crate) fn abr_count(&self) -> usize {
        self.state
            .routers
            .values()
            .filter(|router| router.path_type == PathType::IntraArea)
            .filter(|router| router.flags.is_abr())
            .count()
    }

    // Returns the number of ASBR routers in this area.
    pub(crate) fn asbr_count(&self) -> usize {
        self.state
            .routers
            .values()
            .filter(|router| router.path_type == PathType::IntraArea)
            .filter(|router| router.flags.is_asbr())
            .count()
    }
}

// ===== impl AreaState =====

impl<V> Default for AreaState<V>
where
    V: Version,
{
    fn default() -> AreaState<V> {
        AreaState {
            lsdb: Default::default(),
            transit_capability: false,
            spt: Default::default(),
            routers: Default::default(),
            net_summaries: Default::default(),
            rtr_summaries: Default::default(),
            spf_run_count: 0,
            discontinuity_time: Utc::now(),
            version: Default::default(),
        }
    }
}

// ===== global functions =====

pub(crate) fn update_summary_lsas<V>(
    instance: &mut InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    interfaces: &Arena<Interface<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Check ABR status.
    let is_abr = areas.is_abr(interfaces);

    // Clear the summarized flag from all routes.
    for route in instance.state.rib.values_mut() {
        route.flags.remove(RouteNetFlags::SUMMARIZED);
    }

    // Check which routes should be summarized and which area ranges are active.
    for area in areas.iter_mut() {
        update_net_ranges(area, is_abr, instance);
    }

    // Proceed to originate and/or flush summary LSAs as required.
    for area_idx in areas.indexes().collect::<Vec<_>>() {
        update_net_summary_lsas(area_idx, is_abr, instance, areas, lsa_entries);
        update_rtr_summary_lsas(area_idx, is_abr, instance, areas, lsa_entries);
    }
}

fn update_net_ranges<V>(
    area: &mut Area<V>,
    is_abr: bool,
    instance: &mut InstanceUpView<'_, V>,
) where
    V: Version,
{
    // Reset area ranges.
    for range in area.ranges.values_mut() {
        range.cost = 0;
    }

    // Area ranges are only checked when the router is an ABR.
    if is_abr {
        for (prefix, route) in instance
            .state
            .rib
            .iter_mut()
            // Select intra-area routes from this area.
            .filter(|(_, route)| route.path_type == PathType::IntraArea)
            .filter(|(_, route)| route.area_id == Some(area.area_id))
            // Skip unreachable destinations.
            .filter(|(_, route)| route.metric < LSA_INFINITY)
        {
            // Check if the network is not contained in any explicitly
            // configured address range.
            if let Some((_, range)) = area
                .ranges
                .iter_mut()
                .find(|(range_prefix, _)| range_prefix.is_supernet_of(*prefix))
            {
                route.flags.insert(RouteNetFlags::SUMMARIZED);

                // Update range's cost.
                if route.metric > range.cost {
                    range.cost = route.metric;
                }
            }
        }
    }
}

fn update_net_summary_lsas<V>(
    area_idx: AreaIndex,
    is_abr: bool,
    instance: &InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Compute summary routes.
    let area = &areas[area_idx];
    let new_summaries = compute_net_summaries(is_abr, area, instance, areas);

    // Save the old table of summary routes.
    let area = &mut areas[area_idx];
    let mut old_summaries = std::mem::take(&mut area.state.net_summaries);

    // (Re)originate the required Summary-LSAs.
    area.state.net_summaries = new_summaries
        .into_iter()
        .map(|(prefix, new_summary)| {
            let lsa_id = match old_summaries.remove(&prefix) {
                Some((old_lsa_id, old_summary)) => {
                    // Reoriginate summary LSA if the route has changed, reusing
                    // the previous LSA-ID.
                    if new_summary != old_summary {
                        V::lsa_orig_inter_area_network(
                            area,
                            instance,
                            prefix,
                            Some(old_lsa_id),
                            &new_summary,
                        );
                    }
                    old_lsa_id
                }
                None => {
                    // Originate new summary LSA.
                    V::lsa_orig_inter_area_network(
                        area,
                        instance,
                        prefix,
                        None,
                        &new_summary,
                    )
                }
            };

            (prefix, (lsa_id, new_summary))
        })
        .collect();

    // Flush old summaries that are no longer valid.
    let lsa_type = V::type3_summary(instance.config.extended_lsa);
    let lsa_ids = old_summaries.into_values().map(|(lsa_id, _)| lsa_id);
    flush_summary_lsas(lsa_type, lsa_ids, area, instance, lsa_entries);
}

fn update_rtr_summary_lsas<V>(
    area_idx: AreaIndex,
    is_abr: bool,
    instance: &InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Compute summary routes.
    let area = &areas[area_idx];
    let new_summaries = compute_rtr_summaries(is_abr, area, areas);

    // Save the old table of summary routes.
    let area = &mut areas[area_idx];
    let mut old_summaries = std::mem::take(&mut area.state.rtr_summaries);

    // (Re)originate the required Summary-LSAs.
    area.state.rtr_summaries = new_summaries
        .into_iter()
        .map(|(router_id, new_summary)| {
            let lsa_id = match old_summaries.remove(&router_id) {
                Some((old_lsa_id, old_summary)) => {
                    // Reoriginate summary LSA if the route has changed, reusing
                    // the previous LSA-ID.
                    if new_summary != old_summary {
                        V::lsa_orig_inter_area_router(
                            area,
                            instance,
                            router_id,
                            Some(old_lsa_id),
                            &new_summary,
                        );
                    }
                    old_lsa_id
                }
                None => {
                    // Originate new summary LSA.
                    V::lsa_orig_inter_area_router(
                        area,
                        instance,
                        router_id,
                        None,
                        &new_summary,
                    )
                }
            };

            (router_id, (lsa_id, new_summary))
        })
        .collect();

    // Flush old summaries that are no longer valid.
    let lsa_type = V::type4_summary(instance.config.extended_lsa);
    let lsa_ids = old_summaries.into_values().map(|(lsa_id, _)| lsa_id);
    flush_summary_lsas(lsa_type, lsa_ids, area, instance, lsa_entries);
}

fn compute_net_summaries<V>(
    is_abr: bool,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    areas: &Areas<V>,
) -> Vec<(V::IpNetwork, SummaryNet<V>)>
where
    V: Version,
{
    let mut summaries = vec![];

    // Only ABRs should originate summaries.
    if !is_abr {
        return summaries;
    }

    // Add regular summaries and ranges, except for totally stub/NSSA areas.
    if area.config.summary {
        let rsummaries = compute_net_regular_summaries(area, instance);
        summaries.extend(rsummaries);

        let rsummaries = compute_net_range_summaries(area, areas);
        summaries.extend(rsummaries);
    }

    // Add default route for stub/NSSA areas.
    if area.config.area_type != AreaType::Normal {
        let prefix = V::IpNetwork::default(instance.state.af);
        let default_summary = SummaryNet {
            prefix_options: Default::default(),
            metric: area.config.default_cost,
            prefix_sid: Default::default(),
            flags: SummaryNetFlags::empty(),
        };
        summaries.push((prefix, default_summary));
    }

    summaries
}

fn compute_net_regular_summaries<'a, V>(
    area: &'a Area<V>,
    instance: &'a InstanceUpView<'_, V>,
) -> impl Iterator<Item = (V::IpNetwork, SummaryNet<V>)> + 'a
where
    V: Version,
{
    instance
        .state
        .rib
        .iter()
        // AS external routes are never advertised in summary-LSAs.
        .filter(|(_, route)| {
            !matches!(
                route.path_type,
                PathType::Type1External | PathType::Type2External
            )
        })
        // Skip unreachable destinations.
        .filter(|(_, route)| route.metric < LSA_INFINITY)
        // Skip route if it's associated with the area itself.
        .filter(|(_, route)| route.area_id != Some(area.area_id))
        // Only intra-area routes are advertised into the backbone.
        .filter(|(_, route)| {
            route.path_type == PathType::IntraArea || !area.is_backbone()
        })
        // Check if the nexthops associated with this route belong to
        // the area. This is the logical equivalent of a Distance Vector
        // protocol's split horizon logic.
        .filter(|(_, route)| !nexthops_area_check(&route.nexthops, area))
        // Check if the network is not contained in any explicitly
        // configured address range.
        .filter(|(_, route)| {
            // The backbone's configured ranges should be ignored when
            // originating summary-LSAs into transit areas.
            if route.area_id == Some(Ipv4Addr::UNSPECIFIED)
                && area.state.transit_capability
            {
                true
            } else {
                !route.flags.contains(RouteNetFlags::SUMMARIZED)
            }
        })
        // Map to summary route.
        .map(|(prefix, route)| {
            let mut flags = SummaryNetFlags::empty();
            if route.flags.contains(RouteNetFlags::CONNECTED) {
                flags.insert(SummaryNetFlags::CONNECTED);
            }

            let summary = SummaryNet {
                prefix_options: route.prefix_options,
                metric: route.metric,
                prefix_sid: route.prefix_sid,
                flags,
            };
            (*prefix, summary)
        })
}

fn compute_net_range_summaries<'a, V>(
    area: &'a Area<V>,
    areas: &'a Areas<V>,
) -> impl Iterator<Item = (V::IpNetwork, SummaryNet<V>)> + 'a
where
    V: Version,
{
    areas
        .iter()
        // Check all other areas.
        .filter(|other_area| other_area.area_id != area.area_id)
        // The backbone's configured ranges should be ignored when
        // originating summary-LSAs into transit areas.
        .filter(|other_area| {
            !(other_area.is_backbone() && area.state.transit_capability)
        })
        .flat_map(|other_area| {
            // Check the other area's configured ranges.
            other_area
                .ranges
                .iter()
                // Skip inactive ranges.
                .filter(|(_, range)| range.cost != 0)
                // Skip ranges whose advertisement isn't enabled.
                .filter(|(_, range)| range.config.advertise)
                // Map to summary route.
                .map(|(range_prefix, range)| {
                    let summary = SummaryNet {
                        prefix_options: Default::default(),
                        metric: range.config.cost.unwrap_or(range.cost),
                        prefix_sid: Default::default(),
                        flags: SummaryNetFlags::empty(),
                    };
                    (*range_prefix, summary)
                })
        })
}

fn compute_rtr_summaries<V>(
    is_abr: bool,
    area: &Area<V>,
    areas: &Areas<V>,
) -> Vec<(Ipv4Addr, SummaryRtr<V>)>
where
    V: Version,
{
    // Check conditions in which no router summaries should be generated.
    if !is_abr || area.config.area_type != AreaType::Normal {
        return Vec::new();
    }

    areas
        .iter()
        // Check the routing table from all other areas.
        .filter(|area_src| area_src.id != area.id)
        .flat_map(|area_src| area_src.state.routers.iter())
        // Only ASBR routes are advertised in summary-LSAs.
        .filter(|(_, route)| route.flags.is_asbr())
        // Skip unreachable destinations.
        .filter(|(_, route)| route.metric < LSA_INFINITY)
        // Only intra-area routes are advertised into the backbone.
        .filter(|(_, route)| {
            route.path_type == PathType::IntraArea || !area.is_backbone()
        })
        // Check if the nexthops associated with this route belong to
        // the area. This is the logical equivalent of a Distance Vector
        // protocol's split horizon logic.
        .filter(|(_, route)| !nexthops_area_check(&route.nexthops, area))
        // Map to summary route.
        .map(|(router_id, route)| {
            let summary = SummaryRtr {
                options: route.options,
                metric: route.metric,
            };
            (*router_id, summary)
        })
        .collect()

    // TODO: filter-out non-preferred paths.
}

fn nexthops_area_check<V>(
    nexthops: &Nexthops<V::IpAddr>,
    area: &Area<V>,
) -> bool
where
    V: Version,
{
    nexthops.values().any(|nexthop| {
        area.interfaces
            .indexes()
            .any(|iface_idx| nexthop.iface_idx == iface_idx)
    })
}

fn flush_summary_lsas<V>(
    lsa_type: V::LsaType,
    lsa_ids: impl Iterator<Item = u32>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    let lsdb_id = LsdbId::Area(area.id);
    let adv_rtr = instance.state.router_id;

    // Flush previously originated summaries that are no longer valid.
    for lsa_id in lsa_ids {
        let lsa_key = LsaKey::new(lsa_type, adv_rtr, lsa_id.into());
        if let Some((_, lse)) = area.state.lsdb.get(lsa_entries, &lsa_key) {
            instance.tx.protocol_input.lsa_flush(
                lsdb_id,
                lse.id,
                LsaFlushReason::PrematureAging,
            );
        }
    }

    // Flush received self-originated summaries that are no longer valid.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(lsa_entries, lsa_type, adv_rtr)
        .filter(|(_, lse)| lse.flags.contains(LsaEntryFlags::RECEIVED))
    {
        instance.tx.protocol_input.lsa_flush(
            lsdb_id,
            lse.id,
            LsaFlushReason::PrematureAging,
        );
    }
}
