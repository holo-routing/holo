//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::cmp::Ordering;
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use bitflags::bitflags;
use derive_new::new;
use holo_utils::ip::IpAddrKind;
use holo_utils::mpls::Label;
use holo_utils::sr::IgpAlgoType;

use crate::area::Area;
use crate::collections::{Areas, Arena, InterfaceIndex};
use crate::debug::Debug;
use crate::instance::{InstanceCfg, InstanceUpView};
use crate::interface::Interface;
use crate::lsdb::{LsaEntry, LSA_INFINITY};
use crate::packet::lsa::{LsaKey, LsaRouterFlagsVersion};
use crate::spf::{SpfPartialComputation, VertexLsaVersion};
use crate::sr;
use crate::version::Version;

// Network routing table entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteNet<V: Version> {
    pub prefix_options: V::PrefixOptions,
    pub area_id: Option<Ipv4Addr>,
    pub origin: Option<LsaKey<V::LsaType>>,
    pub path_type: PathType,
    pub metric: u32,
    pub type2_metric: Option<u32>,
    pub tag: Option<u32>,
    pub prefix_sid: Option<V::PrefixSid>,
    pub sr_label: Option<Label>,
    pub nexthops: Nexthops<V::IpAddr>,
    pub flags: RouteNetFlags,
}

bitflags! {
    #[derive(Default)]
    pub struct RouteNetFlags: u8 {
        const CONNECTED = 0x01;
        const INSTALLED = 0x02;
        const SUMMARIZED = 0x04;
    }
}

// Router routing table entry.
#[derive(Clone, Debug, Eq, PartialEq, new)]
pub struct RouteRtr<V: Version> {
    pub area_id: Ipv4Addr,
    pub path_type: PathType,
    pub options: V::PacketOptions,
    pub flags: V::LsaRouterFlags,
    pub metric: u32,
    pub nexthops: Nexthops<V::IpAddr>,
}

// Locally originated inter-area "network" route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SummaryNet<V: Version> {
    pub prefix_options: V::PrefixOptions,
    pub metric: u32,
    pub prefix_sid: Option<V::PrefixSid>,
    pub flags: SummaryNetFlags,
}

bitflags! {
    #[derive(Default)]
    pub struct SummaryNetFlags: u8 {
        const CONNECTED = 0x01;
    }
}

// Locally originated inter-area "router" route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SummaryRtr<V: Version> {
    pub options: V::PacketOptions,
    pub metric: u32,
}

// OSPF path types in decreasing order of preference.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathType {
    IntraArea,
    InterArea,
    Type1External,
    Type2External,
}

// Route nexthop key.
#[derive(Clone, Copy, Debug, Eq, new, Ord, PartialEq, PartialOrd)]
pub struct NexthopKey<I: IpAddrKind> {
    // Nexthop interface.
    pub iface_idx: InterfaceIndex,
    // Nexthop address (`None` for connected routes).
    pub addr: Option<I>,
}

// Route nexthop.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
pub struct Nexthop<I: IpAddrKind> {
    // Nexthop interface.
    pub iface_idx: InterfaceIndex,
    // Nexthop address (`None` for connected routes).
    pub addr: Option<I>,
    // Router-ID of the remote neighbor (`None` for connected routes).
    pub nbr_router_id: Option<Ipv4Addr>,
    // SR Prefix-SID output label.
    #[new(default)]
    pub sr_label: Option<Label>,
}

// Ordered list of nexthops.
pub type Nexthops<I: IpAddrKind> = BTreeMap<NexthopKey<I>, Nexthop<I>>;

// ===== impl RouteNet =====

impl<V> RouteNet<V>
where
    V: Version,
{
    pub(crate) fn distance(&self, config: &InstanceCfg) -> u8 {
        match self.path_type {
            PathType::IntraArea => config.preference.intra_area,
            PathType::InterArea => config.preference.inter_area,
            PathType::Type1External | PathType::Type2External => {
                config.preference.external
            }
        }
    }

    pub(crate) fn metric(&self) -> u32 {
        match self.path_type {
            PathType::IntraArea | PathType::InterArea => self.metric,
            PathType::Type1External => self.metric,
            PathType::Type2External => self.type2_metric.unwrap(),
        }
    }
}

// ===== global functions =====

// Updates the entire OSPF routing table.
pub(crate) fn update_rib_full<V>(
    instance: &mut InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    interfaces: &Arena<Interface<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    let mut rib = BTreeMap::new();
    let old_rib = std::mem::take(&mut instance.state.rib);

    // Compute intra-area routes.
    for area in areas.iter_mut() {
        update_rib_intra_area(&mut rib, None, area, instance, lsa_entries);
    }

    // Compute inter-area routes.
    let active_areas = areas.active_count(interfaces);
    for area in areas.iter_mut() {
        // If the router has active attachments to multiple areas, only backbone
        // summary-LSAs are examined.
        if active_areas > 1 && !area.is_backbone() {
            continue;
        }

        update_rib_inter_area_networks(
            &mut rib,
            None,
            area,
            instance,
            lsa_entries,
        );
        update_rib_inter_area_routers(None, area, instance, lsa_entries);
    }

    // Compute external routes.
    update_rib_external(&mut rib, None, instance, areas, lsa_entries);

    // Update OSPF routes in the global RIB.
    update_global_rib(&mut rib, old_rib, instance, interfaces);

    // Save updated RIB.
    instance.state.rib = rib;
}

// Updates the affected routes after a partial SPF run.
pub(crate) fn update_rib_partial<V>(
    partial: &mut SpfPartialComputation<V>,
    instance: &mut InstanceUpView<'_, V>,
    areas: &mut Areas<V>,
    interfaces: &Arena<Interface<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    let mut partial_rib = BTreeMap::new();
    let mut rib = std::mem::take(&mut instance.state.rib);
    let mut old_rib = BTreeMap::new();

    // Check for intra-area changes.
    if !partial.intra.is_empty() {
        // Remove affected intra-area routes from the RIB.
        old_rib.extend(rib.extract_if(|prefix, route| {
            partial.intra.contains(prefix)
                && route.path_type == PathType::IntraArea
        }));

        // Recompute the affected intra-area routes.
        //
        // All areas need to be reevaluated to assure correct ECMP handling.
        for area in areas.iter_mut() {
            update_rib_intra_area(
                &mut partial_rib,
                Some(&partial.intra),
                area,
                instance,
                lsa_entries,
            );
        }

        // For destinations that are now newly unreachable, look for alternate
        // inter-area or external paths.
        partial.inter_network.extend(old_rib.keys());
    }

    // Check for inter-area changes.
    if !partial.inter_network.is_empty() {
        // Remove affected inter-area routes from the RIB.
        old_rib.extend(rib.extract_if(|prefix, route| {
            partial.inter_network.contains(prefix)
                && route.path_type == PathType::InterArea
        }));

        // Recompute the affected inter-area routes.
        let active_areas = areas.active_count(interfaces);
        for area in areas.iter_mut() {
            // If the router has active attachments to multiple areas, only
            // backbone summary-LSAs are examined.
            if active_areas > 1 && !area.is_backbone() {
                continue;
            }

            update_rib_inter_area_networks(
                &mut partial_rib,
                Some(&partial.inter_network),
                area,
                instance,
                lsa_entries,
            );
        }

        // For destinations that are now newly unreachable, look for alternate
        // external paths.
        partial.external.extend(old_rib.keys());
    }
    if !partial.inter_router.is_empty() {
        // Recompute the affected inter-area routes.
        let active_areas = areas.active_count(interfaces);
        for area in areas.iter_mut() {
            // If the router has active attachments to multiple areas, only
            // backbone summary-LSAs are examined.
            if active_areas > 1 && !area.is_backbone() {
                continue;
            }

            // Remove affected inter-area routes from the routers RIB.
            let _ = area.state.routers.extract_if(|router_id, route| {
                partial.inter_router.contains(router_id)
                    && route.path_type == PathType::InterArea
            });

            update_rib_inter_area_routers(
                Some(&partial.inter_router),
                area,
                instance,
                lsa_entries,
            );
        }
    }

    // Check for external changes.
    if !partial.inter_router.is_empty() || !partial.external.is_empty() {
        // Changes in any Type-4 LSAs require all AS-external LSAs to be
        // reevaluated.
        let reevaluate_all = !partial.inter_router.is_empty();

        // Remove affected external routes from the RIB.
        old_rib.extend(rib.extract_if(|prefix, route| {
            (reevaluate_all || partial.external.contains(prefix))
                && matches!(
                    route.path_type,
                    PathType::Type1External | PathType::Type2External
                )
        }));

        // Recompute the affected external routes.
        let filter = if reevaluate_all {
            None
        } else {
            Some(&partial.external)
        };
        update_rib_external(
            &mut partial_rib,
            filter,
            instance,
            areas,
            lsa_entries,
        );
    }

    // Update OSPF routes in the global RIB.
    update_global_rib(&mut partial_rib, old_rib, instance, interfaces);

    // Save updated RIB.
    rib.extend(partial_rib);
    instance.state.rib = rib;
}

// ===== helper functions =====

// Computes intra-area routes.
fn update_rib_intra_area<V>(
    rib: &mut BTreeMap<V::IpNetwork, RouteNet<V>>,
    filter: Option<&BTreeSet<V::IpNetwork>>,
    area: &mut Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Iterate over all stub networks and their corresponding vertices.
    let extended_lsa = instance.config.extended_lsa;
    for stub in V::intra_area_networks(area, extended_lsa, lsa_entries)
        // Filter prefixes when running partial SPF.
        .filter(|stub| {
            if let Some(filter) = filter {
                filter.contains(&stub.prefix)
            } else {
                true
            }
        })
    {
        // Calculate stub metric.
        let metric = stub.vertex.distance.saturating_add(stub.metric) as u32;

        // Compare this distance to the current best cost to the stub network.
        // This is done by looking up the stub network's current routing table
        // entry. If the calculated distance D is larger, go on to examine the
        // next stub network link in the LSA.
        if let Some(best_route) = rib.get(&stub.prefix) {
            if metric > best_route.metric {
                continue;
            }
        }

        // Get LS Origin.
        let origin = stub.vertex.lsa.origin();

        // If the newly added vertex is a transit network, the routing table
        // entry for the network is located. (...) If the routing table entry
        // already exists, multiple vertices have mapped to the same IP network.
        // For example, this can occur when a new Designated Router is being
        // established. In this case, the current routing table entry should be
        // overwritten if and only if the newly found path is just as short and
        // the current routing table entry's Link State Origin has a smaller
        // Link State ID than the newly added vertex' LSA.
        if !stub.vertex.lsa.is_router() {
            if let btree_map::Entry::Occupied(o) = rib.entry(stub.prefix) {
                let curr_route = o.get();
                if metric > curr_route.metric
                    || origin.lsa_id < curr_route.origin.unwrap().lsa_id
                {
                    continue;
                }
                o.remove();
            }
        }

        // Create new intra-area route.
        let mut flags = RouteNetFlags::empty();
        if stub.vertex.hops == 0 {
            flags.insert(RouteNetFlags::CONNECTED);
        }
        let mut new_route = RouteNet {
            prefix_options: stub.prefix_options,
            area_id: Some(area.area_id),
            path_type: PathType::IntraArea,
            origin: Some(origin),
            metric,
            type2_metric: None,
            tag: None,
            prefix_sid: None,
            sr_label: None,
            nexthops: stub.vertex.nexthops.clone(),
            flags,
        };

        // Update route's Prefix-SID (if any).
        if instance.config.sr_enabled {
            if let Some(prefix_sid) = stub.prefix_sids.get(&IgpAlgoType::Spf) {
                let local = stub.vertex.hops == 0;
                let last_hop = stub.vertex.hops == 1;
                sr::prefix_sid_update(
                    area,
                    instance,
                    origin.adv_rtr,
                    &mut new_route,
                    prefix_sid,
                    local,
                    last_hop,
                    lsa_entries,
                );
            }
        }

        // Try to add or update stub route in the RIB.
        route_update(rib, stub.prefix, new_route, instance.config.max_paths);
    }
}

// Computes inter-area "network" routes.
fn update_rib_inter_area_networks<V>(
    rib: &mut BTreeMap<V::IpNetwork, RouteNet<V>>,
    filter: Option<&BTreeSet<V::IpNetwork>>,
    area: &mut Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Examine all Type-3 Summary/Inter-Area-Network LSAs.
    let extended_lsa = instance.config.extended_lsa;
    let router_id = instance.state.router_id;
    for lsa in V::inter_area_networks(area, extended_lsa, lsa_entries)
        // Filter out unreachable LSAs.
        .filter(|lsa| lsa.metric < LSA_INFINITY)
        // Filter out LSAs originated by the calculating router itself.
        .filter(|lsa| lsa.adv_rtr != router_id)
        // Filter prefixes when running partial SPF.
        .filter(|lsa| {
            if let Some(filter) = filter {
                filter.contains(&lsa.prefix)
            } else {
                true
            }
        })
    {
        // Look up the routing table entry for BR having Area A as its
        // associated area.
        let route_br = match area
            .state
            .routers
            .get(&lsa.adv_rtr)
            .filter(|route| route.flags.is_abr())
        {
            Some(route_br) => route_br,
            None => {
                // If no such entry exists for router BR, do nothing with this
                // LSA and consider the next in the list.
                Debug::<V>::SpfNetworkUnreachableAbr(&lsa.prefix, lsa.adv_rtr)
                    .log();
                continue;
            }
        };

        // The inter-area path cost is the distance to BR plus the cost
        // specified in the LSA.
        let metric = route_br.metric + lsa.metric;

        // Create new inter-area route.
        let mut new_route = RouteNet {
            prefix_options: lsa.prefix_options,
            area_id: Some(area.area_id),
            path_type: PathType::InterArea,
            origin: None,
            metric,
            type2_metric: None,
            tag: None,
            prefix_sid: None,
            sr_label: None,
            nexthops: route_br.nexthops.clone(),
            flags: RouteNetFlags::empty(),
        };

        // Update route's Prefix-SID (if any).
        if instance.config.sr_enabled {
            if let Some(prefix_sid) = lsa.prefix_sids.get(&IgpAlgoType::Spf) {
                sr::prefix_sid_update(
                    area,
                    instance,
                    lsa.adv_rtr,
                    &mut new_route,
                    prefix_sid,
                    false,
                    false,
                    lsa_entries,
                );
            }
        }

        // Try to add or update summary route in the RIB.
        route_update(rib, lsa.prefix, new_route, instance.config.max_paths);
    }
}

// Computes inter-area "router" routes.
fn update_rib_inter_area_routers<V>(
    filter: Option<&BTreeSet<Ipv4Addr>>,
    area: &mut Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Examine all Type-4 Summary/Inter-Area-Router LSAs.
    let extended_lsa = instance.config.extended_lsa;
    let router_id = instance.state.router_id;
    for lsa in
        V::inter_area_routers(&area.state.lsdb, extended_lsa, lsa_entries)
            // Filter out unreachable LSAs.
            .filter(|lsa| lsa.metric < LSA_INFINITY)
            // Filter out LSAs originated by the calculating router itself.
            .filter(|lsa| lsa.adv_rtr != router_id)
            // Filter routers when running partial SPF.
            .filter(|lsa| {
                if let Some(filter) = filter {
                    filter.contains(&lsa.router_id)
                } else {
                    true
                }
            })
    {
        // Look up the routing table entry for BR having Area A as its
        // associated area.
        let route_br = match area
            .state
            .routers
            .get(&lsa.adv_rtr)
            .filter(|route| route.flags.is_abr())
        {
            Some(route_br) => route_br,
            None => {
                // If no such entry exists for router BR, do nothing with this
                // LSA and consider the next in the list.
                Debug::<V>::SpfRouterUnreachableAbr(
                    &lsa.router_id,
                    lsa.adv_rtr,
                )
                .log();
                continue;
            }
        };

        // The inter-area path cost is the distance to BR plus the cost
        // specified in the LSA.
        let metric = route_br.metric + lsa.metric;

        // Create new inter-area route.
        let new_route = RouteRtr::<V> {
            area_id: area.area_id,
            path_type: PathType::InterArea,
            options: lsa.options,
            flags: lsa.flags,
            metric,
            nexthops: route_br.nexthops.clone(),
        };
        area.state.routers.insert(lsa.router_id, new_route);
    }
}

// Computes AS external routes.
fn update_rib_external<V>(
    rib: &mut BTreeMap<V::IpNetwork, RouteNet<V>>,
    filter: Option<&BTreeSet<V::IpNetwork>>,
    instance: &mut InstanceUpView<'_, V>,
    areas: &Areas<V>,
    lsa_entries: &Arena<LsaEntry<V>>,
) where
    V: Version,
{
    // Examine all AS-external-LSAs.
    let extended_lsa = instance.config.extended_lsa;
    let router_id = instance.state.router_id;
    for lsa in
        V::external_networks(&instance.state.lsdb, extended_lsa, lsa_entries)
            // Filter out unreachable LSAs.
            .filter(|lsa| lsa.metric < LSA_INFINITY)
            // Filter out LSAs originated by the calculating router itself.
            .filter(|lsa| lsa.adv_rtr != router_id)
            // Filter prefixes when running partial SPF.
            .filter(|lsa| {
                if let Some(filter) = filter {
                    filter.contains(&lsa.prefix)
                } else {
                    true
                }
            })
    {
        // Look up the routing table entries (potentially one per attached area)
        // for the AS boundary router (ASBR) that originated the LSA.
        let mut asbr_routes = areas
            .iter()
            .filter_map(|area| {
                area.state
                    .routers
                    .get(&lsa.adv_rtr)
                    .filter(|route| route.flags.is_asbr())
            })
            .collect::<Vec<_>>();

        // Intra-area paths using non-backbone areas are always the most
        // preferred.
        let asbr_routes_pruned = asbr_routes
            .iter()
            .cloned()
            .filter(|route| {
                route.path_type == PathType::IntraArea
                    && route.area_id != Ipv4Addr::UNSPECIFIED
            })
            .collect::<Vec<_>>();
        if !asbr_routes_pruned.is_empty() {
            asbr_routes = asbr_routes_pruned;
        }

        // Select the routing table entry with the least cost; when there are
        // multiple least cost routing table entries the entry whose associated
        // area has the largest OSPF Area ID is chosen.
        let route_asbr = match asbr_routes.iter().reduce(|best, route| {
            match route.metric.cmp(&best.metric) {
                Ordering::Less => route,
                Ordering::Equal => {
                    if route.area_id > best.area_id {
                        route
                    } else {
                        best
                    }
                }
                Ordering::Greater => best,
            }
        }) {
            Some(route_asbr) => route_asbr,
            None => {
                // If no entries exist for router ASBR, do nothing with this
                // LSA and consider the next in the list.
                Debug::<V>::SpfUnreachableAsbr(&lsa.prefix, lsa.adv_rtr).log();
                continue;
            }
        };

        // TODO: examine the forwarding address.

        // Get path type and metric.
        let (path_type, metric, type2_metric) = match lsa.e_bit {
            true => {
                (PathType::Type2External, route_asbr.metric, Some(lsa.metric))
            }
            false => (
                PathType::Type1External,
                route_asbr.metric + lsa.metric,
                None,
            ),
        };

        // Create new external route.
        let new_route = RouteNet {
            prefix_options: lsa.prefix_options,
            area_id: None,
            path_type,
            origin: None,
            metric,
            type2_metric,
            tag: lsa.tag,
            prefix_sid: None,
            sr_label: None,
            nexthops: route_asbr.nexthops.clone(),
            flags: RouteNetFlags::empty(),
        };

        // Try to add or update external route in the RIB.
        route_update(rib, lsa.prefix, new_route, instance.config.max_paths);
    }
}

// Updates OSPF routes in the global RIB.
//
// This step should be done at the end of the routing table calculation to
// prevent transient states from affecting the forwarding plane.
fn update_global_rib<V>(
    rib: &mut BTreeMap<V::IpNetwork, RouteNet<V>>,
    mut old_rib: BTreeMap<V::IpNetwork, RouteNet<V>>,
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &Arena<Interface<V>>,
) where
    V: Version,
{
    // Install new routes or routes that have changed.
    //
    // TODO: prioritize loopback routes to speedup BGP convergence.
    for (prefix, route) in rib {
        let mut old_sr_label = None;

        // Remove route from the old RIB if it's present.
        if let Some(old_route) = old_rib.remove(prefix) {
            old_sr_label = old_route.sr_label;

            // Skip reinstalling the route if it hasn't changed.
            if old_route.metric() == route.metric()
                && old_route.tag == route.tag
                && old_route.sr_label == route.sr_label
                && old_route.nexthops == route.nexthops
            {
                if old_route.flags.contains(RouteNetFlags::INSTALLED) {
                    route.flags.insert(RouteNetFlags::INSTALLED);
                }
                continue;
            }
        }

        // The list of nexthops might be empty in the case of nexthop
        // computation errors (e.g. missing Link-LSAs). When that happens,
        // ensure the route is removed from the RIB.
        if !route.flags.contains(RouteNetFlags::CONNECTED)
            && !route.nexthops.is_empty()
        {
            let distance = route.distance(instance.config);
            instance.tx.sb.route_install(
                prefix,
                route,
                old_sr_label,
                distance,
                interfaces,
            );
            route.flags.insert(RouteNetFlags::INSTALLED);
        } else if route.flags.contains(RouteNetFlags::INSTALLED) {
            instance.tx.sb.route_uninstall(prefix, route);
            route.flags.remove(RouteNetFlags::INSTALLED);
        }
    }

    // Uninstall routes that are no longer available.
    for (dest, route) in old_rib
        .into_iter()
        .filter(|(_, route)| route.flags.contains(RouteNetFlags::INSTALLED))
    {
        instance.tx.sb.route_uninstall(&dest, &route);
    }
}

fn route_update<V>(
    rib: &mut BTreeMap<V::IpNetwork, RouteNet<V>>,
    prefix: V::IpNetwork,
    route: RouteNet<V>,
    max_paths: u16,
) where
    V: Version,
{
    let route = match rib.entry(prefix) {
        btree_map::Entry::Occupied(o) => {
            let curr_route = o.into_mut();

            match route_compare(&route, curr_route) {
                Ordering::Less => {
                    // Overwrite the current routing table entry, but preserve
                    // the flag indicating whether the route is installed or
                    // not.
                    let installed =
                        curr_route.flags.contains(RouteNetFlags::INSTALLED);
                    *curr_route = route;
                    if installed {
                        curr_route.flags.insert(RouteNetFlags::INSTALLED);
                    }
                }
                Ordering::Equal => {
                    // Merge nexthops.
                    curr_route.nexthops.extend(route.nexthops.into_iter());
                }
                Ordering::Greater => {
                    // Ignore less preferred route.
                }
            }

            curr_route
        }
        btree_map::Entry::Vacant(v) => v.insert(route),
    };

    // Honor configured maximum number of ECMP paths.
    if route.nexthops.len() > max_paths as usize {
        route.nexthops = route
            .nexthops
            .iter()
            .map(|(k, v)| (*k, *v))
            .take(max_paths as usize)
            .collect();
    }
}

fn route_compare<V>(a: &RouteNet<V>, b: &RouteNet<V>) -> Ordering
where
    V: Version,
{
    let cmp = a.path_type.cmp(&b.path_type);
    if cmp != Ordering::Equal {
        return cmp;
    }

    match a.path_type {
        PathType::IntraArea | PathType::InterArea => a.metric.cmp(&b.metric),
        PathType::Type1External => {
            // TODO: prefer intra-area paths using non-backbone areas (16.4.1).

            a.metric.cmp(&b.metric)
        }
        PathType::Type2External => {
            let cmp = a.type2_metric.cmp(&b.type2_metric);
            if cmp != Ordering::Equal {
                return cmp;
            }

            // TODO: prefer intra-area paths using non-backbone areas (16.4.1).

            a.metric.cmp(&b.metric)
        }
    }
}
