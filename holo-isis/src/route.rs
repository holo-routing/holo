//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::IpAddr;

use bitflags::bitflags;
use derive_new::new;
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{IsisRouteType, RouteOpaqueAttrs};
use ipnetwork::IpNetwork;

use crate::collections::{InterfaceIndex, Interfaces};
use crate::ibus;
use crate::instance::InstanceUpView;
use crate::northbound::configuration::{InstanceCfg, SummaryCfg};
use crate::packet::subtlvs::prefix::PrefixSidStlv;
use crate::packet::{LevelNumber, LevelType, SystemId};
use crate::spf::{Vertex, VertexNetwork};

// Routing table entry.
#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub route_type: IsisRouteType,
    pub metric: u32,
    pub level: LevelNumber,
    pub tag: Option<u32>,
    pub prefix_sid: Option<PrefixSidStlv>,
    pub sr_label: Option<Label>,
    pub nexthops: BTreeMap<IpAddr, Nexthop>,
    pub flags: RouteFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RouteFlags: u8 {
        const CONNECTED = 0x01;
        const INSTALLED = 0x02;
        const SUMMARY = 0x04;
    }
}

// Route nexthop.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
pub struct Nexthop {
    // System ID of the nexthop router.
    pub system_id: SystemId,
    // Nexthop interface.
    pub iface_idx: InterfaceIndex,
    // Nexthop address (`None` for connected routes).
    pub addr: IpAddr,
    // SR Prefix-SID output label.
    pub sr_label: Option<Label>,
}

// Route redistributed from the global RIB.
#[derive(Clone, Debug)]
pub struct RouteSys {
    pub protocol: Protocol,
    pub metric: u32,
    pub tag: Option<u32>,
    pub opaque_attrs: RouteOpaqueAttrs,
}

// Summary route.
#[derive(Clone, Debug)]
pub struct SummaryRoute {
    pub config: SummaryCfg,
    pub metric: u32,
}

// ===== impl Route =====

impl Route {
    pub(crate) fn new(
        vertex: &Vertex,
        vertex_network: &VertexNetwork,
        level: LevelNumber,
    ) -> Route {
        let mut flags = RouteFlags::empty();
        if vertex.hops == 0 {
            flags.insert(RouteFlags::CONNECTED);
        }
        let route_type = match (level, vertex_network.external) {
            (LevelNumber::L1, false) => IsisRouteType::L1IntraArea,
            (LevelNumber::L1, true) => IsisRouteType::L1External,
            (LevelNumber::L2, false) => IsisRouteType::L2IntraArea,
            (LevelNumber::L2, true) => IsisRouteType::L2External,
        };
        Route {
            route_type,
            metric: vertex.distance + vertex_network.metric,
            level,
            tag: None,
            prefix_sid: vertex_network.prefix_sid,
            sr_label: None,
            nexthops: Self::build_nexthops(vertex, vertex_network),
            flags,
        }
    }

    pub(crate) fn merge_nexthops(
        &mut self,
        vertex: &Vertex,
        vertex_network: &VertexNetwork,
    ) {
        let nexthops = Self::build_nexthops(vertex, vertex_network);
        self.nexthops.extend(nexthops);
    }

    fn build_nexthops(
        vertex: &Vertex,
        vertex_network: &VertexNetwork,
    ) -> BTreeMap<IpAddr, Nexthop> {
        vertex
            .nexthops
            .iter()
            .filter_map(|nexthop| {
                let addr = match vertex_network.prefix.address_family() {
                    AddressFamily::Ipv4 => nexthop.ipv4.map(IpAddr::V4),
                    AddressFamily::Ipv6 => nexthop.ipv6.map(IpAddr::V6),
                }?;
                Some((
                    addr,
                    Nexthop {
                        system_id: nexthop.system_id,
                        iface_idx: nexthop.iface_idx.unwrap(),
                        addr,
                        sr_label: None,
                    },
                ))
            })
            .collect()
    }

    pub(crate) const fn distance(&self, config: &InstanceCfg) -> u8 {
        match self.route_type {
            IsisRouteType::L2IntraArea
            | IsisRouteType::L1IntraArea
            | IsisRouteType::L1InterArea => config.preference.internal,
            IsisRouteType::L2External
            | IsisRouteType::L1External
            | IsisRouteType::L1InterAreaExternal => config.preference.external,
        }
    }
}

impl From<&SummaryRoute> for Route {
    fn from(summary: &SummaryRoute) -> Route {
        Route {
            route_type: IsisRouteType::L2IntraArea,
            metric: summary.metric(),
            level: LevelNumber::L2,
            tag: None,
            prefix_sid: None,
            sr_label: None,
            nexthops: [].into(),
            flags: RouteFlags::SUMMARY,
        }
    }
}

// ===== impl SummaryRoute =====

impl SummaryRoute {
    // Returns the configured summary metric if set. Otherwise, returns the
    // lowest metric from contributing more-specific routes.
    pub(crate) fn metric(&self) -> u32 {
        self.config.metric.unwrap_or(self.metric)
    }
}

// ===== global functions =====

// Updates the local RIB for the specified level and the combined L1/L2 RIB for
// L1/L2 routers.
pub(crate) fn update_rib(
    level: LevelNumber,
    mut new_rib: BTreeMap<IpNetwork, Route>,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
) {
    // Save the old local RIB.
    let old_rib =
        std::mem::take(instance.state.rib_mut(instance.config.level_type));

    if instance.config.level_type == LevelType::All {
        match level {
            LevelNumber::L1 => {
                // Whenever the L1 RIB is updated, we need to recompute the L2
                // summary routes.
                instance.state.summaries.clear();
                for (prefix, route) in &new_rib {
                    if let Some((summary_prefix, summary_cfg)) =
                        instance.config.summaries.get_spm(prefix)
                    {
                        instance
                            .state
                            .summaries
                            .entry(summary_prefix)
                            .and_modify(|summary: &mut SummaryRoute| {
                                // Keep track of the lowest metric among the
                                // contributing more-specific routes.
                                summary.metric =
                                    std::cmp::min(summary.metric, route.metric);
                            })
                            .or_insert_with(|| SummaryRoute {
                                config: summary_cfg.clone(),
                                metric: route.metric,
                            });
                    }
                }
            }
            LevelNumber::L2 => {
                // Add active summary routes to the L2 RIB. These will be
                // installed in the global RIB as blackhole routes to prevent
                // routing loops.
                new_rib.extend(
                    instance.state.summaries.iter().map(|(prefix, summary)| {
                        (*prefix, Route::from(summary))
                    }),
                );
            }
        }

        // Store the new local RIB for the current level.
        *instance.state.rib_single.get_mut(level) = new_rib;

        // Merge L1 and L2 local RIBs, preferring L1 routes.
        let rib_l1 = instance.state.rib_single.get(LevelNumber::L1);
        let rib_l2 = instance.state.rib_single.get(LevelNumber::L2);
        new_rib = rib_l2
            .iter()
            .chain(rib_l1.iter())
            .map(|(prefix, route)| (*prefix, route.clone()))
            .collect();
    }

    // Update the global RIB.
    update_global_rib(&mut new_rib, old_rib, instance, interfaces);

    // Store the new local RIB.
    *instance.state.rib_mut(instance.config.level_type) = new_rib;
}

// ===== helper functions =====

// Updates IS-IS routes in the global RIB.
fn update_global_rib(
    rib: &mut BTreeMap<IpNetwork, Route>,
    mut old_rib: BTreeMap<IpNetwork, Route>,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
) {
    // Install new routes or routes that have changed.
    //
    // TODO: prioritize loopback routes to speedup BGP convergence.
    for (prefix, route) in rib {
        let mut old_sr_label = None;

        // Remove route from the old RIB if it's present.
        if let Some(old_route) = old_rib.remove(prefix) {
            old_sr_label = old_route.sr_label;

            // Skip reinstalling the route if it hasn't changed.
            if old_route.metric == route.metric
                && old_route.tag == route.tag
                && old_route.nexthops == route.nexthops
            {
                if old_route.flags.contains(RouteFlags::INSTALLED) {
                    route.flags.insert(RouteFlags::INSTALLED);
                }
                continue;
            }
        }

        // The list of nexthops might be empty in the case of nexthop
        // computation errors (e.g. adjacencies with missing IP address TLVs).
        // When that happens, ensure the route is removed from the global RIB.
        if !route.flags.contains(RouteFlags::CONNECTED)
            && (route.flags.contains(RouteFlags::SUMMARY)
                || !route.nexthops.is_empty())
        {
            let distance = route.distance(instance.config);
            ibus::tx::route_install(
                &instance.tx.ibus,
                prefix,
                route,
                old_sr_label,
                distance,
                interfaces,
            );
            route.flags.insert(RouteFlags::INSTALLED);
        } else if route.flags.contains(RouteFlags::INSTALLED) {
            ibus::tx::route_uninstall(&instance.tx.ibus, prefix, route);
            route.flags.remove(RouteFlags::INSTALLED);
        }
    }

    // Uninstall routes that are no longer available.
    for (dest, route) in old_rib
        .into_iter()
        .filter(|(_, route)| route.flags.contains(RouteFlags::INSTALLED))
    {
        ibus::tx::route_uninstall(&instance.tx.ibus, &dest, &route);
    }
}
