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
use holo_utils::southbound::IsisRouteType;
use ipnetwork::IpNetwork;

use crate::collections::{InterfaceIndex, Interfaces};
use crate::instance::InstanceUpView;
use crate::northbound::configuration::InstanceCfg;
use crate::packet::LevelNumber;
use crate::southbound;
use crate::spf::{Vertex, VertexNetwork};

// Routing table entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub route_type: IsisRouteType,
    pub metric: u32,
    pub level: LevelNumber,
    pub tag: Option<u32>,
    pub nexthops: BTreeMap<IpAddr, Nexthop>,
    pub flags: RouteFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RouteFlags: u8 {
        const CONNECTED = 0x01;
        const INSTALLED = 0x02;
    }
}

// Route nexthop.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
pub struct Nexthop {
    // Nexthop interface.
    pub iface_idx: InterfaceIndex,
    // Nexthop address (`None` for connected routes).
    pub addr: IpAddr,
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
                let iface_idx = nexthop.iface_idx;
                let addr = match vertex_network.prefix.address_family() {
                    AddressFamily::Ipv4 => nexthop.ipv4.map(IpAddr::V4),
                    AddressFamily::Ipv6 => nexthop.ipv6.map(IpAddr::V6),
                }?;
                Some((addr, Nexthop { iface_idx, addr }))
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

// ===== global functions =====

// Updates IS-IS routes in the global RIB.
pub(crate) fn update_global_rib(
    rib: &mut BTreeMap<IpNetwork, Route>,
    mut old_rib: BTreeMap<IpNetwork, Route>,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
) {
    // Install new routes or routes that have changed.
    //
    // TODO: prioritize loopback routes to speedup BGP convergence.
    for (prefix, route) in rib {
        // Remove route from the old RIB if it's present.
        if let Some(old_route) = old_rib.remove(prefix) {
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
            && !route.nexthops.is_empty()
        {
            let distance = route.distance(instance.config);
            southbound::tx::route_install(
                &instance.tx.ibus,
                prefix,
                route,
                distance,
                interfaces,
            );
            route.flags.insert(RouteFlags::INSTALLED);
        } else if route.flags.contains(RouteFlags::INSTALLED) {
            southbound::tx::route_uninstall(&instance.tx.ibus, prefix, route);
            route.flags.remove(RouteFlags::INSTALLED);
        }
    }

    // Uninstall routes that are no longer available.
    for (dest, route) in old_rib
        .into_iter()
        .filter(|(_, route)| route.flags.contains(RouteFlags::INSTALLED))
    {
        southbound::tx::route_uninstall(&instance.tx.ibus, &dest, &route);
    }
}
