//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::rib::LocalRoute;

// ===== global functions =====

pub(crate) fn router_id_sub(ibus_tx: &IbusChannelsTx) {
    ibus_tx.router_id_sub();
}

pub(crate) fn route_install(
    ibus_tx: &IbusChannelsTx,
    prefix: impl Into<IpNetwork>,
    route: &LocalRoute,
    distance: u8,
) {
    // Fill-in nexthops.
    let nexthops = route
        .nexthops
        .iter()
        .flat_map(|nexthops| nexthops.iter())
        .map(|nexthop| Nexthop::Recursive {
            addr: *nexthop,
            labels: vec![],
            resolved: Default::default(),
        })
        .collect::<BTreeSet<_>>();

    // Install route.
    let msg = RouteMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
        distance: distance.into(),
        metric: route.attrs.base.value.med.unwrap_or(0),
        tag: None,
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops: nexthops.clone(),
    };
    ibus_tx.route_ip_add(msg);
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusChannelsTx,
    prefix: impl Into<IpNetwork>,
) {
    // Uninstall route.
    let msg = RouteKeyMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
    };
    ibus_tx.route_ip_del(msg);
}

pub(crate) fn nexthop_track(ibus_tx: &IbusChannelsTx, addr: IpAddr) {
    ibus_tx.nexthop_track(addr);
}

pub(crate) fn nexthop_untrack(ibus_tx: &IbusChannelsTx, addr: IpAddr) {
    ibus_tx.nexthop_untrack(addr);
}
