//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::{IbusSender, NexthopMsg, RouteIpMsg, RouterIdMsg};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::rib::LocalRoute;

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(RouterIdMsg::Query.into());
}

pub(crate) fn route_install(
    ibus_tx: &IbusSender,
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
    let msg = RouteIpMsg::Add(RouteMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
        distance: distance.into(),
        metric: route.attrs.base.value.med.unwrap_or(0),
        tag: None,
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops: nexthops.clone(),
    });
    let _ = ibus_tx.send(msg.into());
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusSender,
    prefix: impl Into<IpNetwork>,
) {
    // Uninstall route.
    let msg = RouteIpMsg::Delete(RouteKeyMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
    });
    let _ = ibus_tx.send(msg.into());
}

pub(crate) fn nexthop_track(ibus_tx: &IbusSender, addr: IpAddr) {
    let msg = NexthopMsg::Track(addr);
    let _ = ibus_tx.send(msg.into());
}

pub(crate) fn nexthop_untrack(ibus_tx: &IbusSender, addr: IpAddr) {
    let msg = NexthopMsg::Untrack(addr);
    let _ = ibus_tx.send(msg.into());
}
