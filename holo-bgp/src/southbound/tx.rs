//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::rib::Route;

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(IbusMsg::RouterIdQuery);
}

pub(crate) fn route_install(
    ibus_tx: &IbusSender,
    prefix: impl Into<IpNetwork>,
    route: &Route,
    nexthops: &BTreeSet<IpAddr>,
    distance: u8,
) {
    // Fill-in nexthops.
    let nexthops = nexthops
        .iter()
        .map(|nexthop| Nexthop::Address {
            // TODO
            ifindex: 0,
            addr: *nexthop,
            labels: vec![],
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
    let msg = IbusMsg::RouteIpAdd(msg);
    let _ = ibus_tx.send(msg);
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusSender,
    prefix: impl Into<IpNetwork>,
) {
    // Uninstall route.
    let msg = RouteKeyMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
    };
    let msg = IbusMsg::RouteIpDel(msg);
    let _ = ibus_tx.send(msg);
}
