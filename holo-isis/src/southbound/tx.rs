//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::collections::Interfaces;
use crate::route::Route;

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(IbusMsg::RouterIdQuery);
}

pub(crate) fn route_install(
    ibus_tx: &IbusSender,
    destination: &IpNetwork,
    route: &Route,
    distance: u8,
    interfaces: &Interfaces,
) {
    // Fill-in nexthops.
    let nexthops = route
        .nexthops
        .values()
        .map(|nexthop| {
            let iface = &interfaces[nexthop.iface_idx];
            Nexthop::Address {
                ifindex: iface.system.ifindex.unwrap(),
                addr: nexthop.addr,
                labels: vec![],
            }
        })
        .collect::<BTreeSet<_>>();

    // Install route.
    let msg = RouteMsg {
        protocol: Protocol::ISIS,
        prefix: *destination,
        distance: distance.into(),
        metric: route.metric,
        tag: route.tag,
        opaque_attrs: RouteOpaqueAttrs::Isis {
            route_type: route.route_type,
        },
        nexthops: nexthops.clone(),
    };
    let msg = IbusMsg::RouteIpAdd(msg);
    let _ = ibus_tx.send(msg);
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusSender,
    destination: &IpNetwork,
    _route: &Route,
) {
    // Uninstall route.
    let msg = RouteKeyMsg {
        protocol: Protocol::ISIS,
        prefix: *destination,
    };
    let msg = IbusMsg::RouteIpDel(msg);
    let _ = ibus_tx.send(msg);
}
