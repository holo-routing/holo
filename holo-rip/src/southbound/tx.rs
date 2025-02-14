//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::southbound::{
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};

use crate::route::{Route, RouteType};
use crate::version::Version;

// ===== impl InstanceSouthboundTx =====

// Install RIP route in the RIB.
pub(crate) fn route_install<V>(
    ibus_tx: &IbusChannelsTx,
    route: &Route<V>,
    distance: u8,
) where
    V: Version,
{
    if route.route_type != RouteType::Rip {
        return;
    }

    // Fill-in message.
    let msg = RouteMsg {
        protocol: V::PROTOCOL,
        prefix: route.prefix.into(),
        distance: distance.into(),
        metric: route.metric.get() as u32,
        tag: Some(route.tag.into()),
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops: [Nexthop::Address {
            ifindex: route.ifindex,
            addr: route.nexthop.unwrap().into(),
            labels: Vec::new(),
        }]
        .into(),
    };

    // Send message.
    ibus_tx.route_ip_add(msg);
}

// Uninstall RIP route from the RIB.
pub(crate) fn route_uninstall<V>(ibus_tx: &IbusChannelsTx, route: &Route<V>)
where
    V: Version,
{
    if route.route_type != RouteType::Rip {
        return;
    }

    // Fill-in message.
    let msg = RouteKeyMsg {
        protocol: V::PROTOCOL,
        prefix: route.prefix.into(),
    };

    // Send message.
    ibus_tx.route_ip_del(msg);
}
