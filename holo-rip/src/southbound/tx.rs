//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use derive_new::new;
use holo_southbound::tx::SouthboundTx;
use holo_southbound::zclient::ffi::NexthopType;
use holo_southbound::zclient::messages::{
    ZapiTxHelloInfo, ZapiTxMsg, ZapiTxNexthopInfo, ZapiTxRouteInfo,
};

use crate::route::{Route, RouteType};
use crate::version::Version;

#[derive(Debug, new)]
pub struct InstanceSouthboundTx(pub SouthboundTx);

// ===== impl InstanceSouthboundTx =====

impl InstanceSouthboundTx {
    // Install RIP route in the RIB.
    pub(crate) fn route_install<V>(&self, route: &Route<V>, distance: u8)
    where
        V: Version,
    {
        if route.route_type != RouteType::Rip {
            return;
        }

        // Fill-in message.
        let msg_info = ZapiTxRouteInfo {
            proto: V::PROTOCOL.into(),
            instance: 0,
            prefix: route.prefix.into(),
            nexthops: vec![ZapiTxNexthopInfo {
                nhtype: NexthopType::from((V::ADDRESS_FAMILY, true)),
                addr: Some(route.nexthop.unwrap().into()),
                ifindex: route.ifindex,
                label: None,
            }],
            distance: Some(distance),
            metric: Some(route.metric.get() as u32),
            tag: Some(route.tag.into()),
        };

        // Send message.
        let msg = ZapiTxMsg::RouteReplace(msg_info);
        self.0.send(msg);
    }

    // Uninstall RIP route from the RIB.
    pub(crate) fn route_uninstall<V>(&self, route: &Route<V>)
    where
        V: Version,
    {
        if route.route_type != RouteType::Rip {
            return;
        }

        // Fill-in message.
        let msg_info = ZapiTxRouteInfo {
            proto: V::PROTOCOL.into(),
            instance: 0,
            prefix: route.prefix.into(),
            nexthops: vec![],
            distance: None,
            metric: None,
            tag: None,
        };

        // Send message.
        let msg = ZapiTxMsg::RouteDel(msg_info);
        self.0.send(msg);
    }

    pub(crate) fn request_interface_info(&self) {
        self.0.send(ZapiTxMsg::InterfaceAdd);
    }

    pub(crate) fn initial_requests(&self) {
        // Hello message.
        let msg = ZapiTxMsg::Hello(ZapiTxHelloInfo {
            redist_default: self.0.zclient.redist_default,
            instance: self.0.zclient.instance,
            session_id: 0,
            receive_notify: self.0.zclient.receive_notify as u8,
        });
        self.0.send(msg);
    }
}
