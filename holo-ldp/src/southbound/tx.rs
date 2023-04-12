//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use derive_new::new;
use holo_southbound::tx::SouthboundTx;
use holo_southbound::zclient;
use holo_southbound::zclient::messages::{
    ZapiTxHelloInfo, ZapiTxLabelsInfo, ZapiTxLabelsRouteInfo, ZapiTxMsg,
    ZapiTxNexthopInfo, ZapiTxRedistInfo, ZapiTxRtrIdInfo,
};
use holo_utils::ip::AddressFamily;

use crate::fec::{FecInner, Nexthop};

#[derive(Debug, new)]
pub struct InstanceSouthboundTx(pub SouthboundTx);

// ===== impl InstanceSouthboundTx =====

impl InstanceSouthboundTx {
    fn label_send(&self, fec: &FecInner, nexthop: &Nexthop, install: bool) {
        let local_label = match fec.local_label {
            Some(label) => label,
            None => return,
        };
        if local_label.is_reserved() {
            return;
        }
        let remote_label = match nexthop.get_label() {
            Some(label) => label,
            None => return,
        };
        let owner = fec.owner.as_ref().unwrap();

        // Fill-in message.
        let lsp_type = zclient::ffi::LspType::Ldp;
        let msg_info = ZapiTxLabelsInfo {
            lsp_type,
            // Label.
            local_label,
            // Route.
            route: Some(ZapiTxLabelsRouteInfo {
                prefix: *fec.prefix,
                proto: owner.proto,
                instance: owner.instance,
            }),
            // Nexthop.
            nexthops: vec![ZapiTxNexthopInfo {
                nhtype: zclient::ffi::NexthopType::Ipv4Ifindex,
                addr: Some(nexthop.addr),
                ifindex: nexthop.ifindex.unwrap_or(0),
                label: Some((lsp_type, remote_label)),
            }],
        };

        // Send message.
        let msg = if install {
            ZapiTxMsg::LabelsAdd(msg_info)
        } else {
            ZapiTxMsg::LabelsDel(msg_info)
        };
        self.0.send(msg);
    }

    pub(crate) fn label_install(&self, fec: &FecInner, nexthop: &Nexthop) {
        self.label_send(fec, nexthop, true);
    }

    pub(crate) fn label_uninstall(&self, fec: &FecInner, nexthop: &Nexthop) {
        self.label_send(fec, nexthop, false);
    }

    pub(crate) fn request_interface_info(&self) {
        self.0.send(ZapiTxMsg::InterfaceAdd);
    }

    pub(crate) fn request_route_info(&self) {
        // Request information about all non-BGP routes.
        for msg in [
            ZapiTxMsg::RedistributeDel(ZapiTxRedistInfo {
                afi: AddressFamily::Ipv4 as u16,
                proto: zclient::ffi::RouteType::All,
                instance: 0,
            }),
            ZapiTxMsg::RedistributeAdd(ZapiTxRedistInfo {
                afi: AddressFamily::Ipv4 as u16,
                proto: zclient::ffi::RouteType::All,
                instance: 0,
            }),
        ] {
            self.0.send(msg);
        }
    }

    pub(crate) fn initial_requests(&self) {
        for msg in [
            // Hello message.
            ZapiTxMsg::Hello(ZapiTxHelloInfo {
                redist_default: self.0.zclient.redist_default,
                instance: self.0.zclient.instance,
                session_id: 0,
                receive_notify: self.0.zclient.receive_notify as u8,
            }),
            // Request Router ID information.
            ZapiTxMsg::RouterIdAdd(ZapiTxRtrIdInfo {
                afi: AddressFamily::Ipv4 as u16,
            }),
        ] {
            self.0.send(msg);
        }
    }
}
