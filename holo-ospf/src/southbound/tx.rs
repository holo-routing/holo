//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::IpAddr;

use derive_new::new;
use holo_southbound::tx::SouthboundTx;
use holo_southbound::zclient::ffi::{LspType, NexthopType};
use holo_southbound::zclient::messages::{
    ZapiTxHelloInfo, ZapiTxLabelsInfo, ZapiTxMsg, ZapiTxNexthopInfo,
    ZapiTxRouteInfo, ZapiTxRtrIdInfo,
};
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::mpls::Label;

use crate::collections::Arena;
use crate::interface::Interface;
use crate::route::RouteNet;
use crate::version::Version;

#[derive(Debug, new)]
pub struct InstanceSouthboundTx(pub SouthboundTx);

// ===== impl InstanceSouthboundTx =====

impl InstanceSouthboundTx {
    pub(crate) fn route_install<V>(
        &self,
        destination: &V::IpNetwork,
        route: &RouteNet<V>,
        old_sr_label: Option<Label>,
        distance: u8,
        interfaces: &Arena<Interface<V>>,
    ) where
        V: Version,
    {
        // Fill-in nexthops.
        let af = destination.address_family();
        let lsp_type = LspType::OspfSr;
        let nexthops = route
            .nexthops
            .values()
            .map(|nexthop| match nexthop.addr {
                Some(addr) => {
                    let iface = &interfaces[nexthop.iface_idx];
                    let addr = <V::IpAddr as Into<IpAddr>>::into(addr);
                    ZapiTxNexthopInfo {
                        nhtype: NexthopType::from((af, true)),
                        addr: Some(addr),
                        ifindex: iface.system.ifindex.unwrap(),
                        label: nexthop.sr_label.map(|label| (lsp_type, label)),
                    }
                }
                None => {
                    let iface = &interfaces[nexthop.iface_idx];
                    ZapiTxNexthopInfo {
                        nhtype: NexthopType::Ifindex,
                        addr: None,
                        ifindex: iface.system.ifindex.unwrap(),
                        label: nexthop.sr_label.map(|label| (lsp_type, label)),
                    }
                }
            })
            .collect::<Vec<_>>();

        // Install route.
        let msg_info = ZapiTxRouteInfo {
            proto: V::PROTOCOL.into(),
            instance: 0,
            prefix: (*destination).into(),
            nexthops: nexthops.clone(),
            distance: Some(distance),
            metric: Some(route.metric()),
            tag: route.tag,
        };
        let msg = ZapiTxMsg::RouteReplace(msg_info);
        self.0.send(msg);

        // Unnstall previous SR Prefix-SID input label if it has changed.
        if old_sr_label != route.sr_label {
            if let Some(old_sr_label) = old_sr_label {
                let msg_info = ZapiTxLabelsInfo {
                    lsp_type,
                    local_label: old_sr_label,
                    route: None,
                    nexthops: vec![],
                };
                let msg = ZapiTxMsg::LabelsDel(msg_info);
                self.0.send(msg);
            }
        }

        // Install SR Prefix-SID input label.
        if let Some(sr_label) = &route.sr_label {
            let msg_info = ZapiTxLabelsInfo {
                lsp_type,
                local_label: *sr_label,
                route: None,
                nexthops,
            };
            let msg = ZapiTxMsg::LabelsReplace(msg_info);
            self.0.send(msg);
        }
    }

    pub(crate) fn route_uninstall<V>(
        &self,
        destination: &V::IpNetwork,
        route: &RouteNet<V>,
    ) where
        V: Version,
    {
        // Uninstall route.
        let msg_info = ZapiTxRouteInfo {
            proto: V::PROTOCOL.into(),
            instance: 0,
            prefix: (*destination).into(),
            nexthops: vec![],
            distance: None,
            metric: None,
            tag: route.tag,
        };
        let msg = ZapiTxMsg::RouteDel(msg_info);
        self.0.send(msg);

        // Uninstall SR Prefix-SID input label.
        if let Some(sr_label) = &route.sr_label {
            let msg_info = ZapiTxLabelsInfo {
                lsp_type: LspType::OspfSr,
                local_label: *sr_label,
                route: None,
                nexthops: vec![],
            };
            let msg = ZapiTxMsg::LabelsDel(msg_info);
            self.0.send(msg);
        }
    }

    pub(crate) fn adj_sid_install<V>(
        &self,
        iface: &Interface<V>,
        nbr_addr: V::NetIpAddr,
        label: Label,
    ) where
        V: Version,
    {
        let af = nbr_addr.address_family();
        let lsp_type = LspType::OspfSr;
        let msg_info = ZapiTxLabelsInfo {
            lsp_type,
            local_label: label,
            route: None,
            nexthops: vec![ZapiTxNexthopInfo {
                nhtype: NexthopType::from((af, true)),
                addr: Some(nbr_addr.into()),
                ifindex: iface.system.ifindex.unwrap(),
                label: Some((lsp_type, Label::new(Label::IMPLICIT_NULL))),
            }],
        };
        let msg = ZapiTxMsg::LabelsAdd(msg_info);
        self.0.send(msg);
    }

    pub(crate) fn adj_sid_uninstall(&self, label: Label) {
        let msg_info = ZapiTxLabelsInfo {
            lsp_type: LspType::OspfSr,
            local_label: label,
            route: None,
            nexthops: vec![],
        };
        let msg = ZapiTxMsg::LabelsDel(msg_info);
        self.0.send(msg);
    }

    pub(crate) fn request_interface_info(&self) {
        self.0.send(ZapiTxMsg::InterfaceAdd);
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
