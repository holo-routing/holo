//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::{
    IbusSender, RouteBierMsg, RouteIpMsg, RouteMplsMsg, RouterIdMsg,
};
use holo_utils::mpls::Label;
use holo_utils::southbound::{
    BierNbrInstallMsg, BierNbrUninstallMsg, LabelInstallMsg, LabelUninstallMsg,
    Nexthop, RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};

use crate::collections::Arena;
use crate::interface::Interface;
use crate::route::RouteNet;
use crate::version::Version;

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(RouterIdMsg::Query.into());
}

pub(crate) fn route_install<V>(
    ibus_tx: &IbusSender,
    destination: &V::IpNetwork,
    route: &RouteNet<V>,
    old_sr_label: Option<Label>,
    distance: u8,
    interfaces: &Arena<Interface<V>>,
) where
    V: Version,
{
    // Fill-in nexthops.
    let nexthops = route
        .nexthops
        .values()
        .map(|nexthop| match nexthop.addr {
            Some(addr) => {
                let iface = &interfaces[nexthop.iface_idx];
                Nexthop::Address {
                    ifindex: iface.system.ifindex.unwrap(),
                    addr: <V::IpAddr as Into<IpAddr>>::into(addr),
                    labels: nexthop
                        .sr_label
                        .map(|label| vec![label])
                        .unwrap_or_default(),
                }
            }
            None => {
                let iface = &interfaces[nexthop.iface_idx];
                Nexthop::Interface {
                    ifindex: iface.system.ifindex.unwrap(),
                }
            }
        })
        .collect::<BTreeSet<_>>();

    // Install route.
    let msg = RouteIpMsg::Add(RouteMsg {
        protocol: V::PROTOCOL,
        prefix: (*destination).into(),
        distance: distance.into(),
        metric: route.metric(),
        tag: route.tag,
        opaque_attrs: RouteOpaqueAttrs::Ospf {
            route_type: route.path_type,
        },
        nexthops: nexthops.clone(),
    });
    let _ = ibus_tx.send(msg.into());

    // Unnstall previous SR Prefix-SID input label if it has changed.
    if old_sr_label != route.sr_label {
        if let Some(old_sr_label) = old_sr_label {
            let msg = RouteMplsMsg::Delete(LabelUninstallMsg {
                protocol: V::PROTOCOL,
                label: old_sr_label,
                nexthops: BTreeSet::new(),
                route: None,
            });
            let _ = ibus_tx.send(msg.into());
        }
    }

    // Install SR Prefix-SID input label.
    if let Some(sr_label) = &route.sr_label {
        let msg = RouteMplsMsg::Add(LabelInstallMsg {
            protocol: V::PROTOCOL,
            label: *sr_label,
            nexthops: nexthops.clone(),
            route: None,
            replace: true,
        });
        let _ = ibus_tx.send(msg.into());
    }

    // Install BIER neighbor entry
    if let Some(bier_info) = &route.bier_info {
        let msg = RouteBierMsg::Add(BierNbrInstallMsg {
            bier_info: bier_info.clone(),
            nexthops,
            prefix: (*destination).into(),
        });
        let _ = ibus_tx.send(msg.into());
    }
}

pub(crate) fn route_uninstall<V>(
    ibus_tx: &IbusSender,
    destination: &V::IpNetwork,
    route: &RouteNet<V>,
) where
    V: Version,
{
    // Uninstall route.
    let msg = RouteIpMsg::Delete(RouteKeyMsg {
        protocol: V::PROTOCOL,
        prefix: (*destination).into(),
    });
    let _ = ibus_tx.send(msg.into());

    // Uninstall SR Prefix-SID input label.
    if let Some(sr_label) = &route.sr_label {
        let msg = RouteMplsMsg::Delete(LabelUninstallMsg {
            protocol: V::PROTOCOL,
            label: *sr_label,
            nexthops: BTreeSet::new(),
            route: None,
        });
        let _ = ibus_tx.send(msg.into());
    }

    // Uninstall BIER neighbor entry
    if let Some(bier_info) = &route.bier_info {
        for bsl in &bier_info.bfr_bss {
            let msg = RouteBierMsg::Delete(BierNbrUninstallMsg {
                sd_id: bier_info.sd_id,
                bfr_id: bier_info.bfr_id,
                bsl: *bsl,
            });
            let _ = ibus_tx.send(msg.into());
        }
    }
}

pub(crate) fn adj_sid_install<V>(
    ibus_tx: &IbusSender,
    iface: &Interface<V>,
    nbr_addr: V::NetIpAddr,
    label: Label,
) where
    V: Version,
{
    let msg = RouteMplsMsg::Add(LabelInstallMsg {
        protocol: V::PROTOCOL,
        label,
        nexthops: [Nexthop::Address {
            ifindex: iface.system.ifindex.unwrap(),
            addr: nbr_addr.into(),
            labels: vec![Label::new(Label::IMPLICIT_NULL)],
        }]
        .into(),
        route: None,
        replace: false,
    });
    let _ = ibus_tx.send(msg.into());
}

pub(crate) fn adj_sid_uninstall<V>(ibus_tx: &IbusSender, label: Label)
where
    V: Version,
{
    let msg = RouteMplsMsg::Delete(LabelUninstallMsg {
        protocol: V::PROTOCOL,
        label,
        nexthops: BTreeSet::new(),
        route: None,
    });
    let _ = ibus_tx.send(msg.into());
}
