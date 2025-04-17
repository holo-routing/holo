//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    LabelInstallMsg, LabelUninstallMsg, Nexthop, RouteKeyMsg, RouteMsg,
    RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::collections::Interfaces;
use crate::interface::Interface;
use crate::route::Route;

// ===== global functions =====

pub(crate) fn router_id_sub(ibus_tx: &IbusChannelsTx) {
    ibus_tx.router_id_sub();
}

pub(crate) fn hostname_sub(ibus_tx: &IbusChannelsTx) {
    ibus_tx.hostname_sub();
}

pub(crate) fn route_install(
    ibus_tx: &IbusChannelsTx,
    destination: &IpNetwork,
    route: &Route,
    old_sr_label: Option<Label>,
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
                labels: nexthop
                    .sr_label
                    .map(|label| vec![label])
                    .unwrap_or_default(),
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
    ibus_tx.route_ip_add(msg);

    // Unnstall previous SR Prefix-SID input label if it has changed.
    if old_sr_label != route.sr_label
        && let Some(old_sr_label) = old_sr_label
    {
        let msg = LabelUninstallMsg {
            protocol: Protocol::ISIS,
            label: old_sr_label,
            nexthops: BTreeSet::new(),
            route: None,
        };
        ibus_tx.route_mpls_del(msg);
    }

    // Install SR Prefix-SID input label.
    if let Some(sr_label) = route.sr_label {
        let msg = LabelInstallMsg {
            protocol: Protocol::ISIS,
            label: sr_label,
            nexthops,
            route: None,
            replace: true,
        };
        ibus_tx.route_mpls_add(msg);
    }
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusChannelsTx,
    destination: &IpNetwork,
    route: &Route,
) {
    // Uninstall route.
    let msg = RouteKeyMsg {
        protocol: Protocol::ISIS,
        prefix: *destination,
    };
    ibus_tx.route_ip_del(msg);

    // Uninstall SR Prefix-SID input label.
    if let Some(sr_label) = route.sr_label {
        let msg = LabelUninstallMsg {
            protocol: Protocol::ISIS,
            label: sr_label,
            nexthops: BTreeSet::new(),
            route: None,
        };
        ibus_tx.route_mpls_del(msg);
    }
}

pub(crate) fn adj_sid_install(
    ibus_tx: &IbusChannelsTx,
    iface: &Interface,
    nbr_addr: IpAddr,
    label: Label,
) {
    let msg = LabelInstallMsg {
        protocol: Protocol::ISIS,
        label,
        nexthops: [Nexthop::Address {
            ifindex: iface.system.ifindex.unwrap(),
            addr: nbr_addr,
            labels: vec![Label::new(Label::IMPLICIT_NULL)],
        }]
        .into(),
        route: None,
        replace: true,
    };
    ibus_tx.route_mpls_add(msg);
}

pub(crate) fn adj_sid_uninstall(ibus_tx: &IbusChannelsTx, label: Label) {
    let msg = LabelUninstallMsg {
        protocol: Protocol::ISIS,
        label,
        nexthops: Default::default(),
        route: None,
    };
    ibus_tx.route_mpls_del(msg);
}
