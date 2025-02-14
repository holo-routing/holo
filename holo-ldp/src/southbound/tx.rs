//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{self, LabelInstallMsg, LabelUninstallMsg};

use crate::fec::{FecInner, Nexthop};

// ===== global functions =====

pub(crate) fn router_id_sub(ibus_tx: &IbusChannelsTx) {
    ibus_tx.router_id_sub();
}

pub(crate) fn route_redistribute_sub(ibus_tx: &IbusChannelsTx) {
    for protocol in
        Protocol::route_types().filter(|protocol| *protocol != Protocol::BGP)
    {
        ibus_tx.route_redistribute_sub(protocol, Some(AddressFamily::Ipv4));
    }
}

pub(crate) fn label_install(
    ibus_tx: &IbusChannelsTx,
    fec: &FecInner,
    nexthop: &Nexthop,
) {
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
    let protocol = fec.protocol.unwrap();

    // Fill-in message.
    let msg = LabelInstallMsg {
        protocol: Protocol::LDP,
        label: local_label,
        nexthops: [southbound::Nexthop::Address {
            ifindex: nexthop.ifindex.unwrap(),
            addr: nexthop.addr,
            labels: vec![remote_label],
        }]
        .into(),
        route: Some((protocol, *fec.prefix)),
        replace: false,
    };

    // Send message.
    ibus_tx.route_mpls_add(msg);
}

pub(crate) fn label_uninstall(
    ibus_tx: &IbusChannelsTx,
    fec: &FecInner,
    nexthop: &Nexthop,
) {
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
    let protocol = fec.protocol.unwrap();

    // Fill-in message.
    let msg = LabelUninstallMsg {
        protocol: Protocol::LDP,
        label: local_label,
        nexthops: [southbound::Nexthop::Address {
            ifindex: nexthop.ifindex.unwrap(),
            addr: nexthop.addr,
            labels: vec![remote_label],
        }]
        .into(),
        route: Some((protocol, *fec.prefix)),
    };

    // Send message.
    ibus_tx.route_mpls_del(msg);
}
