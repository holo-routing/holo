//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusSender, RouteMplsMsg, RouterIdMsg};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{self, LabelInstallMsg, LabelUninstallMsg};

use crate::fec::{FecInner, Nexthop};

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(RouterIdMsg::Query.into());
}

pub(crate) fn label_install(
    ibus_tx: &IbusSender,
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
    let msg = RouteMplsMsg::Add(LabelInstallMsg {
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
    });

    // Send message.
    let _ = ibus_tx.send(msg.into());
}

pub(crate) fn label_uninstall(
    ibus_tx: &IbusSender,
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
    let msg = RouteMplsMsg::Delete(LabelUninstallMsg {
        protocol: Protocol::LDP,
        label: local_label,
        nexthops: [southbound::Nexthop::Address {
            ifindex: nexthop.ifindex.unwrap(),
            addr: nexthop.addr,
            labels: vec![remote_label],
        }]
        .into(),
        route: Some((protocol, *fec.prefix)),
    });

    // Send message.
    let _ = ibus_tx.send(msg.into());
}
