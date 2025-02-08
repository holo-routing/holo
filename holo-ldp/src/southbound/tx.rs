//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusChannelsTx, IbusMsg};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{self, LabelInstallMsg, LabelUninstallMsg};

use crate::fec::{FecInner, Nexthop};

// ===== global functions =====

pub(crate) fn router_id_query(ibus_tx: &IbusChannelsTx) {
    let _ = ibus_tx.interface.send(IbusMsg::RouterIdQuery);
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
    let msg = IbusMsg::RouteMplsAdd(msg);
    let _ = ibus_tx.routing.send(msg);
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
    let msg = IbusMsg::RouteMplsDel(msg);
    let _ = ibus_tx.routing.send(msg);
}
