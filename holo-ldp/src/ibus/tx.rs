//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{self, LabelInstallMsg, LabelUninstallMsg};

use crate::fec::Fec;

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

pub(crate) fn route_redistribute_unsub(ibus_tx: &IbusChannelsTx) {
    for protocol in
        Protocol::route_types().filter(|protocol| *protocol != Protocol::BGP)
    {
        ibus_tx.route_redistribute_unsub(protocol, Some(AddressFamily::Ipv4));
    }
}

// Installs the labels learned for the nexthops of a FEC, replacing those
// installed before, or uninstalls them once no nexthop has a label left.
pub(crate) fn fec_sync(ibus_tx: &IbusChannelsTx, fec: &Fec) {
    let Some(local_label) = fec.inner.local_label else {
        return;
    };
    if local_label.is_reserved() {
        return;
    }
    let protocol = fec.inner.protocol.unwrap();
    let route = Some((protocol, *fec.inner.prefix));

    // Collect the nexthops that have a label.
    let nexthops = fec
        .nexthops
        .values()
        .filter_map(|nexthop| {
            let label = nexthop.get_label()?;
            Some(southbound::Nexthop::Address {
                ifindex: nexthop.ifindex.unwrap(),
                addr: nexthop.addr,
                labels: [label].into(),
            })
        })
        .collect::<Vec<_>>();

    // Fill-in and send message.
    if nexthops.is_empty() {
        let msg = LabelUninstallMsg {
            protocol: Protocol::LDP,
            label: local_label,
            route,
        };
        ibus_tx.route_mpls_del(msg);
    } else {
        let msg = LabelInstallMsg {
            protocol: Protocol::LDP,
            label: local_label,
            nexthops,
            route,
        };
        ibus_tx.route_mpls_add(msg);
    }
}
