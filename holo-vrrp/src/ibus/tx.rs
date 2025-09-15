//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::mac_addr::MacAddr;
use ipnetwork::IpNetwork;

pub(crate) fn mvlan_create(
    ibus_tx: &IbusChannelsTx,
    parent_ifname: String,
    ifname: String,
    mac_addr: MacAddr,
) {
    ibus_tx.macvlan_add(parent_ifname, ifname, Some(mac_addr));
}

pub(crate) fn mvlan_delete(
    ibus_tx: &IbusChannelsTx,
    ifname: impl Into<String>,
) {
    ibus_tx.macvlan_del(ifname.into());
}

pub(crate) fn ip_addr_add(
    ibus_tx: &IbusChannelsTx,
    ifname: impl Into<String>,
    addr: impl Into<IpNetwork>,
) {
    ibus_tx.interface_ip_add(ifname.into(), addr.into());
}

pub(crate) fn ip_addr_del(
    ibus_tx: &IbusChannelsTx,
    ifname: impl Into<String>,
    addr: impl Into<IpNetwork>,
) {
    ibus_tx.interface_ip_del(ifname.into(), addr.into());
}
