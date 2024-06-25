//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{
    InterfaceIpAddRequestMsg, InterfaceIpDeleteRequestMsg, MacvlanCreateMsg,
};
use ipnetwork::IpNetwork;

pub(crate) fn create_macvlan_iface(
    name: String,
    parent_name: String,
    mac_address: [u8; 6],
    ibus_tx: &IbusSender,
) {
    let msg = MacvlanCreateMsg {
        parent_name,
        name,
        mac_address: Some(mac_address),
    };
    let _ = ibus_tx.send(IbusMsg::CreateMacVlan(msg));
}

pub(crate) fn mvlan_delete(ifindex: u32, ibus_tx: &IbusSender) {
    let _ = ibus_tx.send(IbusMsg::InterfaceDeleteRequest(ifindex));
}

// adds an address to an interface
pub(crate) fn addr_add(ifindex: u32, addr: IpNetwork, ibus_tx: &IbusSender) {
    let msg = InterfaceIpAddRequestMsg { ifindex, addr };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpAddRequest(msg));
}

// removes a specific address from an interface
pub(crate) fn addr_del(ifindex: u32, addr: IpNetwork, ibus_tx: &IbusSender) {
    let msg = InterfaceIpDeleteRequestMsg { ifindex, addr };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpDeleteRequest(msg));
}
