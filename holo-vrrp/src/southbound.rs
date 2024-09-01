//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::southbound::{AddressMsg, InterfaceUpdateMsg};
use ipnetwork::IpNetwork;

use crate::interface::Interface;

// ===== global functions =====

pub(crate) fn process_iface_update(
    iface: &mut Interface,
    msg: InterfaceUpdateMsg,
) {
    // when the iface being updated is the
    // main interface for this `holo-vrrp`
    if msg.ifname == iface.name {
        iface.system.flags = msg.flags;
        iface.system.ifindex = Some(msg.ifindex);
        iface.system.mac_address = msg.mac_address;
    }

    // check if it is one of the macvlans being updated.
    for (vrid, instance) in iface.instances.iter_mut() {
        if let Some(mvlan_iface) = &mut instance.config.mac_vlan {
            let name = format!(
                "mvlan-vrrp{}{}",
                iface.system.ifindex.unwrap_or(0),
                vrid,
            );
            if mvlan_iface.name == name {
                mvlan_iface.system.flags = msg.flags;
                mvlan_iface.system.ifindex = Some(msg.ifindex);
                mvlan_iface.system.mac_address = msg.mac_address;
            }
        }
    }
    // TODO: trigger protocol event?
}

pub(crate) fn process_addr_add(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.insert(addr);

        // TODO: trigger protocol event?
    }
}

pub(crate) fn process_addr_del(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.remove(&addr);

        // TODO: trigger protocol event?
    }
}
