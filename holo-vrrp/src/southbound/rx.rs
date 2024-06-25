//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
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

        // update names for all macvlans
        for (vrid, instance) in iface.instances.iter_mut() {
            instance.mac_vlan.name = format!("mvlan-vrrp-{}", vrid);
        }
        return;
    }

    let mut target_vrid: Option<u8> = None;

    //check if it is one of the macvlans being updated.
    'outer: for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;

        if mvlan_iface.name == name {
            mvlan_iface.system.flags = msg.flags;
            mvlan_iface.system.ifindex = Some(msg.ifindex);
            mvlan_iface.system.mac_address = msg.mac_address;

            target_vrid = Some(*vrid);

            break 'outer;
        }
    }

    if let Some(vrid) = target_vrid {
        iface.macvlan_create(vrid);
    }
}

pub(crate) fn process_addr_del(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname != iface.name {
        return;
    }

    // remove the address from the addresses of parent interfaces
    if let IpNetwork::V4(addr) = msg.addr {
        iface.system.addresses.remove(&addr);
    }

    for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;

        // if it is one of the macvlans being edited, we
        // remove the macvlan's
        if mvlan_iface.name == name {
            if let IpNetwork::V4(addr) = msg.addr {
                mvlan_iface.system.addresses.remove(&addr);
            }
        }
    }
}

pub(crate) fn process_addr_add(iface: &mut Interface, msg: AddressMsg) {
    if msg.ifname == iface.name {
        if let IpNetwork::V4(addr) = msg.addr {
            iface.system.addresses.insert(addr);
        }
    }

    // when this is some, it means that we need to rebind our
    // transmission socket multicast address to the newly added address
    let mut target_vrid: Option<u8> = None;

    // if the interface being updated is one of the macvlans
    for (vrid, instance) in iface.instances.iter_mut() {
        let name = format!("mvlan-vrrp-{}", vrid);
        let mvlan_iface = &mut instance.mac_vlan;
        if mvlan_iface.system.addresses.is_empty() {
            target_vrid = Some(*vrid);
        }
        if mvlan_iface.name == name {
            if let IpNetwork::V4(addr) = msg.addr {
                mvlan_iface.system.addresses.insert(addr);
            }
        }
    }

    if let Some(vrid) = target_vrid {
        iface.macvlan_create(vrid);
        iface.reset_timer(vrid);
    }
}
