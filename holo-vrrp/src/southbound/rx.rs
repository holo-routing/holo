//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::southbound::{AddressMsg, InterfaceUpdateMsg};

use crate::interface::Interface;

// ===== global functions =====

pub(crate) fn process_iface_update(
    interface: &mut Interface,
    msg: InterfaceUpdateMsg,
) {
    let (iface, mut instances) = interface.iter_instances();

    // Handle updates for the primary VRRP interface.
    if msg.ifname == iface.name {
        iface.system.flags = msg.flags;
        iface.system.ifindex = Some(msg.ifindex);
        iface.system.mac_address = msg.mac_address;
        for instance in instances {
            instance.update(&iface);
        }
        return;
    }

    // Handle updates for macvlan interfaces.
    if let Some(instance) =
        instances.find(|instance| msg.ifname == instance.mvlan.name)
    {
        // mvlan  updates
        let mvlan = &mut instance.mvlan;
        mvlan.system.flags = msg.flags;
        mvlan.system.ifindex = Some(msg.ifindex);
        mvlan.system.mac_address = msg.mac_address;
        instance.update(&iface);
    }
}

pub(crate) fn process_addr_add(interface: &mut Interface, msg: AddressMsg) {
    let (interface, instances) = interface.iter_instances();

    // Handle address updates for the primary VRRP interface.
    if msg.ifname == interface.name {
        interface.system.addresses.insert(msg.addr);
        for instance in instances {
            instance.update(&interface);
        }
    }
}

pub(crate) fn process_addr_del(interface: &mut Interface, msg: AddressMsg) {
    let (interface, instances) = interface.iter_instances();

    // Handle address updates for the primary VRRP interface.
    if msg.ifname == interface.name {
        interface.system.addresses.remove(&msg.addr);
        for instance in instances {
            instance.update(&interface);
        }
    }
}
