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
    let (interface, mut instances) = interface.iter_instances();

    // Handle updates for the primary VRRP interface.
    if msg.ifname == interface.name {
        interface.system.flags = msg.flags;
        interface.system.ifindex = Some(msg.ifindex);
        interface.system.mac_address = msg.mac_address;
        for instance in instances {
            instance.update(&interface);
        }
        return;
    }

    // Handle updates for VRRP macvlan interfaces.
    if let Some(instance) =
        instances.find(|instance| msg.ifname == instance.mvlan.name)
    {
        instance.mvlan.system.flags = msg.flags;
        instance.mvlan.system.ifindex = Some(msg.ifindex);
        instance.mvlan.system.mac_address = msg.mac_address;
        instance.update(&interface);
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
        return;
    }

    // Check for if it's an mvlan interface whose address has been added.
    for instance in instances {
        if instance.mvlan.name == msg.ifname {
            instance.mvlan.system.addresses.insert(msg.addr);
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
        return;
    }

    // Check for if it's an mvlan interface whose address has been deleted.
    for instance in instances {
        if instance.mvlan.name == msg.ifname {
            instance.mvlan.system.addresses.remove(&msg.addr);
            instance.update(&interface);
        }
    }
}
