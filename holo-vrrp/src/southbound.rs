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
    if msg.ifname != iface.name {
        return;
    }

    iface.system.flags = msg.flags;
    iface.system.ifindex = Some(msg.ifindex);

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
