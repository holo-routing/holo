//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;

use holo_utils::southbound::{AddressMsg, InterfaceUpdateMsg};
use ipnetwork::IpNetwork;

use crate::error::Error;
use crate::instance::Instance;
use crate::packet::LevelType;

// ===== global functions =====

pub(crate) async fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;
}

pub(crate) fn process_iface_update(
    instance: &mut Instance,
    msg: InterfaceUpdateMsg,
) -> Result<(), Error> {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return Ok(());
    };
    let iface_idx = iface.index;

    // Update interface data.
    let old_mtu = iface.system.mtu;
    iface.system.flags = msg.flags;
    iface.system.mtu = Some(msg.mtu);
    iface.system.mac_addr = Some(msg.mac_address);
    if iface.system.ifindex != Some(msg.ifindex) {
        instance
            .arenas
            .interfaces
            .update_ifindex(iface_idx, Some(msg.ifindex));
    }

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        // Update the padding used in Hello PDUs if the MTU has changed.
        if iface.config.hello_padding
            && iface.system.mtu != old_mtu
            && iface.state.active
            && !iface.is_passive()
        {
            iface.hello_interval_start(&instance, LevelType::All);
        }

        // Check if IS-IS needs to be activated or deactivated on this interface.
        iface.update(&mut instance, &mut arenas.adjacencies)?;
    }

    Ok(())
}

pub(crate) fn process_addr_add(instance: &mut Instance, msg: AddressMsg) {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };
    let iface_idx = iface.index;

    // Add address to interface.
    match msg.addr {
        IpNetwork::V4(addr) => {
            iface.system.ipv4_addr_list.insert(addr);
        }
        IpNetwork::V6(addr) => {
            iface.system.ipv6_addr_list.insert(addr);
        }
    }

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        if iface.state.active {
            // Update Hello Tx task(s).
            if !iface.is_passive() {
                iface.hello_interval_start(&instance, LevelType::All);
            }

            // Schedule LSP reorigination.
            instance.schedule_lsp_origination(LevelType::All);
        }
    }
}

pub(crate) fn process_addr_del(instance: &mut Instance, msg: AddressMsg) {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };
    let iface_idx = iface.index;

    // Remove address from interface.
    match msg.addr {
        IpNetwork::V4(addr) => {
            iface.system.ipv4_addr_list.remove(&addr);
        }
        IpNetwork::V6(addr) => {
            iface.system.ipv6_addr_list.remove(&addr);
        }
    }

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        if iface.state.active {
            // Update Hello Tx task(s).
            if !iface.is_passive() {
                iface.hello_interval_start(&instance, LevelType::All);
            }

            // Schedule LSP reorigination.
            instance.schedule_lsp_origination(LevelType::All);
        }
    }
}
