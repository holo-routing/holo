//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};

use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::LsaOriginateEvent;
use crate::version::Version;

// OSPF version-specific code.
pub trait SouthboundRxVersion<V: Version> {
    fn process_addr_add(
        iface: &mut Interface<V>,
        addr: V::NetIpNetwork,
        unnumbered: bool,
    );

    fn process_addr_del(iface: &mut Interface<V>, addr: V::NetIpNetwork);
}

// ===== global functions =====

pub(crate) fn process_router_id_update<V>(
    instance: &mut Instance<V>,
    router_id: Option<Ipv4Addr>,
) where
    V: Version,
{
    instance.system.router_id = router_id;
    instance.update();
}

pub(crate) fn process_iface_update<V>(
    instance: &mut Instance<V>,
    msg: InterfaceUpdateMsg,
) where
    V: Version,
{
    let Some((instance, arenas)) = instance.as_up() else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, area)) = arenas.areas.iter_mut().find_map(|area| {
        area.interfaces
            .get_by_name(&arenas.interfaces, &msg.ifname)
            .map(|(iface_idx, _iface)| (iface_idx, area))
    }) else {
        return;
    };
    let iface = &mut arenas.interfaces[iface_idx];

    // Update interface data.
    iface.system.mtu = Some(msg.mtu as u16);
    iface.system.flags = msg.flags;
    if iface.system.ifindex != Some(msg.ifindex) {
        area.interfaces
            .update_ifindex(iface_idx, iface, Some(msg.ifindex));
    }

    // Check if OSPF needs to be activated or deactivated on this interface.
    iface.update(area, &instance, &mut arenas.neighbors, &arenas.lsa_entries);
}

pub(crate) fn process_addr_add<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some((instance, arenas)) = instance.as_up() else {
        return;
    };

    // Get address value.
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, area)) = arenas.areas.iter().find_map(|area| {
        area.interfaces
            .get_by_name(&arenas.interfaces, &msg.ifname)
            .map(|(iface_idx, _iface)| (iface_idx, area))
    }) else {
        return;
    };
    let iface = &mut arenas.interfaces[iface_idx];

    // Add address to interface.
    if !iface.system.addr_list.insert(addr) {
        return;
    }

    // Check if the instance does routing for this address-family.
    if addr.address_family() == instance.state.af {
        // (Re)originate LSAs that might have been affected.
        instance.tx.protocol_input.lsa_orig_event(
            LsaOriginateEvent::InterfaceAddrAddDel {
                area_id: area.id,
                iface_id: iface.id,
            },
        );
    }

    // OSPF version-specific address handling.
    if let Some(addr) = V::NetIpNetwork::get(msg.addr) {
        V::process_addr_add(
            iface,
            addr,
            msg.flags.contains(AddressFlags::UNNUMBERED),
        );
    }

    // Check if OSPF needs to be activated on this interface.
    iface.update(area, &instance, &mut arenas.neighbors, &arenas.lsa_entries);
}

pub(crate) fn process_addr_del<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some((instance, arenas)) = instance.as_up() else {
        return;
    };

    // Get address value.
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, area)) = arenas.areas.iter().find_map(|area| {
        area.interfaces
            .get_by_name(&arenas.interfaces, &msg.ifname)
            .map(|(iface_idx, _iface)| (iface_idx, area))
    }) else {
        return;
    };
    let iface = &mut arenas.interfaces[iface_idx];

    // Remove address from interface.
    if !iface.system.addr_list.remove(&addr) {
        return;
    }

    // Check if the instance does routing for this address-family.
    if addr.address_family() == instance.state.af {
        // (Re)originate LSAs that might have been affected.
        instance.tx.protocol_input.lsa_orig_event(
            LsaOriginateEvent::InterfaceAddrAddDel {
                area_id: area.id,
                iface_id: iface.id,
            },
        );
    }

    // OSPF version-specific address handling.
    if let Some(addr) = V::NetIpNetwork::get(msg.addr) {
        V::process_addr_del(iface, addr);
    }

    // Check if OSPF needs to be deactivated on this interface.
    iface.update(area, &instance, &mut arenas.neighbors, &arenas.lsa_entries);
}
