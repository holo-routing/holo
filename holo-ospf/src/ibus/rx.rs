//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::bfd;
use holo_utils::bier::BierCfgEvent;
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};
use holo_utils::sr::SrCfgEvent;

use crate::error::Error;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::LsaOriginateEvent;
use crate::neighbor::nsm;
use crate::version::Version;

// OSPF version-specific code.
pub trait IbusRxVersion<V: Version> {
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

pub(crate) fn process_sr_cfg_change<V>(
    instance: &mut Instance<V>,
    change: SrCfgEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if let Some((instance, arenas)) = instance.as_up()
        && instance.config.sr_enabled
    {
        // Check which LSAs need to be reoriginated or flushed.
        V::lsa_orig_event(
            &instance,
            arenas,
            LsaOriginateEvent::SrCfgChange { change },
        )?;
    }

    Ok(())
}

pub(crate) fn process_bier_cfg_change<V>(
    instance: &mut Instance<V>,
    change: BierCfgEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if let Some((instance, arenas)) = instance.as_up()
        && instance.config.bier.enabled
    {
        V::lsa_orig_event(
            &instance,
            arenas,
            LsaOriginateEvent::BierCfgChange { change },
        )?;
    }
    Ok(())
}

pub(crate) fn process_bfd_state_update<V>(
    instance: &mut Instance<V>,
    sess_key: bfd::SessionKey,
    state: bfd::State,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // We're only interested on peer down notifications.
    if state != bfd::State::Down {
        return Ok(());
    }

    // Ignore notification if the OSPF instance isn't active anymore.
    let Some((instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    if let bfd::SessionKey::IpSingleHop { ifname, dst } = sess_key {
        // Lookup area and interface.
        let (iface, area) = match arenas.areas.iter().find_map(|area| {
            area.interfaces
                .get_by_name(&arenas.interfaces, &ifname)
                .map(|(_, iface)| (iface, area))
        }) {
            Some(value) => value,
            None => return Ok(()),
        };

        // Lookup neighbor.
        if let Some(nbr) = iface
            .state
            .neighbors
            .iter(&arenas.neighbors)
            .find(|nbr| nbr.src.into() == dst)
        {
            instance.tx.protocol_input.nsm_event(
                area.id,
                iface.id,
                nbr.id,
                nsm::Event::InactivityTimer,
            );
        }
    }

    Ok(())
}

pub(crate) fn process_keychain_update<V>(
    instance: &mut Instance<V>,
    keychain_name: &str,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let Some((instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    for area in arenas.areas.iter_mut() {
        for iface_idx in area.interfaces.indexes() {
            let iface = &mut arenas.interfaces[iface_idx];
            if iface.config.auth_keychain.as_deref() != Some(keychain_name) {
                continue;
            }

            // Update interface authentication keys.
            iface.auth_update(area, &instance);
        }
    }

    Ok(())
}

pub(crate) fn process_hostname_update<V>(
    instance: &mut Instance<V>,
    hostname: Option<String>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    instance.shared.hostname = hostname;

    if let Some((instance, arenas)) = instance.as_up() {
        V::lsa_orig_event(
            &instance,
            arenas,
            LsaOriginateEvent::HostnameChange,
        )?;
    }

    Ok(())
}
