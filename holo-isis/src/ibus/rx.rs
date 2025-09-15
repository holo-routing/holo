//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use holo_utils::bfd;
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{
    AddressMsg, InterfaceUpdateMsg, RouteKeyMsg, RouteMsg,
};
use holo_utils::sr::{MsdType, SrCfg};

use crate::adjacency::{AdjacencyEvent, AdjacencyState};
use crate::error::Error;
use crate::instance::Instance;
use crate::packet::LevelType;
use crate::route::RouteSys;

// ===== global functions =====

pub(crate) fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(LevelType::All);
    }
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
    iface.system.msd = msg.msd;
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
    iface.system.addr_list.insert(msg.addr);

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
    iface.system.addr_list.remove(&msg.addr);

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

pub(crate) fn process_route_add(instance: &mut Instance, msg: RouteMsg) {
    let prefix = msg.prefix;
    if !prefix.is_routable() {
        return;
    }

    // Return if no configuration exists for the address family.
    let Some(af_cfg) = instance.config.afs.get(&prefix.address_family()) else {
        return;
    };

    // Iterate over levels where redistribution is enabled for this route's
    // protocol.
    for level in instance
        .config
        .levels()
        .filter(|level| {
            af_cfg.redistribution.contains_key(&(*level, msg.protocol))
        })
        .collect::<Vec<_>>()
    {
        let route = RouteSys {
            protocol: msg.protocol,
            metric: msg.metric,
            tag: msg.tag,
            opaque_attrs: msg.opaque_attrs,
        };
        let routes = instance.system.routes.get_mut(level);
        routes.insert(prefix, route);

        // Schedule LSP reorigination.
        if let Some((mut instance, _)) = instance.as_up() {
            instance.schedule_lsp_origination(level);
        }
    }
}

pub(crate) fn process_route_del(instance: &mut Instance, msg: RouteKeyMsg) {
    let prefix = msg.prefix;
    if !prefix.is_routable() {
        return;
    }

    // Return if no configuration exists for the address family.
    let Some(af_cfg) = instance.config.afs.get(&prefix.address_family()) else {
        return;
    };

    // Iterate over levels where redistribution is enabled for this route's
    // protocol.
    for level in instance
        .config
        .levels()
        .filter(|level| {
            af_cfg.redistribution.contains_key(&(*level, msg.protocol))
        })
        .collect::<Vec<_>>()
    {
        let routes = instance.system.routes.get_mut(level);
        routes.remove(&prefix);

        // Schedule LSP reorigination.
        if let Some((mut instance, _)) = instance.as_up() {
            instance.schedule_lsp_origination(level);
        }
    }
}

pub(crate) fn process_hostname_update(
    instance: &mut Instance,
    hostname: Option<String>,
) {
    // Update hostname.
    instance.shared.hostname = hostname;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

pub(crate) fn process_bfd_state_update(
    instance: &mut Instance,
    sess_key: bfd::SessionKey,
    state: bfd::State,
) -> Result<(), Error> {
    // We're only interested on peer down notifications.
    if state != bfd::State::Down {
        return Ok(());
    }

    // Ignore notification if the IS-IS instance isn't active anymore.
    let Some((mut instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    // Lookup interface.
    let bfd::SessionKey::IpSingleHop { ifname, .. } = &sess_key else {
        return Ok(());
    };
    let Some(iface) = arenas.interfaces.get_mut_by_name(ifname) else {
        return Ok(());
    };

    // On LAN interfaces, both L1 and L2 adjacencies share the same BFD session.
    iface.with_adjacencies(&mut arenas.adjacencies, |iface, adj| {
        let bfd = adj
            .bfd
            .iter_mut()
            .filter_map(|(_, b)| b.as_mut())
            .find(|b| b.sess_key == sess_key);
        if let Some(bfd) = bfd {
            // Update the status of the BFD session.
            bfd.state = Some(state);
            if !adj.is_bfd_healthy() {
                adj.state_change(
                    iface,
                    &mut instance,
                    AdjacencyEvent::BfdDown,
                    AdjacencyState::Down,
                );
            }
        }
    });
    instance.schedule_lsp_origination(instance.config.level_type);

    Ok(())
}

pub(crate) fn process_keychain_update(
    instance: &mut Instance,
    keychain_name: &str,
) -> Result<(), Error> {
    let Some((mut instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    for iface in arenas.interfaces.iter_mut() {
        if iface.config.hello_auth.all.keychain.as_deref()
            != Some(keychain_name)
        {
            continue;
        }

        // Restart network Tx/Rx tasks.
        iface.restart_network_tasks(&mut instance);
    }

    Ok(())
}

pub(crate) fn process_sr_cfg_update(
    instance: &mut Instance,
    sr_config: Arc<SrCfg>,
) {
    // Update SR configuration.
    instance.shared.sr_config = sr_config;

    // Schedule LSP reorigination.
    if instance.config.sr.enabled
        && let Some((mut instance, _)) = instance.as_up()
    {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

pub(crate) fn process_msd_update(
    instance: &mut Instance,
    node_msd: BTreeMap<MsdType, u8>,
) {
    // Update node MSD.
    instance.system.node_msd = node_msd;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}
