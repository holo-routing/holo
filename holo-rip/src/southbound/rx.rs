//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_protocol::InstanceChannelsTx;
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};

use crate::instance::{Instance, InstanceState};
use crate::interface::{Interface, InterfaceUp};
use crate::route::{Route, RouteType};
use crate::southbound;
use crate::version::Version;

// ===== helper functions =====

fn connected_route_add<V>(
    instance_state: &mut InstanceState<V>,
    instance_tx: &InstanceChannelsTx<Instance<V>>,
    iface: &InterfaceUp<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    // Uninstall previously learned route (if any).
    let prefix = addr.apply_mask();
    if let Some(route) = instance_state.routes.get(&prefix) {
        southbound::tx::route_uninstall(&instance_tx.ibus, route);
    }

    // Add new connected route.
    let route = Route::new(
        prefix,
        iface.core.system.ifindex.unwrap(),
        None,
        iface.core.config.cost,
        0,
        RouteType::Connected,
    );
    instance_state.routes.insert(prefix, route);

    // Signal the output process to trigger an update.
    instance_tx.protocol_input.trigger_update();
}

fn connected_route_invalidate<V>(
    instance_state: &mut InstanceState<V>,
    instance_tx: &InstanceChannelsTx<Instance<V>>,
    iface: &InterfaceUp<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    let prefix = addr.apply_mask();
    if let Some(route) = instance_state.routes.get_mut(&prefix) {
        route.invalidate(iface.core.config.flush_interval, instance_tx);
    }
}

// ===== global functions =====

pub(crate) fn process_iface_update<V>(
    instance: &mut Instance<V>,
    msg: InterfaceUpdateMsg,
) where
    V: Version,
{
    let instance = match instance {
        Instance::Up(instance) => instance,
        _ => return,
    };

    if let Some((_, iface)) = instance
        .core
        .interfaces
        .update_ifindex(&msg.ifname, Some(msg.ifindex))
    {
        iface.core_mut().system.mtu = Some(msg.mtu);
        iface.core_mut().system.flags = msg.flags;
        iface.update(&mut instance.state, &instance.tx);

        // Add connected routes.
        if let Interface::Up(iface) = iface {
            for addr in &iface.core.system.addr_list {
                connected_route_add(
                    &mut instance.state,
                    &instance.tx,
                    iface,
                    addr,
                );
            }
        }
    }
}

pub(crate) fn process_addr_add<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let instance = match instance {
        Instance::Up(instance) => instance,
        _ => return,
    };
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };
    let Some((_, iface)) =
        instance.core.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Add address.
    if !iface.core_mut().system.addr_list.insert(addr) {
        return;
    }

    // Check if RIP needs to be activated on this interface.
    iface.update(&mut instance.state, &instance.tx);

    // Add connected route.
    if let Interface::Up(iface) = iface {
        connected_route_add(&mut instance.state, &instance.tx, iface, &addr);
    }
}

pub(crate) fn process_addr_del<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let instance = match instance {
        Instance::Up(instance) => instance,
        _ => return,
    };
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };
    let Some((_, iface)) =
        instance.core.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Remove address.
    if !iface.core_mut().system.addr_list.remove(&addr) {
        return;
    }

    // Invalidate connected route.
    if let Interface::Up(iface) = iface {
        connected_route_invalidate(
            &mut instance.state,
            &instance.tx,
            iface,
            &addr,
        );
    }

    // Check if RIP needs to be deactivated on this interface.
    iface.update(&mut instance.state, &instance.tx);
}
