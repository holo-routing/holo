//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};

use crate::ibus;
use crate::instance::{Instance, InstanceUpView};
use crate::interface::Interface;
use crate::route::{Route, RouteType};
use crate::version::Version;

// ===== global functions =====

pub(crate) fn process_iface_update<V>(
    instance: &mut Instance<V>,
    msg: InterfaceUpdateMsg,
) where
    V: Version,
{
    // Lookup interface.
    let Some((iface_idx, iface)) = instance
        .interfaces
        .update_ifindex(&msg.ifname, Some(msg.ifindex))
    else {
        return;
    };

    // Update interface data.
    iface.system.mtu = Some(msg.mtu);
    iface.system.flags = msg.flags;

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Check if RIP needs to be activated or deactivated on this interface.
        iface.update(&mut instance);

        // Add connected routes.
        if iface.state.active {
            for addr in &iface.system.addr_list {
                connected_route_add(&mut instance, iface, addr);
            }
        }
    }
}

pub(crate) fn process_addr_add<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, iface)) =
        instance.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Add address.
    if !iface.system.addr_list.insert(addr) {
        return;
    }

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Check if RIP needs to be activated on this interface.
        iface.update(&mut instance);

        // Add connected route.
        connected_route_add(&mut instance, iface, &addr);
    }
}

pub(crate) fn process_addr_del<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, iface)) =
        instance.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Remove address.
    if !iface.system.addr_list.remove(&addr) {
        return;
    }

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Invalidate connected route.
        connected_route_invalidate(&mut instance, iface, &addr);

        // Check if RIP needs to be deactivated on this interface.
        iface.update(&mut instance);
    }
}

// ===== helper functions =====

fn connected_route_add<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &Interface<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    // Uninstall previously learned route (if any).
    let prefix = addr.apply_mask();
    if let Some(route) = instance.state.routes.get(&prefix) {
        ibus::tx::route_uninstall(&instance.tx.ibus, route);
    }

    // Add new connected route.
    let route = Route::new(
        prefix,
        iface.system.ifindex.unwrap(),
        None,
        iface.config.cost,
        0,
        RouteType::Connected,
        &instance.config.trace_opts,
    );
    instance.state.routes.insert(prefix, route);

    // Signal the output process to trigger an update.
    instance.tx.protocol_input.trigger_update();
}

fn connected_route_invalidate<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &Interface<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    let prefix = addr.apply_mask();
    if let Some(route) = instance.state.routes.get_mut(&prefix) {
        route.invalidate(
            iface.config.flush_interval,
            instance.tx,
            &instance.config.trace_opts,
        );
    }
}
