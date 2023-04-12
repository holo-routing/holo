//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use async_trait::async_trait;
use derive_new::new;
use holo_protocol::{InstanceChannelsTx, MessageReceiver};
use holo_southbound::rx::{SouthboundRx, SouthboundRxCallbacks};
use holo_southbound::zclient::messages::{
    ZapiRxAddressInfo, ZapiRxIfaceInfo, ZapiRxMsg,
};
use holo_utils::ip::IpNetworkKind;

use crate::instance::{Instance, InstanceState};
use crate::interface::{Interface, InterfaceUp};
use crate::route::{Route, RouteType};
use crate::version::Version;

#[derive(Debug, new)]
pub struct InstanceSouthboundRx(pub SouthboundRx);

// ===== impl Instance =====

#[async_trait]
impl<V> SouthboundRxCallbacks for Instance<V>
where
    V: Version,
{
    async fn process_iface_upd(&mut self, msg: ZapiRxIfaceInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        if let Some((_, iface)) = instance
            .core
            .interfaces
            .update_ifindex(&msg.ifname, msg.ifindex)
        {
            iface.core_mut().system.mtu = Some(msg.mtu);
            iface.core_mut().system.operative = msg.operative;
            iface.core_mut().system.loopback = msg.loopback;
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

    async fn process_addr_add(&mut self, msg: ZapiRxAddressInfo) {
        let addr = match V::IpNetwork::get(msg.addr) {
            Some(addr) => addr,
            None => return,
        };
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };
        let iface =
            match instance.core.interfaces.get_mut_by_ifindex(msg.ifindex) {
                Some((_, iface)) => iface,
                None => return,
            };

        // Add address.
        if !iface.core_mut().system.addr_list.insert(addr) {
            return;
        }

        // Check if RIP needs to be activated on this interface.
        iface.update(&mut instance.state, &instance.tx);

        // Add connected route.
        if let Interface::Up(iface) = iface {
            connected_route_add(
                &mut instance.state,
                &instance.tx,
                iface,
                &addr,
            );
        }
    }

    async fn process_addr_del(&mut self, msg: ZapiRxAddressInfo) {
        let addr = match V::IpNetwork::get(msg.addr) {
            Some(addr) => addr,
            None => return,
        };
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };
        let iface =
            match instance.core.interfaces.get_mut_by_ifindex(msg.ifindex) {
                Some((_, iface)) => iface,
                None => return,
            };

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
}

// ===== impl InstanceSouthboundRx =====

#[async_trait]
impl MessageReceiver<ZapiRxMsg> for InstanceSouthboundRx {
    async fn recv(&mut self) -> Option<ZapiRxMsg> {
        self.0.recv().await
    }
}

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
        instance_tx.sb.route_uninstall(route);
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
