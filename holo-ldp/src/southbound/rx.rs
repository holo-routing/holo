//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use async_trait::async_trait;
use derive_new::new;
use holo_protocol::MessageReceiver;
use holo_southbound::rx::{SouthboundRx, SouthboundRxCallbacks};
use holo_southbound::zclient;
use holo_southbound::zclient::messages::{
    ZapiRtrIdInfo, ZapiRxAddressInfo, ZapiRxIfaceInfo, ZapiRxMsg,
    ZapiRxRouteInfo,
};
use holo_utils::mpls::Label;
use ipnetwork::IpNetwork;
use maplit::btreeset;

use crate::debug::Debug;
use crate::events;
use crate::fec::{Fec, FecOwner};
use crate::instance::{Instance, InstanceUp};
use crate::interface::Interface;
use crate::northbound::notification;
use crate::packet::AddressMessageType;

#[derive(Debug, new)]
pub struct InstanceSouthboundRx(pub SouthboundRx);

// ===== impl Instance =====

#[async_trait]
impl SouthboundRxCallbacks for Instance {
    async fn process_rtr_id_upd(&mut self, msg: ZapiRtrIdInfo) {
        self.core_mut().system.router_id = msg.router_id;
        self.update().await;
    }

    async fn process_iface_upd(&mut self, msg: ZapiRxIfaceInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        if let Some((iface_idx, iface)) = instance
            .core
            .interfaces
            .update_ifindex(&msg.ifname, msg.ifindex)
        {
            iface.system.operative = msg.operative;
            Interface::update(instance, iface_idx);
        }
    }

    async fn process_addr_add(&mut self, msg: ZapiRxAddressInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        // Add address to global list.
        match msg.addr {
            IpNetwork::V4(addr) => {
                if instance.core.system.ipv4_addr_list.insert(addr) {
                    // Inform neighbors about new address.
                    for nbr in instance
                        .state
                        .neighbors
                        .iter_mut()
                        .filter(|nbr| nbr.is_operational())
                    {
                        nbr.send_address(
                            &instance.state.msg_id,
                            AddressMessageType::Address,
                            btreeset![addr.ip()],
                        )
                    }
                }
            }
            IpNetwork::V6(addr) => {
                instance.core.system.ipv6_addr_list.insert(addr);
            }
        }

        if let Some((iface_idx, iface)) =
            instance.core.interfaces.get_mut_by_ifindex(msg.ifindex)
        {
            match msg.addr {
                IpNetwork::V4(addr) => {
                    if iface.system.ipv4_addr_list.insert(addr) {
                        // Check if LDP needs to be activated on this
                        // interface.
                        Interface::update(instance, iface_idx);
                    }
                }
                IpNetwork::V6(addr) => {
                    iface.system.ipv6_addr_list.insert(addr);
                }
            }
        }
    }

    async fn process_addr_del(&mut self, msg: ZapiRxAddressInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        // Remove address from global list.
        match msg.addr {
            IpNetwork::V4(addr) => {
                if instance.core.system.ipv4_addr_list.remove(&addr) {
                    // Inform neighbors about deleted address.
                    for nbr in instance
                        .state
                        .neighbors
                        .iter_mut()
                        .filter(|nbr| nbr.is_operational())
                    {
                        nbr.send_address(
                            &instance.state.msg_id,
                            AddressMessageType::AddressWithdraw,
                            btreeset![addr.ip()],
                        )
                    }
                }
            }
            IpNetwork::V6(addr) => {
                instance.core.system.ipv6_addr_list.remove(&addr);
            }
        }

        if let Some((iface_idx, iface)) =
            instance.core.interfaces.get_mut_by_ifindex(msg.ifindex)
        {
            match msg.addr {
                IpNetwork::V4(addr) => {
                    if iface.system.ipv4_addr_list.remove(&addr) {
                        // Check if LDP needs to be disabled on this
                        // interface.
                        Interface::update(instance, iface_idx);
                    }
                }
                IpNetwork::V6(addr) => {
                    iface.system.ipv6_addr_list.remove(&addr);
                }
            }
        }
    }

    async fn process_route_add(&mut self, msg: ZapiRxRouteInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        // Find or create new FEC.
        let prefix = msg.prefix;
        let fec = instance
            .state
            .fecs
            .entry(prefix)
            .or_insert_with(|| Fec::new(prefix));
        let old_fec_status = fec.is_operational();
        fec.inner.owner = Some(FecOwner {
            proto: msg.proto,
            instance: msg.instance,
        });

        // Find the nexthops that were deleted.
        for nexthop_addr in fec.nexthops.keys().copied().collect::<Vec<_>>() {
            if !msg.nexthops.iter().any(|zapi_nexthop| {
                if let Some(zapi_nexthop_addr) = zapi_nexthop.addr {
                    zapi_nexthop_addr == nexthop_addr
                } else {
                    false
                }
            }) {
                let nexthop = &fec.nexthops[&nexthop_addr];
                instance.tx.sb.label_uninstall(&fec.inner, nexthop);
                fec.nexthops.remove(&nexthop_addr);
            }
        }

        if old_fec_status != fec.is_operational() {
            notification::mpls_ldp_fec_event(
                &instance.tx.nb,
                &instance.core.name,
                fec,
            );
        }

        // Find newly added nexthops.
        for zapi_nexthop in &msg.nexthops {
            let zapi_nexthop_addr = match zapi_nexthop.addr {
                Some(addr) => addr,
                // Ignore nexthops that don't contain an IP address.
                None => continue,
            };

            if fec.nexthops.get(&zapi_nexthop_addr).is_none() {
                fec.nexthop_add(zapi_nexthop_addr, zapi_nexthop.ifindex);
            }
        }

        // Allocate new label if necessary.
        local_label_update(fec, &mut instance.state.next_fec_label);
        process_new_fec(instance, prefix);
    }

    async fn process_route_del(&mut self, msg: ZapiRxRouteInfo) {
        let instance = match self {
            Instance::Up(instance) => instance,
            _ => return,
        };

        let prefix = msg.prefix;
        if let Some(fec) = instance.state.fecs.get_mut(&prefix) {
            let old_fec_status = fec.is_operational();

            // Withdraw previously allocated label.
            let msg_id = &instance.state.msg_id;
            for nbr in instance
                .state
                .neighbors
                .iter_mut()
                .filter(|nbr| nbr.is_operational())
            {
                nbr.send_label_withdraw(msg_id, fec);
            }

            // Uninstall learned labels.
            for nexthop in fec.nexthops.values() {
                instance.tx.sb.label_uninstall(&fec.inner, nexthop);
            }

            // TODO deallocate local label.

            // Delete nexthops.
            fec.nexthops.clear();

            if old_fec_status != fec.is_operational() {
                notification::mpls_ldp_fec_event(
                    &instance.tx.nb,
                    &instance.core.name,
                    fec,
                );
            }
        }
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

fn local_label_update(fec: &mut Fec, next_fec_label: &mut u32) {
    if fec.inner.local_label.is_some() {
        return;
    }

    let owner = fec.inner.owner.as_ref().unwrap();
    let label = if owner.proto == zclient::ffi::RouteType::Connect {
        Label::IMPLICIT_NULL
    } else {
        // TODO: request labels to a label manager.
        let label = *next_fec_label;
        *next_fec_label += 1;
        label
    };
    let label = Some(Label::new(label));

    Debug::FecLabelUpdate(fec, &label).log();
    fec.inner.local_label = label;
}

fn process_new_fec(instance: &mut InstanceUp, prefix: IpNetwork) {
    let fec = instance.state.fecs.get_mut(&prefix).unwrap();

    // FEC.1: perform lsr label distribution procedure.
    let msg_id = &instance.state.msg_id;
    for nbr in instance
        .state
        .neighbors
        .iter_mut()
        .filter(|nbr| nbr.is_operational())
    {
        nbr.send_label_mapping(msg_id, fec);
    }

    for nexthop_addr in fec.nexthops.keys().copied().collect::<Vec<_>>() {
        if let Some((nbr_idx, nbr)) =
            instance.state.neighbors.get_by_adv_addr(&nexthop_addr)
        {
            // FEC.2.
            if let Some(mapping) = nbr.rcvd_mappings.get(&prefix).copied() {
                // FEC.5.
                let fec_elem = prefix.into();
                events::process_nbr_msg_label_mapping(
                    instance,
                    nbr_idx,
                    mapping.label,
                    fec_elem,
                );
            }
        }
    }
}
