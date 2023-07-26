//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use async_trait::async_trait;
use derive_new::new;
use holo_protocol::MessageReceiver;
use holo_southbound::rx::{SouthboundRx, SouthboundRxCallbacks};
use holo_southbound::zclient::messages::{
    ZapiRtrIdInfo, ZapiRxAddressInfo, ZapiRxIfaceInfo, ZapiRxMsg,
};
use holo_utils::ip::IpNetworkKind;

use crate::area::Area;
use crate::instance::{Instance, InstanceUpView};
use crate::interface::Interface;
use crate::lsdb::LsaOriginateEvent;
use crate::version::Version;

#[derive(Debug, new)]
pub struct InstanceSouthboundRx(pub SouthboundRx);

// OSPF version-specific code.
pub trait SouthboundRxVersion<V: Version> {
    fn process_ifindex_update(
        iface: &mut Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    );

    fn process_addr_add(
        iface: &mut Interface<V>,
        addr: V::NetIpNetwork,
        unnumbered: bool,
    );

    fn process_addr_del(iface: &mut Interface<V>, addr: V::NetIpNetwork);
}

// ===== impl Instance =====

#[async_trait]
impl<V> SouthboundRxCallbacks for Instance<V>
where
    V: Version,
{
    async fn process_rtr_id_upd(&mut self, msg: ZapiRtrIdInfo) {
        self.system.router_id = msg.router_id;
        self.update();
    }

    async fn process_iface_upd(&mut self, msg: ZapiRxIfaceInfo) {
        let (instance, arenas) = match self.as_up() {
            Some(value) => value,
            None => return,
        };

        if let Some((area, iface_idx)) =
            arenas.areas.iter_mut().find_map(|area| {
                area.interfaces
                    .get_by_name(&arenas.interfaces, &msg.ifname)
                    .map(|(iface_idx, _iface)| (area, iface_idx))
            })
        {
            let iface = &mut arenas.interfaces[iface_idx];
            iface.system.mtu = Some(msg.mtu as u16);
            iface.system.operative = msg.operative;
            iface.system.loopback = msg.loopback;
            if iface.system.ifindex != msg.ifindex {
                area.interfaces
                    .update_ifindex(iface_idx, iface, msg.ifindex);

                // OSPF version-specific ifindex update handling.
                V::process_ifindex_update(iface, area, &instance);

                // (Re)originate LSAs that might have been affected.
                instance.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::InterfaceIdChange {
                        area_id: area.id,
                        iface_id: iface.id,
                    },
                );
            }
            iface.update(
                area,
                &instance,
                &mut arenas.neighbors,
                &arenas.lsa_entries,
            );
        }
    }

    async fn process_addr_add(&mut self, msg: ZapiRxAddressInfo) {
        let (instance, arenas) = match self.as_up() {
            Some(value) => value,
            None => return,
        };

        // Get address value.
        let addr = match V::IpNetwork::get(msg.addr) {
            Some(addr) => addr,
            None => return,
        };

        // Lookup interface.
        let (iface_idx, area) = match arenas.areas.iter().find_map(|area| {
            area.interfaces
                .get_by_ifindex(&arenas.interfaces, msg.ifindex)
                .map(|(iface_idx, _iface)| (iface_idx, area))
        }) {
            Some(value) => value,
            None => return,
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
            V::process_addr_add(iface, addr, msg.unnumbered);
        }

        // Check if OSPF needs to be activated on this interface.
        iface.update(
            area,
            &instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
        );
    }

    async fn process_addr_del(&mut self, msg: ZapiRxAddressInfo) {
        let (instance, arenas) = match self.as_up() {
            Some(value) => value,
            None => return,
        };

        // Get address value.
        let addr = match V::IpNetwork::get(msg.addr) {
            Some(addr) => addr,
            None => return,
        };

        // Lookup interface.
        let (iface_idx, area) = match arenas.areas.iter().find_map(|area| {
            area.interfaces
                .get_by_ifindex(&arenas.interfaces, msg.ifindex)
                .map(|(iface_idx, _iface)| (iface_idx, area))
        }) {
            Some(value) => value,
            None => return,
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
        iface.update(
            area,
            &instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
        );
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
