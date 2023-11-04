//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{btree_map, BTreeMap};
use std::net::{IpAddr, Ipv4Addr};

use holo_utils::ibus::IbusSender;
use holo_utils::ip::Ipv4NetworkExt;
use holo_utils::southbound::{AddressFlags, InterfaceFlags};
use ipnetwork::{IpNetwork, Ipv4Network};

use crate::ibus;

#[derive(Debug, Default)]
pub struct Interfaces {
    // List of interfaces.
    pub tree: BTreeMap<String, Interface>,
    // Auto-generated Router ID.
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub ifindex: u32,
    pub mtu: u32,
    pub flags: InterfaceFlags,
    pub addresses: BTreeMap<IpNetwork, InterfaceAddress>,
}

#[derive(Debug)]
pub struct InterfaceAddress {
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

// ===== impl Interfaces =====

impl Interfaces {
    pub(crate) fn update(
        &mut self,
        ifname: String,
        ifindex: u32,
        mtu: u32,
        flags: InterfaceFlags,
        ibus_tx: Option<&IbusSender>,
    ) {
        match self.tree.entry(ifname.clone()) {
            btree_map::Entry::Vacant(v) => {
                // If the interface does not exist, create a new entry.
                v.insert(Interface {
                    name: ifname.clone(),
                    ifindex,
                    mtu,
                    flags,
                    addresses: Default::default(),
                });
            }
            btree_map::Entry::Occupied(o) => {
                let iface = o.into_mut();

                // If nothing of interest has changed, return early.
                if iface.ifindex == ifindex
                    && iface.mtu == mtu
                    && iface.flags == flags
                {
                    return;
                }

                // Update the existing interface with the new information.
                iface.ifindex = ifindex;
                iface.mtu = mtu;
                iface.flags = flags;
            }
        }

        // Notify protocol instances about the interface update.
        if let Some(ibus_tx) = ibus_tx {
            ibus::notify_interface_update(ibus_tx, ifname, ifindex, mtu, flags);
        }
    }

    pub(crate) fn remove(
        &mut self,
        ifname: String,
        ibus_tx: Option<&IbusSender>,
    ) {
        // Remove interface.
        if self.tree.remove(&ifname).is_none() {
            return;
        }

        // Notify protocol instances.
        if let Some(ibus_tx) = ibus_tx {
            ibus::notify_interface_del(ibus_tx, ifname);
        }

        // Check if the Router ID needs to be updated.
        self.update_router_id(ibus_tx);
    }

    pub(crate) fn addr_add(
        &mut self,
        ifindex: u32,
        addr: IpNetwork,
        ibus_tx: Option<&IbusSender>,
    ) {
        // Ignore loopback addresses.
        if addr.ip().is_loopback() {
            return;
        }

        // Lookup interface.
        let Some(iface) = self
            .tree
            .values_mut()
            .find(|iface| iface.ifindex == ifindex)
        else {
            return;
        };

        // Add address to the interface.
        let mut flags = AddressFlags::empty();
        if !iface.flags.contains(InterfaceFlags::LOOPBACK)
            && addr.is_ipv4()
            && addr.prefix() == Ipv4Network::MAX_PREFIXLEN
        {
            flags.insert(AddressFlags::UNNUMBERED);
        }
        let iface_addr = InterfaceAddress { addr, flags };
        iface.addresses.insert(addr, iface_addr);

        // Notify protocol instances.
        if let Some(ibus_tx) = ibus_tx {
            let ifname = iface.name.clone();
            ibus::notify_addr_add(ibus_tx, ifname, addr, flags);
        }

        // Check if the Router ID needs to be updated.
        self.update_router_id(ibus_tx);
    }

    pub(crate) fn addr_del(
        &mut self,
        ifindex: u32,
        addr: IpNetwork,
        ibus_tx: Option<&IbusSender>,
    ) {
        // Lookup interface.
        let Some(iface) = self
            .tree
            .values_mut()
            .find(|iface| iface.ifindex == ifindex)
        else {
            return;
        };

        // Remove address from the interface.
        if let Some(iface_addr) = iface.addresses.remove(&addr) {
            // Notify protocol instances.
            if let Some(ibus_tx) = ibus_tx {
                let ifname = iface.name.clone();
                ibus::notify_addr_del(
                    ibus_tx,
                    ifname,
                    iface_addr.addr,
                    iface_addr.flags,
                );
            }

            // Check if the Router ID needs to be updated.
            self.update_router_id(ibus_tx);
        }
    }

    fn update_router_id(&mut self, ibus_tx: Option<&IbusSender>) {
        let loopback_interfaces = self
            .tree
            .values()
            .filter(|iface| iface.flags.contains(InterfaceFlags::LOOPBACK));
        let non_loopback_interfaces = self
            .tree
            .values()
            .filter(|iface| !iface.flags.contains(InterfaceFlags::LOOPBACK));

        // Helper function to find the highest IPv4 address among a list of
        // interfaces.
        fn highest_ipv4_addr<'a>(
            interfaces: impl Iterator<Item = &'a Interface>,
        ) -> Option<Ipv4Addr> {
            interfaces
                .flat_map(|iface| iface.addresses.values())
                .filter_map(|addr| {
                    if let IpAddr::V4(addr) = addr.addr.ip() {
                        Some(addr)
                    } else {
                        None
                    }
                })
                .filter(|addr| !addr.is_loopback())
                .filter(|addr| !addr.is_link_local())
                .filter(|addr| !addr.is_multicast())
                .filter(|addr| !addr.is_broadcast())
                .max()
        }

        // First, check for the highest IPv4 address on loopback interfaces.
        // If none exist or lack IPv4 addresses, try the non-loopback interfaces.
        let router_id = highest_ipv4_addr(loopback_interfaces)
            .or_else(|| highest_ipv4_addr(non_loopback_interfaces));

        if self.router_id != router_id {
            // Update the Router ID with the new value.
            self.router_id = router_id;

            // Notify the protocol instances about the Router ID update.
            if let Some(ibus_tx) = ibus_tx {
                ibus::notify_router_id_update(ibus_tx, self.router_id);
            }
        }
    }
}
