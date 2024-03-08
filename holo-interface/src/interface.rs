//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use generational_arena::{Arena, Index};
use holo_utils::ibus::IbusSender;
use holo_utils::ip::Ipv4NetworkExt;
use holo_utils::southbound::{AddressFlags, InterfaceFlags};
use ipnetwork::{IpNetwork, Ipv4Network};

use crate::ibus;

#[derive(Debug, Default)]
pub struct Interfaces {
    // Interface arena.
    arena: Arena<Interface>,
    // Interface binary tree keyed by name (1:1).
    name_tree: BTreeMap<String, Index>,
    // Interface hash table keyed by ifindex (1:1).
    ifindex_tree: HashMap<u32, Index>,
    // Auto-generated Router ID.
    router_id: Option<Ipv4Addr>,
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
    // Adds or updates the interface with the specified attributes.
    pub(crate) fn update(
        &mut self,
        ifname: String,
        ifindex: u32,
        mtu: u32,
        flags: InterfaceFlags,
        ibus_tx: Option<&IbusSender>,
    ) {
        match self.ifindex_tree.get(&ifindex).copied() {
            Some(iface_idx) => {
                let iface = &mut self.arena[iface_idx];

                // If nothing of interest has changed, return early.
                if iface.name == ifname
                    && iface.mtu == mtu
                    && iface.flags == flags
                {
                    return;
                }

                // Update the existing interface with the new information.
                if iface.name != ifname {
                    self.name_tree.remove(&iface.name);
                    iface.name.clone_from(&ifname);
                    self.name_tree.insert(ifname.clone(), iface_idx);
                }
                iface.mtu = mtu;
                iface.flags = flags;
            }
            None => {
                // If the interface does not exist, create a new entry.
                let iface = Interface {
                    name: ifname.clone(),
                    ifindex,
                    mtu,
                    flags,
                    addresses: Default::default(),
                };

                let iface_idx = self.arena.insert(iface);
                self.name_tree.insert(ifname.clone(), iface_idx);
                self.ifindex_tree.insert(ifindex, iface_idx);
            }
        }

        // Notify protocol instances about the interface update.
        if let Some(ibus_tx) = ibus_tx {
            ibus::notify_interface_update(ibus_tx, ifname, ifindex, mtu, flags);
        }
    }

    // Removes the specified interface identified by its ifindex.
    pub(crate) fn remove(
        &mut self,
        ifindex: u32,
        ibus_tx: Option<&IbusSender>,
    ) {
        let Some(iface_idx) = self.ifindex_tree.get(&ifindex).copied() else {
            return;
        };

        // Notify protocol instances.
        let iface = &self.arena[iface_idx];
        if let Some(ibus_tx) = ibus_tx {
            ibus::notify_interface_del(ibus_tx, iface.name.clone());
        }

        // Remove interface.
        self.name_tree.remove(&iface.name);
        self.ifindex_tree.remove(&iface.ifindex);
        self.arena.remove(iface_idx);

        // Check if the Router ID needs to be updated.
        self.update_router_id(ibus_tx);
    }

    // Adds the specified address to the interface identified by its ifindex.
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
        let Some(iface) = self.get_mut_by_ifindex(ifindex) else {
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

    // Removes the specified address from the interface identified by its ifindex.
    pub(crate) fn addr_del(
        &mut self,
        ifindex: u32,
        addr: IpNetwork,
        ibus_tx: Option<&IbusSender>,
    ) {
        // Lookup interface.
        let Some(iface) = self.get_mut_by_ifindex(ifindex) else {
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

    // Returns the auto-generated Router ID.
    pub(crate) fn router_id(&self) -> Option<Ipv4Addr> {
        self.router_id
    }

    // Updates the auto-generated Router ID.
    fn update_router_id(&mut self, ibus_tx: Option<&IbusSender>) {
        let loopback_interfaces = self
            .iter()
            .filter(|iface| iface.flags.contains(InterfaceFlags::LOOPBACK));
        let non_loopback_interfaces = self
            .iter()
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

    // Returns a reference to the interface corresponding to the given name.
    pub(crate) fn get_by_name(&self, ifname: &str) -> Option<&Interface> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
    }

    // Returns a mutable reference to the interface corresponding to the given
    // name.
    #[allow(dead_code)]
    pub(crate) fn get_mut_by_name(
        &mut self,
        ifname: &str,
    ) -> Option<&mut Interface> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(move |iface_idx| &mut self.arena[iface_idx])
    }

    // Returns a reference to the interface corresponding to the given ifindex.
    #[allow(dead_code)]
    pub(crate) fn get_by_ifindex(&self, ifindex: u32) -> Option<&Interface> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    pub(crate) fn get_mut_by_ifindex(
        &mut self,
        ifindex: u32,
    ) -> Option<&mut Interface> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(move |iface_idx| &mut self.arena[iface_idx])
    }

    // Returns an iterator visiting all interfaces.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Interface> + '_ {
        self.name_tree
            .values()
            .map(|iface_idx| &self.arena[*iface_idx])
    }
}
