//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap};

use generational_arena::{Arena, Index};
use holo_utils::southbound::{AddressFlags, InterfaceFlags};
use ipnetwork::IpNetwork;

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub ifindex: u32,
    pub flags: InterfaceFlags,
    pub addresses: BTreeMap<IpNetwork, AddressFlags>,
}

#[derive(Debug, Default)]
pub struct Interfaces {
    // Interface arena.
    arena: Arena<Interface>,
    // Interface binary tree keyed by name.
    name_tree: BTreeMap<String, Index>,
    // Interface hash table keyed by ifindex.
    ifindex_tree: HashMap<u32, Index>,
}

// ===== impl Interface =====

impl Interface {
    pub(crate) fn is_unnumbered(&self) -> bool {
        self.addresses
            .values()
            .any(|flags| flags.contains(AddressFlags::UNNUMBERED))
    }
}

// ===== impl Interfaces =====

impl Interfaces {
    // Adds or updates the interface with the specified attributes.
    pub(crate) fn update(
        &mut self,
        ifname: String,
        ifindex: u32,
        flags: InterfaceFlags,
    ) {
        match self.ifindex_tree.get(&ifindex).copied() {
            Some(iface_idx) => {
                let iface = &mut self.arena[iface_idx];

                // Update the existing interface with the new information.
                if iface.name != ifname {
                    self.name_tree.remove(&iface.name);
                    iface.name.clone_from(&ifname);
                    self.name_tree.insert(ifname.clone(), iface_idx);
                }
                iface.flags = flags;
                iface.ifindex = ifindex;
            }
            None => {
                // If the interface does not exist, create a new entry.
                let iface = Interface {
                    name: ifname.clone(),
                    ifindex,
                    flags,
                    addresses: Default::default(),
                };
                let iface_idx = self.arena.insert(iface);
                self.name_tree.insert(ifname.clone(), iface_idx);
                self.ifindex_tree.insert(ifindex, iface_idx);
            }
        }
    }

    // Removes the specified interface identified by its ifindex.
    pub(crate) fn remove(&mut self, ifname: &str) {
        let Some(iface_idx) = self.name_tree.get(ifname).copied() else {
            return;
        };
        let iface = &mut self.arena[iface_idx];

        // Remove interface.
        self.name_tree.remove(&iface.name);
        self.ifindex_tree.remove(&iface.ifindex);
        self.arena.remove(iface_idx);
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
    pub(crate) fn get_by_ifindex(&self, ifindex: u32) -> Option<&Interface> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    #[expect(unused)]
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

    // Returns an iterator visiting all interfaces with mutable references.
    //
    // Order of iteration is not defined.
    #[expect(unused)]
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Interface> + '_ {
        self.arena.iter_mut().map(|(_, iface)| iface)
    }
}
