//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{btree_map, hash_map, BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use generational_arena::{Arena, Index};

use crate::discovery::{Adjacency, AdjacencySource, TargetedNbr};
use crate::error::Error;
use crate::instance::InstanceUp;
use crate::interface::Interface;
use crate::neighbor::{self, Neighbor};
use crate::packet::StatusCode;

pub type InterfaceId = usize;
pub type InterfaceIndex = Index;
pub type AdjacencyId = usize;
pub type AdjacencyIndex = Index;
pub type TargetedNbrIndex = Index;
pub type NeighborId = usize;
pub type NeighborIndex = Index;

#[derive(Debug, Default)]
pub struct Interfaces {
    // Interface arena.
    arena: Arena<Interface>,
    // Interface hash table keyed by ID (1:1).
    id_tree: HashMap<InterfaceId, InterfaceIndex>,
    // Interface binary tree keyed by name (1:1).
    name_tree: BTreeMap<String, InterfaceIndex>,
    // Interface hash table keyed by ifindex (1:1).
    ifindex_tree: HashMap<u32, InterfaceIndex>,
    // Next available ID.
    next_id: InterfaceId,
}

#[derive(Debug, Default)]
pub struct Adjacencies {
    // Adjacency arena.
    arena: Arena<Adjacency>,
    // Adjacency hash table keyed by ID (1:1).
    id_tree: HashMap<AdjacencyId, AdjacencyIndex>,
    // Adjacency binary tree keyed by source (1:1).
    source_tree: BTreeMap<AdjacencySource, AdjacencyIndex>,
    // Adjacency binary tree keyed by LSR-ID (1:N).
    lsr_id_tree: BTreeMap<Ipv4Addr, BTreeMap<AdjacencySource, AdjacencyIndex>>,
    // Adjacency hash table keyed by interface index (1:N).
    iface_tree: HashMap<InterfaceId, BTreeMap<AdjacencySource, AdjacencyIndex>>,
    // Next available ID.
    next_id: AdjacencyId,
}

#[derive(Debug, Default)]
pub struct TargetedNbrs {
    // Targeted neighbor arena.
    arena: Arena<TargetedNbr>,
    // Targeted neighbor binary tree keyed by address (1:1).
    addr_tree: BTreeMap<IpAddr, TargetedNbrIndex>,
}

#[derive(Debug, Default)]
pub struct Neighbors {
    // Neighbor arena.
    arena: Arena<Neighbor>,
    // Neighbor hash table keyed by ID (1:1).
    id_tree: HashMap<NeighborId, NeighborIndex>,
    // Neighbor binary tree keyed by LSR-ID (1:1).
    lsr_id_tree: BTreeMap<Ipv4Addr, NeighborIndex>,
    // Neighbor binary tree keyed by remote transport address (1:1).
    addr_tree: BTreeMap<IpAddr, NeighborIndex>,
    // Next available ID.
    next_id: NeighborId,
}

// ===== impl Interfaces =====

impl Interfaces {
    pub(crate) fn insert(
        &mut self,
        ifname: &str,
    ) -> (InterfaceIndex, &mut Interface) {
        // Check for existing entry first.
        if let Some(iface_idx) = self.name_tree.get(ifname).copied() {
            let iface = &mut self.arena[iface_idx];
            return (iface_idx, iface);
        }

        // Create and insert interface into the arena.
        let id = self.next_id();
        let iface = Interface::new(id, ifname.to_owned());
        let iface_idx = self.arena.insert(iface);

        // Link interface to different collections.
        let iface = &mut self.arena[iface_idx];
        self.id_tree.insert(iface.id, iface_idx);
        self.name_tree.insert(iface.name.clone(), iface_idx);

        (iface_idx, iface)
    }

    pub(crate) fn delete(&mut self, iface_idx: InterfaceIndex) {
        let iface = &mut self.arena[iface_idx];

        // Unlink interface from different collections.
        self.id_tree.remove(&iface.id);
        self.name_tree.remove(&iface.name);
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }

        // Remove interface from the arena.
        self.arena.remove(iface_idx);
    }

    pub(crate) fn update_ifindex(
        &mut self,
        ifname: &str,
        ifindex: Option<u32>,
    ) -> Option<(InterfaceIndex, &mut Interface)> {
        let iface_idx = match self.name_tree.get(ifname).copied() {
            Some(iface_idx) => iface_idx,
            None => return None,
        };
        let iface = &mut self.arena[iface_idx];

        // Update interface ifindex.
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        iface.system.ifindex = ifindex;
        if let Some(ifindex) = ifindex {
            self.ifindex_tree.insert(ifindex, iface_idx);
        }

        Some((iface_idx, iface))
    }

    // Returns a reference to the interface corresponding to the given ID.
    pub(crate) fn get_by_id(
        &self,
        id: InterfaceId,
    ) -> Result<(InterfaceIndex, &Interface), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|iface_idx| (iface_idx, &self.arena[iface_idx]))
            .ok_or_else(|| Error::InterfaceIdNotFound(id))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ID.
    #[allow(dead_code)]
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: InterfaceId,
    ) -> Result<(InterfaceIndex, &mut Interface), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut self.arena[iface_idx]))
            .ok_or_else(|| Error::InterfaceIdNotFound(id))
    }

    // Returns a reference to the interface corresponding to the given name.
    #[allow(dead_code)]
    pub(crate) fn get_by_name(
        &self,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &Interface)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(|iface_idx| (iface_idx, &self.arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // name.
    pub(crate) fn get_mut_by_name(
        &mut self,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &mut Interface)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut self.arena[iface_idx]))
    }

    // Returns a reference to the interface corresponding to the given ifindex.
    #[allow(dead_code)]
    pub(crate) fn get_by_ifindex(
        &self,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &Interface)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| (iface_idx, &self.arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    pub(crate) fn get_mut_by_ifindex(
        &mut self,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &mut Interface)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut self.arena[iface_idx]))
    }

    // Returns a reference to the interface corresponding to the given IP
    // address.
    //
    // NOTE: this method scales linearly with the number of interfaces and is
    // intended to be removed in the future.
    pub(crate) fn get_by_addr(
        &self,
        addr: &IpAddr,
    ) -> Option<(InterfaceIndex, &Interface)> {
        for (iface_idx, iface) in self.arena.iter() {
            if iface.system.contains_addr(addr) {
                return Some((iface_idx, iface));
            }
        }

        None
    }

    // Returns a mutable reference to the interface corresponding to the given
    // IP address.
    //
    // NOTE: this method scales linearly with the number of interfaces and is
    // intended to be removed in the future.
    #[allow(dead_code)]
    pub(crate) fn get_mut_by_addr(
        &mut self,
        addr: &IpAddr,
    ) -> Option<(InterfaceIndex, &mut Interface)> {
        for (iface_idx, iface) in self.arena.iter_mut() {
            if iface.system.contains_addr(addr) {
                return Some((iface_idx, iface));
            }
        }

        None
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
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Interface> + '_ {
        self.arena.iter_mut().map(|(_, iface)| iface)
    }

    // Returns an iterator over all interface indexes.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = InterfaceIndex> + '_ {
        self.name_tree.values().cloned()
    }

    // Get next interface ID.
    pub(crate) fn next_id(&mut self) -> InterfaceId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl std::ops::Index<InterfaceIndex> for Interfaces {
    type Output = Interface;

    fn index(&self, index: InterfaceIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl std::ops::IndexMut<InterfaceIndex> for Interfaces {
    fn index_mut(&mut self, index: InterfaceIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}

// ===== impl Adjacencies =====

impl Adjacencies {
    pub(crate) fn insert(
        &mut self,
        adj: Adjacency,
    ) -> (AdjacencyIndex, &mut Adjacency) {
        // Insert adjacency into the arena.
        let adj_idx = self.arena.insert(adj);

        // Link adjacency to different collections.
        let adj = &mut self.arena[adj_idx];
        self.id_tree.insert(adj.id, adj_idx);
        self.source_tree.insert(adj.source, adj_idx);
        self.lsr_id_tree
            .entry(adj.lsr_id)
            .or_default()
            .insert(adj.source, adj_idx);
        if let Some(iface_id) = adj.source.iface_id {
            self.iface_tree
                .entry(iface_id)
                .or_default()
                .insert(adj.source, adj_idx);
        }

        // Return a mutable reference to the moved adjacency.
        (adj_idx, adj)
    }

    pub(crate) fn delete(&mut self, adj_idx: AdjacencyIndex) {
        let adj = &mut self.arena[adj_idx];

        // Unlink adjacency from different collections.
        self.id_tree.remove(&adj.id);
        self.source_tree.remove(&adj.source);
        if let btree_map::Entry::Occupied(mut o) =
            self.lsr_id_tree.entry(adj.lsr_id)
        {
            let tree = o.get_mut();
            tree.remove(&adj.source);
            if tree.is_empty() {
                o.remove_entry();
            }
        }
        if let Some(iface_id) = adj.source.iface_id {
            if let hash_map::Entry::Occupied(mut o) =
                self.iface_tree.entry(iface_id)
            {
                let tree = o.get_mut();
                tree.remove(&adj.source);
                if tree.is_empty() {
                    o.remove_entry();
                }
            }
        }

        // Remove interface from the arena.
        self.arena.remove(adj_idx);
    }

    // Returns a reference to the adjacency corresponding to the given ID.
    pub(crate) fn get_by_id(
        &self,
        id: AdjacencyId,
    ) -> Result<(AdjacencyIndex, &Adjacency), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|adj_idx| (adj_idx, &self.arena[adj_idx]))
            .ok_or_else(|| Error::AdjacencyIdNotFound(id))
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // ID.
    #[allow(dead_code)]
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: AdjacencyId,
    ) -> Result<(AdjacencyIndex, &mut Adjacency), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |adj_idx| (adj_idx, &mut self.arena[adj_idx]))
            .ok_or_else(|| Error::AdjacencyIdNotFound(id))
    }

    // Returns a reference to the adjacency corresponding to the given source.
    pub(crate) fn get_by_source(
        &self,
        source: &AdjacencySource,
    ) -> Option<(AdjacencyIndex, &Adjacency)> {
        self.source_tree
            .get(source)
            .copied()
            .map(|adj_idx| (adj_idx, &self.arena[adj_idx]))
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // source.
    pub(crate) fn get_mut_by_source(
        &mut self,
        source: &AdjacencySource,
    ) -> Option<(AdjacencyIndex, &mut Adjacency)> {
        self.source_tree
            .get(source)
            .copied()
            .map(move |adj_idx| (adj_idx, &mut self.arena[adj_idx]))
    }

    // Returns a list of all adjacencies associated to the given LSR-ID.
    pub(crate) fn get_by_lsr_id(
        &self,
        lsr_id: &Ipv4Addr,
    ) -> Option<&BTreeMap<AdjacencySource, AdjacencyIndex>> {
        self.lsr_id_tree.get(lsr_id)
    }

    // Returns a list of all adjacencies associated to the given interface.
    pub(crate) fn get_by_iface(
        &self,
        iface_id: InterfaceId,
    ) -> Option<&BTreeMap<AdjacencySource, AdjacencyIndex>> {
        self.iface_tree.get(&iface_id)
    }

    // Returns an iterator visiting all adjacencies.
    //
    // Adjacencies are ordered by their sources.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Adjacency> + '_ {
        self.source_tree
            .values()
            .map(|adj_idx| &self.arena[*adj_idx])
    }

    // Returns an iterator visiting all adjacencies associated to the specified
    // interface.
    //
    // Adjacencies are ordered by their sources.
    pub(crate) fn iter_by_iface(
        &self,
        iface_id: &InterfaceId,
    ) -> Option<impl Iterator<Item = &'_ Adjacency> + '_> {
        Some(
            self.iface_tree
                .get(iface_id)?
                .iter()
                .map(|(_, adj_idx)| &self.arena[*adj_idx]),
        )
    }

    // Returns an iterator visiting all adjacencies associated to the specified
    // neighbor LSR-ID.
    //
    // Adjacencies are ordered by their sources.
    pub(crate) fn iter_by_lsr_id(
        &self,
        lsr_id: &Ipv4Addr,
    ) -> Option<impl Iterator<Item = &'_ Adjacency> + '_> {
        Some(
            self.lsr_id_tree
                .get(lsr_id)?
                .iter()
                .map(|(_, adj_idx)| &self.arena[*adj_idx]),
        )
    }

    // Returns an iterator over all adjacency indexes.
    //
    // Adjacencies are ordered by their sources.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = AdjacencyIndex> + '_ {
        self.source_tree.values().cloned()
    }

    // Get next adjacency ID.
    pub(crate) fn next_id(&mut self) -> AdjacencyId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl std::ops::Index<AdjacencyIndex> for Adjacencies {
    type Output = Adjacency;

    fn index(&self, index: AdjacencyIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl std::ops::IndexMut<AdjacencyIndex> for Adjacencies {
    fn index_mut(&mut self, index: AdjacencyIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}

// ===== impl TargetedNbrs =====

impl TargetedNbrs {
    pub(crate) fn insert(
        &mut self,
        addr: IpAddr,
    ) -> (TargetedNbrIndex, &mut TargetedNbr) {
        // Check for existing entry first.
        if let Some(tnbr_idx) = self.addr_tree.get(&addr).copied() {
            let tnbr = &mut self.arena[tnbr_idx];
            return (tnbr_idx, tnbr);
        }

        // Create and insert targeted neighbor into the arena.
        let tnbr = TargetedNbr::new(addr);
        let tnbr_idx = self.arena.insert(tnbr);

        // Link targeted neighbor to different collections.
        let tnbr = &mut self.arena[tnbr_idx];
        self.addr_tree.insert(tnbr.addr, tnbr_idx);

        (tnbr_idx, tnbr)
    }

    pub(crate) fn delete(&mut self, tnbr_idx: TargetedNbrIndex) {
        let tnbr = &mut self.arena[tnbr_idx];

        // Unlink targeted neighbor from different collections.
        self.addr_tree.remove(&tnbr.addr);

        // Remove targeted neighbor from the arena.
        self.arena.remove(tnbr_idx);
    }

    // Returns a reference to the targeted neighbor corresponding to the given
    // name.
    pub(crate) fn get_by_addr(
        &self,
        addr: &IpAddr,
    ) -> Option<(TargetedNbrIndex, &TargetedNbr)> {
        self.addr_tree
            .get(addr)
            .copied()
            .map(|tnbr_idx| (tnbr_idx, &self.arena[tnbr_idx]))
    }

    // Returns a mutable reference to the targeted neighbor corresponding to the
    // given name.
    pub(crate) fn get_mut_by_addr(
        &mut self,
        addr: &IpAddr,
    ) -> Option<(TargetedNbrIndex, &mut TargetedNbr)> {
        self.addr_tree
            .get(addr)
            .copied()
            .map(move |tnbr_idx| (tnbr_idx, &mut self.arena[tnbr_idx]))
    }

    // Returns an iterator visiting all targeted neighbors.
    //
    // Targeted neighbors are ordered by their addresses.
    #[allow(dead_code)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ TargetedNbr> + '_ {
        self.addr_tree
            .values()
            .map(|tnbr_idx| &self.arena[*tnbr_idx])
    }

    // Returns an iterator visiting all targeted neighbors with mutable
    // references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut TargetedNbr> + '_ {
        self.arena.iter_mut().map(|(_, tnbr)| tnbr)
    }

    // Returns an iterator over all targeted neighbor indexes.
    //
    // Targeted neighbors are ordered by their addresses.
    pub(crate) fn indexes(
        &self,
    ) -> impl Iterator<Item = TargetedNbrIndex> + '_ {
        self.addr_tree.values().cloned()
    }
}

impl std::ops::Index<TargetedNbrIndex> for TargetedNbrs {
    type Output = TargetedNbr;

    fn index(&self, index: TargetedNbrIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl std::ops::IndexMut<TargetedNbrIndex> for TargetedNbrs {
    fn index_mut(&mut self, index: TargetedNbrIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}

// ===== impl Neighbors =====

impl Neighbors {
    pub(crate) fn insert(
        &mut self,
        nbr: Neighbor,
    ) -> (NeighborIndex, &mut Neighbor) {
        // Insert neighbor into the arena.
        let nbr_idx = self.arena.insert(nbr);

        // Link neighbor to different collections.
        let nbr = &mut self.arena[nbr_idx];
        self.id_tree.insert(nbr.id, nbr_idx);
        self.lsr_id_tree.insert(nbr.lsr_id, nbr_idx);
        self.addr_tree.insert(nbr.trans_addr, nbr_idx);

        // Return a mutable reference to the moved neighbor.
        (nbr_idx, nbr)
    }

    fn delete(&mut self, nbr_idx: NeighborIndex) {
        let nbr = &mut self.arena[nbr_idx];

        // Unlink neighbor from different collections.
        self.id_tree.remove(&nbr.id);
        self.lsr_id_tree.remove(&nbr.lsr_id);
        self.addr_tree.remove(&nbr.trans_addr);

        // Remove neighbor from the arena.
        self.arena.remove(nbr_idx);
    }

    // Delete neighbor if its last adjacency was deleted.
    pub(crate) fn delete_check(
        instance: &mut InstanceUp,
        lsr_id: &Ipv4Addr,
        status_code: StatusCode,
    ) {
        if instance
            .state
            .ipv4
            .adjacencies
            .get_by_lsr_id(lsr_id)
            .is_none()
        {
            let (nbr_idx, nbr) =
                instance.state.neighbors.get_mut_by_lsr_id(lsr_id).unwrap();

            // Send error notification.
            if nbr.is_operational() {
                nbr.send_notification(
                    &instance.state.msg_id,
                    status_code,
                    None,
                    None,
                );
                Neighbor::fsm(
                    instance,
                    nbr_idx,
                    neighbor::fsm::Event::ErrorSent,
                );
            }

            // Unset neighbor password (if any).
            let nbr = &instance.state.neighbors[nbr_idx];
            nbr.set_listener_md5sig(&instance.state.ipv4.session_socket, None);

            // Delete neighbor.
            instance.state.neighbors.delete(nbr_idx);
        }
    }

    pub(crate) fn update_id(&mut self, nbr_idx: NeighborIndex, id: NeighborId) {
        let nbr = &mut self.arena[nbr_idx];

        self.id_tree.remove(&nbr.id);
        nbr.id = id;
        self.id_tree.insert(nbr.id, nbr_idx);
    }

    // Returns a reference to the neighbor corresponding to the given ID.
    #[allow(dead_code)]
    pub(crate) fn get_by_id(
        &self,
        id: NeighborId,
    ) -> Result<(NeighborIndex, &Neighbor), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|nbr_idx| (nbr_idx, &self.arena[nbr_idx]))
            .ok_or_else(|| Error::NeighborIdNotFound(id))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: NeighborId,
    ) -> Result<(NeighborIndex, &mut Neighbor), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut self.arena[nbr_idx]))
            .ok_or_else(|| Error::NeighborIdNotFound(id))
    }

    // Returns a reference to the neighbor corresponding to the given LSR-ID.
    pub(crate) fn get_by_lsr_id(
        &self,
        lsr_id: &Ipv4Addr,
    ) -> Option<(NeighborIndex, &Neighbor)> {
        self.lsr_id_tree
            .get(lsr_id)
            .copied()
            .map(|nbr_idx| (nbr_idx, &self.arena[nbr_idx]))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // LSR-ID.
    pub(crate) fn get_mut_by_lsr_id(
        &mut self,
        lsr_id: &Ipv4Addr,
    ) -> Option<(NeighborIndex, &mut Neighbor)> {
        self.lsr_id_tree
            .get(lsr_id)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut self.arena[nbr_idx]))
    }

    // Returns a reference to the neighbor corresponding to the given transport
    // address.
    #[allow(dead_code)]
    pub(crate) fn get_by_trans_addr(
        &self,
        addr: &IpAddr,
    ) -> Option<(NeighborIndex, &Neighbor)> {
        self.addr_tree
            .get(addr)
            .copied()
            .map(|nbr_idx| (nbr_idx, &self.arena[nbr_idx]))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // transport address.
    pub(crate) fn get_mut_by_trans_addr(
        &mut self,
        addr: &IpAddr,
    ) -> Option<(NeighborIndex, &mut Neighbor)> {
        self.addr_tree
            .get(addr)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut self.arena[nbr_idx]))
    }

    // Returns a reference to the neighbor that advertised the given IP address.
    //
    // TODO: introduce global BTreeSet mapping addresses to neighbors.
    pub(crate) fn get_by_adv_addr(
        &self,
        addr: &IpAddr,
    ) -> Option<(NeighborIndex, &Neighbor)> {
        for (nbr_idx, nbr) in &self.arena {
            if nbr.addr_list.get(addr).is_some() {
                return Some((nbr_idx, nbr));
            }
        }

        None
    }

    // Returns a mutable reference to the neighbor that advertised the given IP
    // address.
    //
    // TODO: introduce global BTreeSet mapping addresses to neighbors.
    #[allow(dead_code)]
    pub(crate) fn get_mut_by_adv_addr(
        &mut self,
        addr: &IpAddr,
    ) -> Option<(NeighborIndex, &Neighbor)> {
        for (nbr_idx, nbr) in &mut self.arena {
            if nbr.addr_list.get(addr).is_some() {
                return Some((nbr_idx, nbr));
            }
        }

        None
    }

    // Returns an iterator visiting all neighbors.
    //
    // Neighbors are ordered by their LSR-IDs.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Neighbor> + '_ {
        self.lsr_id_tree
            .values()
            .map(|nbr_idx| &self.arena[*nbr_idx])
    }

    // Returns an iterator visiting all neighbors with mutable references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Neighbor> + '_ {
        self.arena.iter_mut().map(|(_, nbr)| nbr)
    }

    // Returns an iterator over all neighbor indexes.
    //
    // Neighbors are ordered by their LSR-IDs.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = NeighborIndex> + '_ {
        self.lsr_id_tree.values().cloned()
    }

    // Get next neighbor ID.
    pub(crate) fn next_id(&mut self) -> NeighborId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl std::ops::Index<NeighborIndex> for Neighbors {
    type Output = Neighbor;

    fn index(&self, index: NeighborIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl std::ops::IndexMut<NeighborIndex> for Neighbors {
    fn index_mut(&mut self, index: NeighborIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}
