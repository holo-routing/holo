//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet, HashMap};

use generational_arena::Index;
use holo_utils::mac_addr::MacAddr;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

use crate::adjacency::Adjacency;
use crate::error::Error;
use crate::interface::Interface;
use crate::lsdb::LspEntry;
use crate::packet::pdu::Lsp;
use crate::packet::{LanId, LevelNumber, LevelType, LspId, SystemId};
use crate::tasks::messages::input::LspPurgeMsg;

pub type ObjectId = u32;

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum ObjectKey<T> {
    Id(ObjectId),
    Value(T),
}

pub type InterfaceId = ObjectId;
pub type InterfaceIndex = Index;
pub type InterfaceKey = ObjectKey<String>;
pub type AdjacencyId = ObjectId;
pub type AdjacencyIndex = Index;
pub type AdjacencyKey = ObjectKey<SystemId>;
pub type LspEntryId = ObjectId;
pub type LspEntryIndex = Index;
pub type LspEntryKey = ObjectKey<LspId>;

#[derive(Debug)]
pub struct Arena<T>(generational_arena::Arena<T>);

#[derive(Debug, Default)]
pub struct Interfaces {
    arena: Arena<Interface>,
    id_tree: HashMap<InterfaceId, InterfaceIndex>,
    name_tree: BTreeMap<String, InterfaceIndex>,
    ifindex_tree: HashMap<u32, InterfaceIndex>,
    next_id: InterfaceId,
}

#[derive(Debug, Default)]
pub struct Adjacencies {
    id_tree: HashMap<AdjacencyId, AdjacencyIndex>,
    snpa_tree: BTreeMap<MacAddr, AdjacencyIndex>,
    system_id_tree: BTreeMap<SystemId, AdjacencyIndex>,
    active: BTreeSet<MacAddr>,
    next_id: AdjacencyId,
}

#[derive(Debug, Default)]
pub struct Lsdb {
    id_tree: HashMap<ObjectId, LspEntryIndex>,
    lspid_tree: BTreeMap<LspId, LspEntryIndex>,
    next_id: ObjectId,
}

// ===== impl ObjectKey =====

impl<T> From<ObjectId> for ObjectKey<T> {
    fn from(id: ObjectId) -> ObjectKey<T> {
        ObjectKey::Id(id)
    }
}

// ===== impl Arena =====

impl<T> Default for Arena<T> {
    fn default() -> Arena<T> {
        Arena(Default::default())
    }
}

impl<T> std::ops::Index<Index> for Arena<T> {
    type Output = T;

    fn index(&self, index: Index) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> std::ops::IndexMut<Index> for Arena<T> {
    fn index_mut(&mut self, index: Index) -> &mut Self::Output {
        &mut self.0[index]
    }
}

// ===== impl Interfaces =====

impl Interfaces {
    pub(crate) fn insert(&mut self, ifname: &str) -> &mut Interface {
        // Create and insert interface into the arena.
        self.next_id += 1;
        let iface_idx = self.arena.0.insert_with(|index| {
            Interface::new(index, self.next_id, ifname.to_owned())
        });

        // Link interface to different collections.
        let iface = &mut self.arena[iface_idx];
        self.id_tree.insert(iface.id, iface_idx);
        if self
            .name_tree
            .insert(iface.name.clone(), iface_idx)
            .is_some()
        {
            panic!("interface name={} already exists", iface.name);
        }

        iface
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
        self.arena.0.remove(iface_idx);
    }

    // Update interface ifindex.
    pub(crate) fn update_ifindex(
        &mut self,
        iface_idx: InterfaceIndex,
        ifindex: Option<u32>,
    ) {
        let iface = &mut self.arena[iface_idx];
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        iface.system.ifindex = ifindex;
        if let Some(ifindex) = ifindex {
            self.ifindex_tree.insert(ifindex, iface_idx);
        }
    }

    // Returns a reference to the interface corresponding to the given ID.
    pub(crate) fn get_by_id(
        &self,
        id: InterfaceId,
    ) -> Result<&Interface, Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
            .filter(|iface| iface.id == id)
            .ok_or(Error::InterfaceIdNotFound(id))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: InterfaceId,
    ) -> Result<&mut Interface, Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |iface_idx| &mut self.arena[iface_idx])
            .filter(|iface| iface.id == id)
            .ok_or(Error::InterfaceIdNotFound(id))
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
    #[expect(unused)]
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

    // Returns a reference to the interface corresponding to the given object
    // key.
    #[expect(unused)]
    pub(crate) fn get_by_key(
        &self,
        key: &InterfaceKey,
    ) -> Result<&Interface, Error> {
        match key {
            InterfaceKey::Id(id) => self.get_by_id(*id),
            InterfaceKey::Value(ifname) => {
                Ok(self.get_by_name(ifname).unwrap())
            }
        }
    }

    // Returns a mutable reference to the interface corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key(
        &mut self,
        key: &InterfaceKey,
    ) -> Result<&mut Interface, Error> {
        match key {
            InterfaceKey::Id(id) => self.get_mut_by_id(*id),
            InterfaceKey::Value(ifname) => {
                Ok(self.get_mut_by_name(ifname).unwrap())
            }
        }
    }

    // Returns an iterator visiting all interfaces.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Interface> {
        self.name_tree
            .values()
            .map(|iface_idx| &self.arena[*iface_idx])
    }

    // Returns an iterator visiting all interfaces with mutable references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Interface> {
        self.arena.0.iter_mut().map(|(_, iface)| iface)
    }

    // Returns an iterator over all interface indexes.
    //
    // Interfaces are ordered by their names.
    #[expect(unused)]
    pub(crate) fn indexes(&self) -> impl Iterator<Item = InterfaceIndex> + '_ {
        self.name_tree.values().copied()
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
    pub(crate) fn insert<'a>(
        &mut self,
        arena: &'a mut Arena<Adjacency>,
        snpa: MacAddr,
        system_id: SystemId,
        level_capability: LevelType,
        level_usage: LevelType,
    ) -> (AdjacencyIndex, &'a mut Adjacency) {
        // Create and insert adjacency into the arena.
        self.next_id += 1;
        let adj = Adjacency::new(
            self.next_id,
            snpa,
            system_id,
            level_capability,
            level_usage,
        );
        let adj_idx = arena.0.insert(adj);

        // Link adjacency to different collections.
        let adj = &mut arena[adj_idx];
        self.id_tree.insert(adj.id, adj_idx);
        self.snpa_tree.insert(adj.snpa, adj_idx);
        self.system_id_tree.insert(adj.system_id, adj_idx);

        (adj_idx, adj)
    }

    pub(crate) fn delete(
        &mut self,
        arena: &mut Arena<Adjacency>,
        adj_idx: AdjacencyIndex,
    ) {
        let adj = &mut arena[adj_idx];

        // Unlink adjacency from different collections.
        self.id_tree.remove(&adj.id);
        self.snpa_tree.remove(&adj.snpa);
        self.system_id_tree.remove(&adj.system_id);

        // Remove adjacency from the arena.
        arena.0.remove(adj_idx);
    }

    pub(crate) fn clear(&mut self, arena: &mut Arena<Adjacency>) {
        for adj_idx in self.id_tree.values() {
            arena.0.remove(*adj_idx);
        }
        self.id_tree.clear();
        self.snpa_tree.clear();
        self.system_id_tree.clear();
        self.active.clear();
    }

    pub(crate) fn update_system_id(
        &mut self,
        adj_idx: AdjacencyIndex,
        adj: &mut Adjacency,
        system_id: SystemId,
    ) {
        self.system_id_tree.remove(&adj.system_id);
        adj.system_id = system_id;
        self.system_id_tree.insert(adj.system_id, adj_idx);
    }

    // Returns a reference to the adjacency corresponding to the given ID.
    pub(crate) fn get_by_id<'a>(
        &self,
        arena: &'a Arena<Adjacency>,
        id: AdjacencyId,
    ) -> Result<(AdjacencyIndex, &'a Adjacency), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|adj_idx| (adj_idx, &arena[adj_idx]))
            .filter(|(_, adj)| adj.id == id)
            .ok_or(Error::AdjacencyIdNotFound(id))
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id<'a>(
        &mut self,
        arena: &'a mut Arena<Adjacency>,
        id: AdjacencyId,
    ) -> Result<(AdjacencyIndex, &'a mut Adjacency), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |adj_idx| (adj_idx, &mut arena[adj_idx]))
            .filter(|(_, adj)| adj.id == id)
            .ok_or(Error::AdjacencyIdNotFound(id))
    }

    // Returns a reference to the adjacency corresponding to the given SNPA.
    pub(crate) fn get_by_snpa<'a>(
        &self,
        arena: &'a Arena<Adjacency>,
        snpa: MacAddr,
    ) -> Option<(AdjacencyIndex, &'a Adjacency)> {
        self.snpa_tree
            .get(&snpa)
            .copied()
            .map(|adj_idx| (adj_idx, &arena[adj_idx]))
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // SNPA.
    pub(crate) fn get_mut_by_snpa<'a>(
        &mut self,
        arena: &'a mut Arena<Adjacency>,
        snpa: MacAddr,
    ) -> Option<(AdjacencyIndex, &'a mut Adjacency)> {
        self.snpa_tree
            .get(&snpa)
            .copied()
            .map(move |adj_idx| (adj_idx, &mut arena[adj_idx]))
    }

    // Returns a reference to the adjacency corresponding to the given
    // System-ID.
    pub(crate) fn get_by_system_id<'a>(
        &self,
        arena: &'a Arena<Adjacency>,
        system_id: &SystemId,
    ) -> Option<(AdjacencyIndex, &'a Adjacency)> {
        self.system_id_tree
            .get(system_id)
            .copied()
            .map(|adj_idx| (adj_idx, &arena[adj_idx]))
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // System-ID.
    pub(crate) fn get_mut_by_system_id<'a>(
        &mut self,
        arena: &'a mut Arena<Adjacency>,
        system_id: &SystemId,
    ) -> Option<(AdjacencyIndex, &'a mut Adjacency)> {
        self.system_id_tree
            .get(system_id)
            .copied()
            .map(move |adj_idx| (adj_idx, &mut arena[adj_idx]))
    }

    // Returns a reference to the adjacency corresponding to the given object
    // key.
    #[expect(unused)]
    pub(crate) fn get_by_key<'a>(
        &self,
        arena: &'a Arena<Adjacency>,
        key: &AdjacencyKey,
    ) -> Result<(AdjacencyIndex, &'a Adjacency), Error> {
        match key {
            AdjacencyKey::Id(id) => self.get_by_id(arena, *id),
            AdjacencyKey::Value(system_id) => {
                Ok(self.get_by_system_id(arena, system_id).unwrap())
            }
        }
    }

    // Returns a mutable reference to the adjacency corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key<'a>(
        &mut self,
        arena: &'a mut Arena<Adjacency>,
        key: &AdjacencyKey,
    ) -> Result<(AdjacencyIndex, &'a mut Adjacency), Error> {
        match key {
            AdjacencyKey::Id(id) => self.get_mut_by_id(arena, *id),
            AdjacencyKey::Value(system_id) => {
                Ok(self.get_mut_by_system_id(arena, system_id).unwrap())
            }
        }
    }

    // Returns an iterator visiting all adjacencies.
    //
    // Adjacencies are ordered by their System IDs.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<Adjacency>,
    ) -> impl Iterator<Item = &'a Adjacency> + 'a {
        self.system_id_tree.values().map(|adj_idx| &arena[*adj_idx])
    }

    // Returns a reference to the set of active adjacencies
    // (those in Init or Up state, but not Down).
    pub(crate) fn active(&self) -> &BTreeSet<MacAddr> {
        &self.active
    }

    // Returns a mutable reference to the set of active adjacencies
    // (those in Init or Up state, but not Down).
    pub(crate) fn active_mut(&mut self) -> &mut BTreeSet<MacAddr> {
        &mut self.active
    }

    // Returns an iterator over all adjacency indexes.
    //
    // Adjacencies are ordered by their System-IDs.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = AdjacencyIndex> + '_ {
        self.system_id_tree.values().copied()
    }
}

// ===== impl Lsdb =====

impl Lsdb {
    pub(crate) fn insert<'a>(
        &mut self,
        arena: &'a mut Arena<LspEntry>,
        level: LevelNumber,
        lsp: Lsp,
        lsp_purgep: &UnboundedSender<LspPurgeMsg>,
    ) -> (LspEntryIndex, &'a mut LspEntry) {
        // Create and insert LSP entry into the arena.
        self.next_id += 1;
        let lse = LspEntry::new(level, self.next_id, lsp, lsp_purgep);
        let lse_idx = arena.0.insert(lse);

        // Link LSP entry to different collections.
        let lse = &mut arena[lse_idx];
        self.id_tree.insert(lse.id, lse_idx);
        self.lspid_tree.insert(lse.data.lsp_id, lse_idx);

        (lse_idx, lse)
    }

    pub(crate) fn delete(
        &mut self,
        arena: &mut Arena<LspEntry>,
        lse_idx: LspEntryIndex,
    ) -> LspEntry {
        let lse = &mut arena[lse_idx];

        // Unlink LSP entry from different collections.
        self.id_tree.remove(&lse.id);
        self.lspid_tree.remove(&lse.data.lsp_id);

        // Remove LSP entry from the arena.
        arena.0.remove(lse_idx).unwrap()
    }

    pub(crate) fn clear(&mut self, arena: &mut Arena<LspEntry>) {
        for lse_idx in self.id_tree.values() {
            arena.0.remove(*lse_idx).unwrap();
        }
        self.id_tree.clear();
        self.lspid_tree.clear();
    }

    // Returns a reference to the LSP entry corresponding to the given ID.
    pub(crate) fn get_by_id<'a>(
        &self,
        arena: &'a Arena<LspEntry>,
        id: ObjectId,
    ) -> Result<(LspEntryIndex, &'a LspEntry), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|lse_idx| (lse_idx, &arena[lse_idx]))
            .filter(|(_, lse)| lse.id == id)
            .ok_or(Error::LspEntryIdNotFound(id))
    }

    // Returns a mutable reference to the LSP entry corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id<'a>(
        &mut self,
        arena: &'a mut Arena<LspEntry>,
        id: ObjectId,
    ) -> Result<(LspEntryIndex, &'a mut LspEntry), Error> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |lse_idx| (lse_idx, &mut arena[lse_idx]))
            .filter(|(_, lse)| lse.id == id)
            .ok_or(Error::LspEntryIdNotFound(id))
    }

    // Returns a reference to the LSP entry corresponding to the given LSP ID.
    pub(crate) fn get_by_lspid<'a>(
        &self,
        arena: &'a Arena<LspEntry>,
        lsp_id: &LspId,
    ) -> Option<(LspEntryIndex, &'a LspEntry)> {
        self.lspid_tree
            .get(lsp_id)
            .copied()
            .map(|lse_idx| (lse_idx, &arena[lse_idx]))
    }

    // Returns a mutable reference to the LSP entry corresponding to the given
    // LSP ID.
    pub(crate) fn get_mut_by_lspid<'a>(
        &mut self,
        arena: &'a mut Arena<LspEntry>,
        lsp_id: &LspId,
    ) -> Option<(LspEntryIndex, &'a mut LspEntry)> {
        self.lspid_tree
            .get(lsp_id)
            .copied()
            .map(move |lse_idx| (lse_idx, &mut arena[lse_idx]))
    }

    // Returns a reference to the LSP entry corresponding to the given object
    // key.
    pub(crate) fn get_by_key<'a>(
        &self,
        arena: &'a Arena<LspEntry>,
        key: &LspEntryKey,
    ) -> Result<(LspEntryIndex, &'a LspEntry), Error> {
        match key {
            LspEntryKey::Id(id) => self.get_by_id(arena, *id),
            LspEntryKey::Value(lsp_id) => {
                Ok(self.get_by_lspid(arena, lsp_id).unwrap())
            }
        }
    }

    // Returns a mutable reference to the LSP entry corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key<'a>(
        &mut self,
        arena: &'a mut Arena<LspEntry>,
        key: &LspEntryKey,
    ) -> Result<(LspEntryIndex, &'a mut LspEntry), Error> {
        match key {
            LspEntryKey::Id(id) => self.get_mut_by_id(arena, *id),
            LspEntryKey::Value(lsp_id) => {
                Ok(self.get_mut_by_lspid(arena, lsp_id).unwrap())
            }
        }
    }

    // Returns an iterator visiting all LSP entries.
    //
    // LSP are ordered by their LSP IDs.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<LspEntry>,
    ) -> impl Iterator<Item = &'a LspEntry> + 'a {
        self.lspid_tree.values().map(|lse_idx| &arena[*lse_idx])
    }

    // Returns an iterator visiting all LSP entries for the specified System ID.
    //
    // LSP are ordered by their LSP IDs.
    pub(crate) fn iter_for_system_id<'a>(
        &'a self,
        arena: &'a Arena<LspEntry>,
        system_id: SystemId,
    ) -> impl Iterator<Item = &'a LspEntry> + 'a {
        let start = LspId::from((system_id, 0, 0));
        let end = LspId::from((system_id, 255, 255));
        self.range(arena, start..=end)
    }

    // Returns an iterator visiting all LSP entries for the specified LAN ID.
    //
    // LSP are ordered by their LSP IDs.
    pub(crate) fn iter_for_lan_id<'a>(
        &'a self,
        arena: &'a Arena<LspEntry>,
        lan_id: LanId,
    ) -> impl Iterator<Item = &'a LspEntry> + 'a {
        let start = LspId::from((lan_id, 0));
        let end = LspId::from((lan_id, 255));
        self.range(arena, start..=end)
    }

    // Returns an iterator over a range of LSP IDs.
    //
    // LSP are ordered by their LSP IDs.
    pub(crate) fn range<'a>(
        &'a self,
        arena: &'a Arena<LspEntry>,
        range: impl std::ops::RangeBounds<LspId>,
    ) -> impl Iterator<Item = &'a LspEntry> + 'a {
        self.lspid_tree
            .range(range)
            .map(|(_, lse_idx)| &arena[*lse_idx])
    }

    // Returns an iterator over all LSP indexes.
    //
    // LSPs are ordered by their LSP IDs.
    #[expect(unused)]
    pub(crate) fn indexes(&self) -> impl Iterator<Item = LspEntryIndex> + '_ {
        self.lspid_tree.values().copied()
    }
}
