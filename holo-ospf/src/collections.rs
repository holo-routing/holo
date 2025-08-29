//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use generational_arena::Index;
use holo_utils::task::IntervalTask;
use serde::{Deserialize, Serialize};

use crate::area::Area;
use crate::error::Error;
use crate::instance::ProtocolInputChannelsTx;
use crate::interface::Interface;
use crate::lsdb::{LsaDelayedOrig, LsaEntry};
use crate::neighbor::{Neighbor, NeighborNetId};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::tasks;
use crate::version::Version;

pub type ObjectId = u32;

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum ObjectKey<T> {
    Id(ObjectId),
    Value(T),
}

pub type AreaId = ObjectId;
pub type AreaIndex = Index;
pub type AreaKey = ObjectKey<Ipv4Addr>;
pub type InterfaceId = ObjectId;
pub type InterfaceIndex = Index;
pub type InterfaceKey = ObjectKey<String>;
pub type NeighborId = ObjectId;
pub type NeighborIndex = Index;
pub type NeighborKey = ObjectKey<Ipv4Addr>;
pub type LsaEntryId = ObjectId;
pub type LsaEntryIndex = Index;
pub type LsaEntryKey<T> = ObjectKey<LsaKey<T>>;

#[derive(Debug)]
pub struct Arena<T>(generational_arena::Arena<T>);

#[derive(Debug, Default)]
pub struct Areas<V: Version> {
    arena: Arena<Area<V>>,
    id_tree: HashMap<AreaId, AreaIndex>,
    area_id_tree: BTreeMap<Ipv4Addr, AreaIndex>,
    next_id: AreaId,
}

#[derive(Debug, Default)]
pub struct Interfaces<V: Version> {
    id_tree: HashMap<InterfaceId, InterfaceIndex>,
    name_tree: BTreeMap<String, InterfaceIndex>,
    ifindex_tree: HashMap<u32, InterfaceIndex>,
    next_id: InterfaceId,
    _marker: std::marker::PhantomData<V>,
}

#[derive(Debug, Default)]
pub struct Neighbors<V: Version> {
    id_tree: HashMap<NeighborId, NeighborIndex>,
    router_id_tree: BTreeMap<Ipv4Addr, NeighborIndex>,
    net_id_tree: BTreeMap<NeighborNetId, NeighborIndex>,
    next_id: NeighborId,
    _marker: std::marker::PhantomData<V>,
}

#[derive(Debug)]
pub struct Lsdb<V: Version> {
    id_tree: HashMap<LsaEntryId, LsaEntryIndex>,
    tree: BTreeMap<V::LsaType, LsdbSingleType<V>>,
    // List of MaxAge LSAs.
    pub maxage_lsas: HashSet<LsaEntryIndex>,
    maxage_sweeper: Option<IntervalTask>,
    // List of LSAs whose origination was delayed due to the MinLSInterval
    // check.
    pub delayed_orig: HashMap<LsaKey<V::LsaType>, LsaDelayedOrig<V>>,
    // List of LSAs whose sequence number is wrapping.
    pub seqno_wrapping: HashMap<LsaKey<V::LsaType>, Lsa<V>>,
    next_id: LsaEntryId,
    lsa_count: u32,
    cksum_sum: u32,
}

#[derive(Debug)]
pub struct LsdbSingleType<V: Version> {
    lsa_type: V::LsaType,
    tree: BTreeMap<LsaKey<V::LsaType>, LsaEntryIndex>,
    lsa_count: u32,
    cksum_sum: u32,
}

// LSDB ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsdbId {
    Link(AreaId, InterfaceId),
    Area(AreaId),
    As,
}

// LSDB Index.
#[derive(Clone, Copy, Debug, EnumAsInner, Eq, PartialEq)]
pub enum LsdbIndex {
    Link(AreaIndex, InterfaceIndex),
    Area(AreaIndex),
    As,
}

// LSDB key.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum LsdbKey {
    Link(AreaKey, InterfaceKey),
    Area(AreaKey),
    As,
}

// ===== impl ObjectKey =====

impl<T> From<ObjectId> for ObjectKey<T> {
    fn from(id: ObjectId) -> ObjectKey<T> {
        ObjectKey::Id(id)
    }
}

// ===== impl Arena =====

impl<T> Arena<T> {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Index, &T)> {
        self.0.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (Index, &mut T)> {
        self.0.iter_mut()
    }
}

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

// ===== impl Areas =====

impl<V> Areas<V>
where
    V: Version,
{
    pub(crate) fn insert(
        &mut self,
        area_id: Ipv4Addr,
    ) -> (AreaIndex, &mut Area<V>) {
        // Create and insert area into the arena.
        self.next_id += 1;
        let area = Area::new(self.next_id, area_id);
        let area_idx = self.arena.0.insert(area);

        // Link area to different collections.
        let area = &mut self.arena[area_idx];
        self.id_tree.insert(area.id, area_idx);
        if self.area_id_tree.insert(area.area_id, area_idx).is_some() {
            panic!("area area-id={} already exists", area.area_id);
        }

        (area_idx, area)
    }

    pub(crate) fn delete(&mut self, area_idx: AreaIndex) {
        let area = &mut self.arena[area_idx];

        // Unlink area from different collections.
        self.id_tree.remove(&area.id);
        self.area_id_tree.remove(&area.area_id);

        // Remove area from the arena.
        self.arena.0.remove(area_idx);
    }

    // Returns a reference to the area corresponding to the given ID.
    pub(crate) fn get_by_id(
        &self,
        id: AreaId,
    ) -> Result<(AreaIndex, &Area<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|area_idx| (area_idx, &self.arena[area_idx]))
            .filter(|(_, area)| area.id == id)
            .ok_or(Error::AreaIdNotFound(id))
    }

    // Returns a mutable reference to the area corresponding to the given ID.
    pub(crate) fn get_mut_by_id(
        &mut self,
        id: AreaId,
    ) -> Result<(AreaIndex, &mut Area<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |area_idx| (area_idx, &mut self.arena[area_idx]))
            .filter(|(_, area)| area.id == id)
            .ok_or(Error::AreaIdNotFound(id))
    }

    // Returns a reference to the area corresponding to the given area ID.
    pub(crate) fn get_by_area_id(
        &self,
        area_id: Ipv4Addr,
    ) -> Option<(AreaIndex, &Area<V>)> {
        self.area_id_tree
            .get(&area_id)
            .copied()
            .map(|area_idx| (area_idx, &self.arena[area_idx]))
    }

    // Returns a mutable reference to the area corresponding to the given area
    // ID.
    pub(crate) fn get_mut_by_area_id(
        &mut self,
        area_id: Ipv4Addr,
    ) -> Option<(AreaIndex, &mut Area<V>)> {
        self.area_id_tree
            .get(&area_id)
            .copied()
            .map(move |area_idx| (area_idx, &mut self.arena[area_idx]))
    }

    // Returns a reference to the area corresponding to the given object key.
    pub(crate) fn get_by_key(
        &self,
        key: &AreaKey,
    ) -> Result<(AreaIndex, &Area<V>), Error<V>> {
        match key {
            AreaKey::Id(id) => self.get_by_id(*id),
            AreaKey::Value(area_id) => {
                Ok(self.get_by_area_id(*area_id).unwrap())
            }
        }
    }

    // Returns a mutable reference to the area corresponding to the given object
    // key.
    pub(crate) fn get_mut_by_key(
        &mut self,
        key: &AreaKey,
    ) -> Result<(AreaIndex, &mut Area<V>), Error<V>> {
        match key {
            AreaKey::Id(id) => self.get_mut_by_id(*id),
            AreaKey::Value(area_id) => {
                Ok(self.get_mut_by_area_id(*area_id).unwrap())
            }
        }
    }

    // Returns an iterator visiting all areas.
    //
    // Areas are ordered by their area IDs.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Area<V>> {
        self.area_id_tree
            .values()
            .map(|area_idx| &self.arena[*area_idx])
    }

    // Returns an iterator visiting all areas with mutable references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut Area<V>> {
        self.arena.0.iter_mut().map(|(_, area)| area)
    }

    // Returns an iterator over all interface indexes.
    //
    // Areas are ordered by their area IDs.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = AreaIndex> + '_ {
        self.area_id_tree.values().copied()
    }

    // Returns whether we're an area border router.
    pub(crate) fn is_abr(&self, interfaces: &Arena<Interface<V>>) -> bool {
        self.active_count(interfaces) > 1
    }

    // Returns the number of active areas.
    pub(crate) fn active_count(
        &self,
        interfaces: &Arena<Interface<V>>,
    ) -> usize {
        self.iter()
            .filter(|area| area.is_active(interfaces))
            .count()
    }
}

impl<V> std::ops::Index<AreaIndex> for Areas<V>
where
    V: Version,
{
    type Output = Area<V>;

    fn index(&self, index: AreaIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl<V> std::ops::IndexMut<AreaIndex> for Areas<V>
where
    V: Version,
{
    fn index_mut(&mut self, index: AreaIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}

// ===== impl Interfaces =====

impl<V> Interfaces<V>
where
    V: Version,
{
    pub(crate) fn insert<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        ifname: &str,
    ) -> (InterfaceIndex, &'a mut Interface<V>) {
        // Create and insert interface into the arena.
        self.next_id += 1;
        let iface = Interface::new(self.next_id, ifname.to_owned());
        let iface_idx = arena.0.insert(iface);

        // Link interface to different collections.
        let iface = &mut arena[iface_idx];
        self.id_tree.insert(iface.id, iface_idx);
        if self
            .name_tree
            .insert(iface.name.clone(), iface_idx)
            .is_some()
        {
            panic!("interface name={} already exists", iface.name);
        }

        (iface_idx, iface)
    }

    pub(crate) fn delete(
        &mut self,
        arena: &mut Arena<Interface<V>>,
        iface_idx: InterfaceIndex,
    ) {
        let iface = &mut arena[iface_idx];

        // Unlink interface from different collections.
        self.id_tree.remove(&iface.id);
        self.name_tree.remove(&iface.name);
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }

        // Remove interface from the arena.
        arena.0.remove(iface_idx);
    }

    // Update interface ifindex.
    pub(crate) fn update_ifindex(
        &mut self,
        iface_idx: InterfaceIndex,
        iface: &mut Interface<V>,
        ifindex: Option<u32>,
    ) {
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        iface.system.ifindex = ifindex;
        if let Some(ifindex) = ifindex {
            self.ifindex_tree.insert(ifindex, iface_idx);
        }
    }

    // Returns a reference to the interface corresponding to the given ID.
    pub(crate) fn get_by_id<'a>(
        &self,
        arena: &'a Arena<Interface<V>>,
        id: InterfaceId,
    ) -> Result<(InterfaceIndex, &'a Interface<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|iface_idx| (iface_idx, &arena[iface_idx]))
            .filter(|(_, iface)| iface.id == id)
            .ok_or(Error::InterfaceIdNotFound(id))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        id: InterfaceId,
    ) -> Result<(InterfaceIndex, &'a mut Interface<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut arena[iface_idx]))
            .filter(|(_, iface)| iface.id == id)
            .ok_or(Error::InterfaceIdNotFound(id))
    }

    // Returns a reference to the interface corresponding to the given name.
    pub(crate) fn get_by_name<'a>(
        &self,
        arena: &'a Arena<Interface<V>>,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &'a Interface<V>)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(|iface_idx| (iface_idx, &arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // name.
    pub(crate) fn get_mut_by_name<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &'a mut Interface<V>)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut arena[iface_idx]))
    }

    // Returns a reference to the interface corresponding to the given ifindex.
    pub(crate) fn get_by_ifindex<'a>(
        &self,
        arena: &'a Arena<Interface<V>>,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &'a Interface<V>)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| (iface_idx, &arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    #[expect(unused)]
    pub(crate) fn get_mut_by_ifindex<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &'a mut Interface<V>)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // IP address.
    pub(crate) fn get_mut_by_addr<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        addr: V::IpAddr,
    ) -> Option<(InterfaceIndex, &'a mut Interface<V>)> {
        for (iface_idx, iface) in arena.iter_mut() {
            if iface.system.contains_addr(&addr) {
                return Some((iface_idx, iface));
            }
        }

        None
    }

    // Returns a reference to the interface corresponding to the given object
    // key.
    pub(crate) fn get_by_key<'a>(
        &self,
        arena: &'a Arena<Interface<V>>,
        key: &InterfaceKey,
    ) -> Result<(InterfaceIndex, &'a Interface<V>), Error<V>> {
        match key {
            InterfaceKey::Id(id) => self.get_by_id(arena, *id),
            InterfaceKey::Value(ifname) => {
                Ok(self.get_by_name(arena, ifname).unwrap())
            }
        }
    }

    // Returns a mutable reference to the interface corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key<'a>(
        &mut self,
        arena: &'a mut Arena<Interface<V>>,
        key: &InterfaceKey,
    ) -> Result<(InterfaceIndex, &'a mut Interface<V>), Error<V>> {
        match key {
            InterfaceKey::Id(id) => self.get_mut_by_id(arena, *id),
            InterfaceKey::Value(ifname) => {
                Ok(self.get_mut_by_name(arena, ifname).unwrap())
            }
        }
    }

    // Returns an iterator visiting all interfaces.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<Interface<V>>,
    ) -> impl Iterator<Item = &'a Interface<V>> + 'a {
        self.name_tree.values().map(|iface_idx| &arena[*iface_idx])
    }

    // Returns an iterator over all interface indexes.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = InterfaceIndex> + '_ {
        self.name_tree.values().copied()
    }
}

// ===== impl Neighbors =====

impl<V> Neighbors<V>
where
    V: Version,
{
    pub(crate) fn insert<'a>(
        &mut self,
        arena: &'a mut Arena<Neighbor<V>>,
        router_id: Ipv4Addr,
        src: V::NetIpAddr,
    ) -> (NeighborIndex, &'a mut Neighbor<V>) {
        // Create and insert neighbor into the arena.
        self.next_id += 1;
        let nbr = Neighbor::new(self.next_id, router_id, src);
        let nbr_idx = arena.0.insert(nbr);

        // Link neighbor to different collections.
        let nbr = &mut arena[nbr_idx];
        let nbr_net_id = nbr.network_id();
        self.id_tree.insert(nbr.id, nbr_idx);
        self.router_id_tree.insert(nbr.router_id, nbr_idx);
        self.net_id_tree.insert(nbr_net_id, nbr_idx);

        (nbr_idx, nbr)
    }

    pub(crate) fn delete(
        &mut self,
        arena: &mut Arena<Neighbor<V>>,
        nbr_idx: NeighborIndex,
    ) {
        let nbr = &mut arena[nbr_idx];
        let nbr_net_id = nbr.network_id();

        // Unlink neighbor from different collections.
        self.id_tree.remove(&nbr.id);
        self.router_id_tree.remove(&nbr.router_id);
        self.net_id_tree.remove(&nbr_net_id);

        // Remove neighbor from the arena.
        arena.0.remove(nbr_idx);
    }

    pub(crate) fn update_router_id(
        &mut self,
        nbr_idx: NeighborIndex,
        nbr: &mut Neighbor<V>,
        router_id: Ipv4Addr,
    ) {
        self.router_id_tree.remove(&nbr.router_id);
        nbr.router_id = router_id;
        self.router_id_tree.insert(nbr.router_id, nbr_idx);
    }

    // Returns a reference to the neighbor corresponding to the given ID.
    pub(crate) fn get_by_id<'a>(
        &self,
        arena: &'a Arena<Neighbor<V>>,
        id: NeighborId,
    ) -> Result<(NeighborIndex, &'a Neighbor<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|nbr_idx| (nbr_idx, &arena[nbr_idx]))
            .filter(|(_, nbr)| nbr.id == id)
            .ok_or(Error::NeighborIdNotFound(id))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id<'a>(
        &mut self,
        arena: &'a mut Arena<Neighbor<V>>,
        id: NeighborId,
    ) -> Result<(NeighborIndex, &'a mut Neighbor<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut arena[nbr_idx]))
            .filter(|(_, nbr)| nbr.id == id)
            .ok_or(Error::NeighborIdNotFound(id))
    }

    // Returns a reference to the neighbor corresponding to the given Router ID.
    pub(crate) fn get_by_router_id<'a>(
        &self,
        arena: &'a Arena<Neighbor<V>>,
        router_id: Ipv4Addr,
    ) -> Option<(NeighborIndex, &'a Neighbor<V>)> {
        self.router_id_tree
            .get(&router_id)
            .copied()
            .map(|nbr_idx| (nbr_idx, &arena[nbr_idx]))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // Router ID.
    pub(crate) fn get_mut_by_router_id<'a>(
        &mut self,
        arena: &'a mut Arena<Neighbor<V>>,
        router_id: Ipv4Addr,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<V>)> {
        self.router_id_tree
            .get(&router_id)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut arena[nbr_idx]))
    }

    // Returns a reference to the neighbor corresponding to the given
    // multi-access network ID.
    pub(crate) fn get_by_net_id<'a>(
        &self,
        arena: &'a Arena<Neighbor<V>>,
        net_id: NeighborNetId,
    ) -> Option<(NeighborIndex, &'a Neighbor<V>)> {
        self.net_id_tree
            .get(&net_id)
            .copied()
            .map(|nbr_idx| (nbr_idx, &arena[nbr_idx]))
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // multi-access network ID.
    pub(crate) fn get_mut_by_net_id<'a>(
        &mut self,
        arena: &'a mut Arena<Neighbor<V>>,
        net_id: NeighborNetId,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<V>)> {
        self.net_id_tree
            .get(&net_id)
            .copied()
            .map(move |nbr_idx| (nbr_idx, &mut arena[nbr_idx]))
    }

    // Returns a reference to the neighbor corresponding to the given object
    // key.
    #[expect(unused)]
    pub(crate) fn get_by_key<'a>(
        &self,
        arena: &'a Arena<Neighbor<V>>,
        key: &NeighborKey,
    ) -> Result<(NeighborIndex, &'a Neighbor<V>), Error<V>> {
        match key {
            NeighborKey::Id(id) => self.get_by_id(arena, *id),
            NeighborKey::Value(router_id) => {
                Ok(self.get_by_router_id(arena, *router_id).unwrap())
            }
        }
    }

    // Returns a mutable reference to the neighbor corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key<'a>(
        &mut self,
        arena: &'a mut Arena<Neighbor<V>>,
        key: &NeighborKey,
    ) -> Result<(NeighborIndex, &'a mut Neighbor<V>), Error<V>> {
        match key {
            NeighborKey::Id(id) => self.get_mut_by_id(arena, *id),
            NeighborKey::Value(router_id) => {
                Ok(self.get_mut_by_router_id(arena, *router_id).unwrap())
            }
        }
    }

    // Returns an iterator visiting all neighbors.
    //
    // Neighbors are ordered by their Router IDs.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<Neighbor<V>>,
    ) -> impl Iterator<Item = &'a Neighbor<V>> + 'a {
        self.router_id_tree.values().map(|nbr_idx| &arena[*nbr_idx])
    }

    // Returns an iterator over all neighbor Router IDs.
    //
    // Neighbors are ordered by their Router IDs.
    pub(crate) fn router_ids(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.router_id_tree.keys().copied()
    }

    // Returns an iterator over all interface indexes.
    //
    // Neighbors are ordered by their Router IDs.
    pub(crate) fn indexes(&self) -> impl Iterator<Item = NeighborIndex> + '_ {
        self.router_id_tree.values().copied()
    }

    // Returns the number of neighbors.
    pub(crate) fn count(&self) -> usize {
        self.router_id_tree.len()
    }
}

// ===== impl Lsdb =====

impl<V> Lsdb<V>
where
    V: Version,
{
    pub(crate) fn insert<'a>(
        &mut self,
        arena: &'a mut Arena<LsaEntry<V>>,
        lsdb_id: LsdbId,
        lsa: Arc<Lsa<V>>,
        protocol_input: &ProtocolInputChannelsTx<V>,
    ) -> (LsaEntryIndex, &'a mut LsaEntry<V>) {
        let key = lsa.hdr.key();

        // Create and insert LSA into the arena.
        let next_id = self.next_id + 1;
        self.next_id = next_id;
        let lse =
            LsaEntry::new(lsdb_id, next_id, lsa, &protocol_input.lsa_flush);
        let lse_idx = arena.0.insert(lse);

        // Link LSA to different collections.
        let lse = &mut arena[lse_idx];
        self.id_tree.insert(lse.id, lse_idx);
        let lsdb_type =
            self.tree
                .entry(key.lsa_type)
                .or_insert_with(|| LsdbSingleType {
                    lsa_type: key.lsa_type,
                    tree: Default::default(),
                    lsa_count: 0,
                    cksum_sum: 0,
                });
        if lsdb_type.tree.insert(key, lse_idx).is_some() {
            panic!("LSA key={key:?} already exists");
        }

        // If the LSA's age is MaxAge, update the MaxAge list and schedule the
        // LSA removal.
        if lse.data.hdr.is_maxage() {
            self.maxage_lsas.insert(lse_idx);
            if self.maxage_sweeper.is_none() {
                let task = tasks::lsdb_maxage_sweep_interval(
                    lsdb_id,
                    &protocol_input.lsdb_maxage_sweep_interval,
                );
                self.maxage_sweeper = Some(task);
            }
        }

        // Update statistics.
        lsdb_type.lsa_count += 1;
        lsdb_type.cksum_sum += lse.data.hdr.cksum() as u32;
        self.lsa_count += 1;
        self.cksum_sum += lse.data.hdr.cksum() as u32;

        (lse_idx, lse)
    }

    pub(crate) fn delete(
        &mut self,
        arena: &mut Arena<LsaEntry<V>>,
        lse_idx: LsaEntryIndex,
    ) {
        let lse = &mut arena[lse_idx];
        let key = lse.data.hdr.key();
        let lsdb_type = self.tree.get_mut(&key.lsa_type).unwrap();

        // Update statistics.
        lsdb_type.lsa_count -= 1;
        lsdb_type.cksum_sum -= lse.data.hdr.cksum() as u32;
        self.lsa_count -= 1;
        self.cksum_sum -= lse.data.hdr.cksum() as u32;

        // Unlink LSA from different collections.
        self.id_tree.remove(&lse.id);
        lsdb_type.tree.remove(&key);
        if lsdb_type.tree.is_empty() {
            self.tree.remove(&key.lsa_type);
        }

        // Remove LSA from MaxAge list.
        self.maxage_lsas.remove(&lse_idx);
        if self.maxage_lsas.is_empty() {
            self.maxage_sweeper = None;
        }

        // Remove LSA from the arena.
        arena.0.remove(lse_idx);
    }

    pub(crate) fn clear(&mut self, arena: &mut Arena<LsaEntry<V>>) {
        for lse_idx in self.id_tree.values() {
            arena.0.remove(*lse_idx).unwrap();
        }
        self.id_tree.clear();
        self.tree.clear();
        self.maxage_lsas.clear();
        self.maxage_sweeper = None;
        self.delayed_orig.clear();
        self.seqno_wrapping.clear();
        self.lsa_count = 0;
        self.cksum_sum = 0;
    }

    // Returns a reference to the LSA corresponding to the given ID.
    pub(crate) fn get_by_id<'a>(
        &self,
        arena: &'a Arena<LsaEntry<V>>,
        id: LsaEntryId,
    ) -> Result<(LsaEntryIndex, &'a LsaEntry<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(|lse_idx| (lse_idx, &arena[lse_idx]))
            .filter(|(_, lse)| lse.id == id)
            .ok_or(Error::LsaEntryIdNotFound(id))
    }

    // Returns a mutable reference to the LSA corresponding to the given
    // ID.
    pub(crate) fn get_mut_by_id<'a>(
        &mut self,
        arena: &'a mut Arena<LsaEntry<V>>,
        id: LsaEntryId,
    ) -> Result<(LsaEntryIndex, &'a mut LsaEntry<V>), Error<V>> {
        self.id_tree
            .get(&id)
            .copied()
            .map(move |lse_idx| (lse_idx, &mut arena[lse_idx]))
            .filter(|(_, lse)| lse.id == id)
            .ok_or(Error::LsaEntryIdNotFound(id))
    }

    // Returns a reference to the LSA corresponding to the given LSA key.
    pub(crate) fn get<'a>(
        &self,
        arena: &'a Arena<LsaEntry<V>>,
        key: &LsaKey<V::LsaType>,
    ) -> Option<(LsaEntryIndex, &'a LsaEntry<V>)> {
        self.tree
            .get(&key.lsa_type)
            .and_then(|lsdb_type| lsdb_type.tree.get(key).copied())
            .map(move |lse_idx| (lse_idx, &arena[lse_idx]))
    }

    // Returns a mutable reference to the LSA corresponding to the given
    // LSA key.
    pub(crate) fn get_mut<'a>(
        &mut self,
        arena: &'a mut Arena<LsaEntry<V>>,
        key: &LsaKey<V::LsaType>,
    ) -> Option<(LsaEntryIndex, &'a mut LsaEntry<V>)> {
        self.tree
            .get(&key.lsa_type)
            .and_then(|lsdb_type| lsdb_type.tree.get(key).copied())
            .map(move |lse_idx| (lse_idx, &mut arena[lse_idx]))
    }

    // Returns a reference to the LSA corresponding to the given object key.
    pub(crate) fn get_by_key<'a>(
        &self,
        arena: &'a Arena<LsaEntry<V>>,
        key: &LsaEntryKey<V::LsaType>,
    ) -> Result<(LsaEntryIndex, &'a LsaEntry<V>), Error<V>> {
        match key {
            LsaEntryKey::Id(id) => self.get_by_id(arena, *id),
            LsaEntryKey::Value(key) => Ok(self.get(arena, key).unwrap()),
        }
    }

    // Returns a mutable reference to the LSA corresponding to the given
    // object key.
    pub(crate) fn get_mut_by_key<'a>(
        &mut self,
        arena: &'a mut Arena<LsaEntry<V>>,
        key: &LsaEntryKey<V::LsaType>,
    ) -> Result<(LsaEntryIndex, &'a mut LsaEntry<V>), Error<V>> {
        match key {
            LsaEntryKey::Id(id) => self.get_mut_by_id(arena, *id),
            LsaEntryKey::Value(key) => Ok(self.get_mut(arena, key).unwrap()),
        }
    }

    // Returns an iterator visiting all LSAs.
    //
    // LSAs are ordered by their keys.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<LsaEntry<V>>,
    ) -> impl Iterator<Item = (LsaEntryIndex, &'a LsaEntry<V>)> + 'a {
        self.tree
            .values()
            .flat_map(|lsdb_type| lsdb_type.iter(arena))
    }

    // Returns an iterator visiting all LSA types.
    //
    // LSA types are ordered numerically.
    pub(crate) fn iter_types(
        &self,
    ) -> impl Iterator<Item = &LsdbSingleType<V>> + '_ {
        self.tree.values()
    }

    // Returns an iterator visiting all LSAs of the given type.
    //
    // LSAs are ordered by their keys.
    pub(crate) fn iter_by_type<'a>(
        &'a self,
        arena: &'a Arena<LsaEntry<V>>,
        lsa_type: V::LsaType,
    ) -> impl Iterator<Item = (LsaEntryIndex, &'a LsaEntry<V>)> + 'a {
        self.tree
            .get(&lsa_type)
            .into_iter()
            .flat_map(|lsdb_type| lsdb_type.iter(arena))
    }

    // Returns an iterator visiting all LSAs of the given type and advertising
    // router.
    //
    // LSAs are ordered by their keys.
    pub(crate) fn iter_by_type_advrtr<'a>(
        &'a self,
        arena: &'a Arena<LsaEntry<V>>,
        lsa_type: V::LsaType,
        adv_rtr: Ipv4Addr,
    ) -> impl Iterator<Item = (LsaEntryIndex, &'a LsaEntry<V>)> + 'a {
        self.tree
            .get(&lsa_type)
            .into_iter()
            .flat_map(move |lsdb_type| {
                lsdb_type.iter_by_type_advrtr(arena, adv_rtr)
            })
    }

    // Returns an iterator over all LSA indexes.
    //
    // LSAs are ordered by their keys.
    #[expect(unused)]
    pub(crate) fn indexes(&self) -> impl Iterator<Item = LsaEntryIndex> + '_ {
        self.tree
            .values()
            .flat_map(|lsdb_type| lsdb_type.tree.values().copied())
    }

    pub(crate) fn lsa_count(&self) -> u32 {
        self.lsa_count
    }

    pub(crate) fn cksum_sum(&self) -> u32 {
        self.cksum_sum
    }
}

impl<V> Default for Lsdb<V>
where
    V: Version,
{
    fn default() -> Lsdb<V> {
        Lsdb {
            id_tree: Default::default(),
            tree: BTreeMap::new(),
            maxage_lsas: Default::default(),
            maxage_sweeper: Default::default(),
            delayed_orig: Default::default(),
            seqno_wrapping: Default::default(),
            next_id: Default::default(),
            lsa_count: 0,
            cksum_sum: 0,
        }
    }
}

// ===== impl LsdbSingleType =====

impl<V> LsdbSingleType<V>
where
    V: Version,
{
    pub(crate) fn lsa_type(&self) -> V::LsaType {
        self.lsa_type
    }

    // Returns an iterator visiting all LSAs.
    //
    // LSAs are ordered by their keys.
    pub(crate) fn iter<'a>(
        &'a self,
        arena: &'a Arena<LsaEntry<V>>,
    ) -> impl Iterator<Item = (LsaEntryIndex, &'a LsaEntry<V>)> + 'a {
        self.tree
            .values()
            .map(|lse_idx| (*lse_idx, &arena[*lse_idx]))
    }

    // Returns an iterator visiting all LSAs of the given advertising router.
    //
    // LSAs are ordered by their keys.
    pub(crate) fn iter_by_type_advrtr<'a>(
        &'a self,
        arena: &'a Arena<LsaEntry<V>>,
        adv_rtr: Ipv4Addr,
    ) -> impl Iterator<Item = (LsaEntryIndex, &'a LsaEntry<V>)> + 'a {
        let begin = LsaKey {
            lsa_type: self.lsa_type,
            adv_rtr,
            lsa_id: Ipv4Addr::new(0, 0, 0, 0),
        };
        let end = LsaKey {
            lsa_type: self.lsa_type,
            adv_rtr,
            lsa_id: Ipv4Addr::new(255, 255, 255, 255),
        };
        self.tree
            .range((
                std::ops::Bound::Included(&begin),
                std::ops::Bound::Included(&end),
            ))
            .map(|(_, lse_idx)| (*lse_idx, &arena[*lse_idx]))
    }

    pub(crate) fn lsa_count(&self) -> u32 {
        self.lsa_count
    }

    pub(crate) fn cksum_sum(&self) -> u32 {
        self.cksum_sum
    }
}

// ===== impl LsdbKey =====

impl From<LsdbId> for LsdbKey {
    fn from(lsdb_id: LsdbId) -> LsdbKey {
        match lsdb_id {
            LsdbId::Link(area_id, iface_id) => {
                LsdbKey::Link(area_id.into(), iface_id.into())
            }
            LsdbId::Area(area_id) => LsdbKey::Area(area_id.into()),
            LsdbId::As => LsdbKey::As,
        }
    }
}

// ===== global functions =====

pub(crate) fn lsdb_get<'a, V>(
    instance_lsdb: &'a Lsdb<V>,
    areas: &'a Areas<V>,
    interfaces: &'a Arena<Interface<V>>,
    lsdb_key: &LsdbKey,
) -> Result<(LsdbIndex, &'a Lsdb<V>), Error<V>>
where
    V: Version,
{
    match lsdb_key {
        LsdbKey::Link(area_key, iface_key) => {
            let (area_idx, area) = areas.get_by_key(area_key)?;
            let (iface_idx, iface) =
                area.interfaces.get_by_key(interfaces, iface_key)?;

            let lsdb_idx = LsdbIndex::Link(area_idx, iface_idx);
            let lsdb = &iface.state.lsdb;
            Ok((lsdb_idx, lsdb))
        }
        LsdbKey::Area(area_key) => {
            let (area_idx, area) = areas.get_by_key(area_key)?;

            let lsdb_idx = LsdbIndex::Area(area_idx);
            let lsdb = &area.state.lsdb;
            Ok((lsdb_idx, lsdb))
        }
        LsdbKey::As => {
            let lsdb_idx = LsdbIndex::As;
            let lsdb = instance_lsdb;
            Ok((lsdb_idx, lsdb))
        }
    }
}

pub(crate) fn lsdb_get_mut<'a, V>(
    instance_lsdb: &'a mut Lsdb<V>,
    areas: &'a mut Areas<V>,
    interfaces: &'a mut Arena<Interface<V>>,
    lsdb_key: &LsdbKey,
) -> Result<(LsdbIndex, &'a mut Lsdb<V>), Error<V>>
where
    V: Version,
{
    match lsdb_key {
        LsdbKey::Link(area_key, iface_key) => {
            let (area_idx, area) = areas.get_mut_by_key(area_key)?;
            let (iface_idx, iface) =
                area.interfaces.get_mut_by_key(interfaces, iface_key)?;

            let lsdb_idx = LsdbIndex::Link(area_idx, iface_idx);
            let lsdb = &mut iface.state.lsdb;
            Ok((lsdb_idx, lsdb))
        }
        LsdbKey::Area(area_key) => {
            let (area_idx, area) = areas.get_mut_by_key(area_key)?;

            let lsdb_idx = LsdbIndex::Area(area_idx);
            let lsdb = &mut area.state.lsdb;
            Ok((lsdb_idx, lsdb))
        }
        LsdbKey::As => {
            let lsdb_idx = LsdbIndex::As;
            let lsdb = instance_lsdb;
            Ok((lsdb_idx, lsdb))
        }
    }
}

pub(crate) fn lsdb_index<'a, V>(
    instance_lsdb: &'a Lsdb<V>,
    areas: &'a Areas<V>,
    interfaces: &'a Arena<Interface<V>>,
    lsdb_idx: LsdbIndex,
) -> (LsdbId, &'a Lsdb<V>)
where
    V: Version,
{
    match lsdb_idx {
        LsdbIndex::Link(area_idx, iface_idx) => {
            let area = &areas[area_idx];
            let iface = &interfaces[iface_idx];

            let lsdb_id = LsdbId::Link(area.id, iface.id);
            let lsdb = &iface.state.lsdb;
            (lsdb_id, lsdb)
        }
        LsdbIndex::Area(area_idx) => {
            let area = &areas[area_idx];

            let lsdb = &area.state.lsdb;
            let lsdb_id = LsdbId::Area(area.id);
            (lsdb_id, lsdb)
        }
        LsdbIndex::As => {
            let lsdb_id = LsdbId::As;
            let lsdb = instance_lsdb;
            (lsdb_id, lsdb)
        }
    }
}

pub(crate) fn lsdb_index_mut<'a, V>(
    instance_lsdb: &'a mut Lsdb<V>,
    areas: &'a mut Areas<V>,
    interfaces: &'a mut Arena<Interface<V>>,
    lsdb_idx: LsdbIndex,
) -> (LsdbId, &'a mut Lsdb<V>)
where
    V: Version,
{
    match lsdb_idx {
        LsdbIndex::Link(area_idx, iface_idx) => {
            let area = &areas[area_idx];
            let iface = &mut interfaces[iface_idx];

            let lsdb_id = LsdbId::Link(area.id, iface.id);
            let lsdb = &mut iface.state.lsdb;
            (lsdb_id, lsdb)
        }
        LsdbIndex::Area(area_idx) => {
            let area = &mut areas[area_idx];

            let lsdb = &mut area.state.lsdb;
            let lsdb_id = LsdbId::Area(area.id);
            (lsdb_id, lsdb)
        }
        LsdbIndex::As => {
            let lsdb_id = LsdbId::As;
            let lsdb = instance_lsdb;
            (lsdb_id, lsdb)
        }
    }
}
