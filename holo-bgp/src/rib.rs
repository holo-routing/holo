//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{btree_map, hash_map, BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use holo_utils::bgp::RouteType;
use holo_utils::ibus::IbusSender;
use holo_utils::protocol::Protocol;
use prefix_trie::map::PrefixMap;
use serde::{Deserialize, Serialize};

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::northbound::configuration::{
    DistanceCfg, MultipathCfg, RouteSelectionCfg,
};
use crate::packet::attribute::{
    Attrs, BaseAttrs, Comms, ExtComms, Extv6Comms, LargeComms, UnknownAttr,
};
use crate::policy::RoutePolicyInfo;
use crate::southbound;

// Default values.
pub const DFLT_LOCAL_PREF: u32 = 100;
pub const DFLT_MIN_AS_ORIG_INTERVAL: u16 = 15;
pub const DFLT_MIN_ROUTE_ADV_INTERVAL_EBGP: u16 = 30;
pub const DFLT_MIN_ROUTE_ADV_INTERVAL_IBGP: u16 = 5;

#[derive(Debug, Default)]
pub struct Rib {
    pub attr_sets: AttrSetsCxt,
    pub tables: RoutingTables,
}

#[derive(Debug, Default)]
pub struct RoutingTables {
    pub ipv4_unicast: RoutingTable<Ipv4Unicast>,
    pub ipv6_unicast: RoutingTable<Ipv6Unicast>,
}

#[derive(Debug)]
pub struct RoutingTable<A: AddressFamily> {
    pub prefixes: PrefixMap<A::IpNetwork, Destination>,
    pub queued_prefixes: BTreeSet<A::IpNetwork>,
    pub nht: HashMap<IpAddr, NhtEntry<A>>,
}

#[derive(Debug, Default)]
pub struct Destination {
    pub local: Option<Box<LocalRoute>>,
    pub adj_rib: BTreeMap<IpAddr, AdjRib>,
    pub redistribute: Option<Box<Route>>,
}

#[derive(Debug, Default)]
pub struct AdjRib {
    pub in_pre: Option<Box<Route>>,
    pub in_post: Option<Box<Route>>,
    pub out_pre: Option<Box<Route>>,
    pub out_post: Option<Box<Route>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRoute {
    pub origin: RouteOrigin,
    pub attrs: RouteAttrs,
    pub route_type: RouteType,
    pub last_modified: Instant,
    pub nexthops: Option<BTreeSet<IpAddr>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub origin: RouteOrigin,
    pub attrs: RouteAttrs,
    pub route_type: RouteType,
    pub igp_cost: Option<u32>,
    pub last_modified: Instant,
    pub ineligible_reason: Option<RouteIneligibleReason>,
    pub reject_reason: Option<RouteRejectReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum RouteOrigin {
    // Route learned from a neighbor.
    Neighbor {
        identifier: Ipv4Addr,
        remote_addr: IpAddr,
    },
    // Route was injected or redistributed from another protocol.
    Protocol(Protocol),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAttrs {
    pub base: Arc<AttrSet<BaseAttrs>>,
    pub comm: Option<Arc<AttrSet<Comms>>>,
    pub ext_comm: Option<Arc<AttrSet<ExtComms>>>,
    pub extv6_comm: Option<Arc<AttrSet<Extv6Comms>>>,
    pub large_comm: Option<Arc<AttrSet<LargeComms>>>,
    pub unknown: Option<Box<[UnknownAttr]>>,
}

#[derive(Debug, Default)]
pub struct AttrSetsCxt {
    pub base: AttrSets<BaseAttrs>,
    pub comm: AttrSets<Comms>,
    pub ext_comm: AttrSets<ExtComms>,
    pub extv6_comm: AttrSets<Extv6Comms>,
    pub large_comm: AttrSets<LargeComms>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AttrSets<T> {
    pub tree: BTreeMap<T, Arc<AttrSet<T>>>,
    next_index: u64,
}

#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AttrSet<T> {
    pub index: u64,
    pub value: T,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NhtEntry<A: AddressFamily> {
    pub metric: Option<u32>,
    pub prefixes: BTreeMap<A::IpNetwork, u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteIneligibleReason {
    ClusterLoop,
    AsLoop,
    Originator,
    Confed,
    Unresolvable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteRejectReason {
    LocalPrefLower,
    AsPathLonger,
    OriginTypeHigher,
    MedHigher,
    PreferExternal,
    NexthopCostHigher,
    HigherRouterId,
    HigherPeerAddress,
    RejectedImportPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteCompare {
    Preferred(RouteRejectReason),
    LessPreferred(RouteRejectReason),
    MultipathEqual,
    MultipathDifferent,
}

// ===== impl RoutingTable =====

impl<A> Default for RoutingTable<A>
where
    A: AddressFamily,
{
    fn default() -> RoutingTable<A> {
        RoutingTable {
            prefixes: Default::default(),
            queued_prefixes: Default::default(),
            nht: Default::default(),
        }
    }
}

// ===== impl AdjRib =====

impl AdjRib {
    fn remove(
        table: &mut Option<Box<Route>>,
        attr_sets: &mut AttrSetsCxt,
    ) -> Option<Box<Route>> {
        let route = table.take();

        // Check attribute sets that might need to be removed.
        if let Some(route) = &route {
            attr_sets.remove_route_attr_sets(&route.attrs);
        }

        route
    }

    fn update(
        table: &mut Option<Box<Route>>,
        route: Box<Route>,
        attr_sets: &mut AttrSetsCxt,
    ) {
        // Check attribute sets that might need to be removed.
        if let Some(old_route) = table.take()
            && old_route.attrs != route.attrs
        {
            attr_sets.remove_route_attr_sets(&old_route.attrs);
        }

        *table = Some(route)
    }

    pub(crate) fn remove_in_pre(
        &mut self,
        attr_sets: &mut AttrSetsCxt,
    ) -> Option<Box<Route>> {
        Self::remove(&mut self.in_pre, attr_sets)
    }

    pub(crate) fn remove_in_post(
        &mut self,
        attr_sets: &mut AttrSetsCxt,
    ) -> Option<Box<Route>> {
        Self::remove(&mut self.in_post, attr_sets)
    }

    pub(crate) fn remove_out_pre(
        &mut self,
        attr_sets: &mut AttrSetsCxt,
    ) -> Option<Box<Route>> {
        Self::remove(&mut self.out_pre, attr_sets)
    }

    pub(crate) fn remove_out_post(
        &mut self,
        attr_sets: &mut AttrSetsCxt,
    ) -> Option<Box<Route>> {
        Self::remove(&mut self.out_post, attr_sets)
    }

    pub(crate) fn update_in_pre(
        &mut self,
        route: Box<Route>,
        attr_sets: &mut AttrSetsCxt,
    ) {
        Self::update(&mut self.in_pre, route, attr_sets);
    }

    pub(crate) fn update_in_post(
        &mut self,
        route: Box<Route>,
        attr_sets: &mut AttrSetsCxt,
    ) {
        Self::update(&mut self.in_post, route, attr_sets);
    }

    pub(crate) fn update_out_pre(
        &mut self,
        route: Box<Route>,
        attr_sets: &mut AttrSetsCxt,
    ) {
        Self::update(&mut self.out_pre, route, attr_sets);
    }

    pub(crate) fn update_out_post(
        &mut self,
        route: Box<Route>,
        attr_sets: &mut AttrSetsCxt,
    ) {
        Self::update(&mut self.out_post, route, attr_sets);
    }
}

// ===== impl Route =====

impl Route {
    pub(crate) fn new(
        origin: RouteOrigin,
        attrs: RouteAttrs,
        route_type: RouteType,
    ) -> Route {
        Route {
            origin,
            attrs,
            route_type,
            igp_cost: None,
            last_modified: Instant::now(),
            ineligible_reason: None,
            reject_reason: None,
        }
    }

    pub(crate) fn policy_info(&self) -> RoutePolicyInfo {
        RoutePolicyInfo {
            origin: self.origin,
            route_type: self.route_type,
            tag: None,
            opaque_attrs: None,
            attrs: self.attrs.get(),
        }
    }

    pub(crate) fn is_eligible(&self) -> bool {
        self.ineligible_reason.is_none()
    }

    fn compare(
        &self,
        other: &Route,
        selection_cfg: &RouteSelectionCfg,
        mpath_cfg: Option<&MultipathCfg>,
    ) -> RouteCompare {
        // Compare LOCAL_PREFERENCE attributes.
        let a = self.attrs.base.value.local_pref.unwrap_or(DFLT_LOCAL_PREF);
        let b = other.attrs.base.value.local_pref.unwrap_or(DFLT_LOCAL_PREF);
        let reason = RouteRejectReason::LocalPrefLower;
        match a.cmp(&b) {
            Ordering::Less => {
                return RouteCompare::LessPreferred(reason);
            }
            Ordering::Greater => {
                return RouteCompare::Preferred(reason);
            }
            Ordering::Equal => {
                // Move to next tie-breaker.
            }
        }

        // Compare AS_PATH lengths.
        if !selection_cfg.ignore_as_path_length {
            let a = self.attrs.base.value.as_path.path_length();
            let b = other.attrs.base.value.as_path.path_length();
            let reason = RouteRejectReason::AsPathLonger;
            match a.cmp(&b) {
                Ordering::Less => {
                    return RouteCompare::Preferred(reason);
                }
                Ordering::Greater => {
                    return RouteCompare::LessPreferred(reason);
                }
                Ordering::Equal => {
                    // Move to next tie-breaker.
                }
            }
        }

        // Compare ORIGIN attributes.
        let a = self.attrs.base.value.origin;
        let b = other.attrs.base.value.origin;
        let reason = RouteRejectReason::OriginTypeHigher;
        match a.cmp(&b) {
            Ordering::Less => {
                return RouteCompare::Preferred(reason);
            }
            Ordering::Greater => {
                return RouteCompare::LessPreferred(reason);
            }
            Ordering::Equal => {
                // Move to next tie-breaker.
            }
        }

        // Compare MULTI_EXIT_DISC attributes.
        let a_nbr_as = self.attrs.base.value.as_path.first();
        let b_nbr_as = other.attrs.base.value.as_path.first();
        if selection_cfg.always_compare_med || a_nbr_as == b_nbr_as {
            let a = self.attrs.base.value.med.unwrap_or(0);
            let b = other.attrs.base.value.med.unwrap_or(0);
            let reason = RouteRejectReason::MedHigher;
            match a.cmp(&b) {
                Ordering::Less => {
                    return RouteCompare::Preferred(reason);
                }
                Ordering::Greater => {
                    return RouteCompare::LessPreferred(reason);
                }
                Ordering::Equal => {
                    // Move to next tie-breaker.
                }
            }
        }

        // Prefer eBGP routes.
        let a = self.route_type;
        let b = other.route_type;
        let reason = RouteRejectReason::PreferExternal;
        match a.cmp(&b) {
            Ordering::Less => {
                return RouteCompare::LessPreferred(reason);
            }
            Ordering::Greater => {
                return RouteCompare::Preferred(reason);
            }
            Ordering::Equal => {
                // Move to next tie-breaker.
            }
        }

        // Compare IGP costs.
        if !selection_cfg.ignore_next_hop_igp_metric {
            let a = self.igp_cost;
            let b = other.igp_cost;
            let reason = RouteRejectReason::NexthopCostHigher;
            match a.cmp(&b) {
                Ordering::Less => {
                    return RouteCompare::LessPreferred(reason);
                }
                Ordering::Greater => {
                    return RouteCompare::Preferred(reason);
                }
                Ordering::Equal => {
                    // Move to next tie-breaker.
                }
            }
        }

        // If multipath is enabled, routes are considered equal under specific
        // conditions.
        //
        // TODO: implement more multipath selection knobs as documented in
        // draft-lapukhov-bgp-ecmp-considerations-12
        if let Some(mpath_cfg) = mpath_cfg {
            match self.route_type {
                RouteType::External => {
                    // For eBGP, routes are considered equal if they are
                    // received from the same neighboring AS, unless this
                    // restriction is disabled by configuration.
                    if mpath_cfg.ebgp_allow_multiple_as || a_nbr_as == b_nbr_as
                    {
                        return RouteCompare::MultipathEqual;
                    }
                }
                RouteType::Internal => {
                    // For iBGP, routes are considered equal if their AS_PATH
                    // attributes match.
                    if self.attrs.base.value.as_path
                        == other.attrs.base.value.as_path
                    {
                        return RouteCompare::MultipathEqual;
                    }
                }
            }

            // Routes are considered different for multipath routing.
            return RouteCompare::MultipathDifferent;
        }

        // Compare peer BGP identifiers.
        if selection_cfg.external_compare_router_id
            && let (
                RouteOrigin::Neighbor { identifier: a, .. },
                RouteOrigin::Neighbor { identifier: b, .. },
            ) = (&self.origin, &other.origin)
        {
            let reason = RouteRejectReason::HigherRouterId;
            match a.cmp(b) {
                Ordering::Less => {
                    return RouteCompare::Preferred(reason);
                }
                Ordering::Greater => {
                    return RouteCompare::LessPreferred(reason);
                }
                Ordering::Equal => {
                    // Move to next tie-breaker.
                }
            }
        }

        // Compare peer IP addresses.
        if let (
            RouteOrigin::Neighbor { remote_addr: a, .. },
            RouteOrigin::Neighbor { remote_addr: b, .. },
        ) = (&self.origin, &other.origin)
        {
            let reason = RouteRejectReason::HigherPeerAddress;
            match a.cmp(b) {
                Ordering::Less => {
                    return RouteCompare::Preferred(reason);
                }
                Ordering::Greater => {
                    return RouteCompare::LessPreferred(reason);
                }
                Ordering::Equal => {
                    // Move to next tie-breaker.
                }
            }
        }

        // "Isso non ecziste!"
        unreachable!()
    }
}

// ===== impl RouteOrigin =====

impl RouteOrigin {
    pub(crate) fn is_local(&self) -> bool {
        matches!(self, RouteOrigin::Protocol { .. })
    }
}

// ===== impl RouteAttrs =====

impl RouteAttrs {
    pub(crate) fn get(&self) -> Attrs {
        Attrs {
            base: self.base.value.clone(),
            comm: self.comm.as_ref().map(|set| set.value.clone()),
            ext_comm: self.ext_comm.as_ref().map(|set| set.value.clone()),
            extv6_comm: self.extv6_comm.as_ref().map(|set| set.value.clone()),
            large_comm: self.large_comm.as_ref().map(|set| set.value.clone()),
            unknown: self.unknown.clone(),
        }
    }
}

// ===== impl AttrSetsCxt =====

impl AttrSetsCxt {
    pub(crate) fn get_route_attr_sets(&mut self, attrs: &Attrs) -> RouteAttrs {
        RouteAttrs {
            base: self.base.get(&attrs.base),
            comm: attrs.comm.as_ref().map(|c| self.comm.get(c)),
            ext_comm: attrs.ext_comm.as_ref().map(|c| self.ext_comm.get(c)),
            extv6_comm: attrs
                .extv6_comm
                .as_ref()
                .map(|c| self.extv6_comm.get(c)),
            large_comm: attrs
                .large_comm
                .as_ref()
                .map(|c| self.large_comm.get(c)),
            unknown: attrs.unknown.clone(),
        }
    }

    pub(crate) fn remove_route_attr_sets(&mut self, route_attrs: &RouteAttrs) {
        let base = &route_attrs.base;
        if Arc::strong_count(base) == 2 {
            self.base.tree.remove(&base.value);
        }
        if let Some(comm) = &route_attrs.comm
            && Arc::strong_count(comm) == 2
        {
            self.comm.tree.remove(&comm.value);
        }
        if let Some(ext_comm) = &route_attrs.ext_comm
            && Arc::strong_count(ext_comm) == 2
        {
            self.ext_comm.tree.remove(&ext_comm.value);
        }
        if let Some(extv6_comm) = &route_attrs.extv6_comm
            && Arc::strong_count(extv6_comm) == 2
        {
            self.extv6_comm.tree.remove(&extv6_comm.value);
        }
        if let Some(large_comm) = &route_attrs.large_comm
            && Arc::strong_count(large_comm) == 2
        {
            self.large_comm.tree.remove(&large_comm.value);
        }
    }
}

// ===== impl AttrSets =====

impl<T> AttrSets<T>
where
    T: Clone + Eq + Ord + PartialEq + PartialOrd,
{
    fn get(&mut self, attr: &T) -> Arc<AttrSet<T>> {
        if let Some(attr_set) = self.tree.get(attr) {
            Arc::clone(attr_set)
        } else {
            self.next_index += 1;
            let attr_set = Arc::new(AttrSet {
                index: self.next_index,
                value: attr.clone(),
            });
            self.tree.insert(attr.clone(), Arc::clone(&attr_set));
            attr_set
        }
    }
}

impl<T> Default for AttrSets<T> {
    fn default() -> AttrSets<T> {
        AttrSets {
            tree: Default::default(),
            next_index: 0,
        }
    }
}

// ===== impl NhtEntry =====

impl<A> Default for NhtEntry<A>
where
    A: AddressFamily,
{
    fn default() -> NhtEntry<A> {
        NhtEntry {
            metric: Default::default(),
            prefixes: Default::default(),
        }
    }
}

// ===== helper functions =====

fn compute_nexthops<A>(
    dest: &Destination,
    best_route: &Route,
    selection_cfg: &RouteSelectionCfg,
    mpath_cfg: &MultipathCfg,
) -> Option<BTreeSet<IpAddr>>
where
    A: AddressFamily,
{
    // Handle locally originated routes.
    if best_route.origin.is_local() {
        return None;
    }

    // If multipath isn't enabled, return the nexthop of the best route.
    if !mpath_cfg.enabled {
        let nexthop = A::nexthop_rx_extract(&best_route.attrs.base.value);
        return Some([nexthop].into());
    }

    // Otherwise, return as many ECMP nexthops as allowed by the configuration.
    let max_paths = match best_route.route_type {
        RouteType::Internal => mpath_cfg.ibgp_max_paths,
        RouteType::External => mpath_cfg.ebgp_max_paths,
    };
    let nexthops = dest
        .adj_rib
        .values()
        .filter_map(|adj_rib| adj_rib.in_post.as_ref())
        .filter(|route| {
            route.is_eligible()
                && route.compare(best_route, selection_cfg, Some(mpath_cfg))
                    == RouteCompare::MultipathEqual
        })
        .map(|route| A::nexthop_rx_extract(&route.attrs.base.value))
        .take(max_paths as usize)
        .collect();
    Some(nexthops)
}

// ===== global functions =====

pub(crate) fn best_path<A>(
    dest: &mut Destination,
    local_asn: u32,
    nht: &HashMap<IpAddr, NhtEntry<A>>,
    selection_cfg: &RouteSelectionCfg,
) -> Option<Box<Route>>
where
    A: AddressFamily,
{
    let mut best_route = None;

    // Iterate over each Adj-RIB-In route for the destination.
    for route in dest
        .adj_rib
        .values_mut()
        // Pick the post-policy routes.
        .filter_map(|adj_rib| adj_rib.in_post.as_mut())
        // Consider locally redistributed routes too.
        .chain(dest.redistribute.as_mut().into_iter())
    {
        route.reject_reason = None;
        route.ineligible_reason = None;

        // First, check if the route is eligible.
        if route.attrs.base.value.as_path.contains(local_asn) {
            route.ineligible_reason = Some(RouteIneligibleReason::AsLoop);
            continue;
        }

        // Get interior cost to the route's nexthop.
        if !route.origin.is_local() {
            let nexthop = A::nexthop_rx_extract(&route.attrs.base.value);
            route.igp_cost = nht.get(&nexthop).and_then(|nht| nht.metric);
            if route.igp_cost.is_none() {
                route.ineligible_reason =
                    Some(RouteIneligibleReason::Unresolvable);
                continue;
            };
        }

        // Compare the current route with the best route found so far.
        match &mut best_route {
            None => {
                // Initialize the best route with the first eligible route.
                best_route = Some(route)
            }
            Some(best_route) => {
                // Update the best route if the current route is preferred.
                match route.compare(best_route, selection_cfg, None) {
                    RouteCompare::Preferred(reason) => {
                        best_route.reject_reason = Some(reason);
                        *best_route = route;
                    }
                    RouteCompare::LessPreferred(reason) => {
                        route.reject_reason = Some(reason);
                    }
                    RouteCompare::MultipathEqual
                    | RouteCompare::MultipathDifferent => unreachable!(),
                }
            }
        }
    }

    // Return a cloned copy of the best route found, if any.
    best_route.cloned()
}

pub(crate) fn loc_rib_update<A>(
    prefix: A::IpNetwork,
    dest: &mut Destination,
    best_route: Option<Box<Route>>,
    attr_sets: &mut AttrSetsCxt,
    selection_cfg: &RouteSelectionCfg,
    mpath_cfg: &MultipathCfg,
    distance_cfg: &DistanceCfg,
    ibus_tx: &IbusSender,
) where
    A: AddressFamily,
{
    if let Some(best_route) = best_route {
        Debug::BestPathFound(prefix.into(), &best_route).log();

        // Compute route nexthops, considering multipath configuration.
        let nexthops =
            compute_nexthops::<A>(dest, &best_route, selection_cfg, mpath_cfg);

        // Return early if no change in Loc-RIB is needed.
        if let Some(local_route) = &dest.local
            && local_route.origin == best_route.origin
            && local_route.attrs == best_route.attrs
            && local_route.route_type == best_route.route_type
            && local_route.nexthops == nexthops
        {
            return;
        }

        // Create new local route.
        let local_route = LocalRoute {
            origin: best_route.origin,
            attrs: best_route.attrs,
            route_type: best_route.route_type,
            last_modified: best_route.last_modified,
            nexthops,
        };

        // Install local route in the global RIB.
        if !local_route.origin.is_local() {
            southbound::tx::route_install(
                ibus_tx,
                prefix,
                &local_route,
                match best_route.route_type {
                    RouteType::Internal => distance_cfg.internal,
                    RouteType::External => distance_cfg.external,
                },
            );
        }

        // Insert local route into the Loc-RIB.
        dest.local = Some(Box::new(local_route));
    } else {
        Debug::BestPathNotFound(prefix.into()).log();

        // Remove route from the Loc-RIB.
        if let Some(local_route) = dest.local.take()
            && !local_route.origin.is_local()
        {
            // Check attribute sets that might need to be removed.
            attr_sets.remove_route_attr_sets(&local_route.attrs);

            // Uninstall route from the global RIB.
            southbound::tx::route_uninstall(ibus_tx, prefix);
        }
    }
}

pub(crate) fn nexthop_track<A>(
    nht: &mut HashMap<IpAddr, NhtEntry<A>>,
    prefix: A::IpNetwork,
    route: &Route,
    ibus_tx: &IbusSender,
) where
    A: AddressFamily,
{
    let addr = A::nexthop_rx_extract(&route.attrs.base.value);
    let nht = nht.entry(addr).or_insert_with(|| {
        southbound::tx::nexthop_track(ibus_tx, addr);
        Default::default()
    });
    *nht.prefixes.entry(prefix).or_default() += 1;
}

pub(crate) fn nexthop_untrack<A>(
    nht: &mut HashMap<IpAddr, NhtEntry<A>>,
    prefix: &A::IpNetwork,
    route: &Route,
    ibus_tx: &IbusSender,
) where
    A: AddressFamily,
{
    let addr = A::nexthop_rx_extract(&route.attrs.base.value);
    let hash_map::Entry::Occupied(mut nht_e) = nht.entry(addr) else {
        return;
    };

    let nht = nht_e.get_mut();
    let btree_map::Entry::Occupied(mut prefix_e) = nht.prefixes.entry(*prefix)
    else {
        return;
    };

    let count = prefix_e.get_mut();
    *count -= 1;
    if *count == 0 {
        prefix_e.remove();
        if nht.prefixes.is_empty() {
            southbound::tx::nexthop_untrack(ibus_tx, addr);
            nht_e.remove();
        }
    }
}
