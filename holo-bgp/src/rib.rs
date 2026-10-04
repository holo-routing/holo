//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map, hash_map};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Instant;

use holo_utils::bgp::RouteType;
use holo_utils::ibus::IbusChannelsTx;
use holo_utils::protocol::Protocol;
use prefix_trie::map::PrefixMap;
use serde::{Deserialize, Serialize};

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::ibus;
use crate::neighbor::{Neighbor, Neighbors, PeerIndex, PeerType};
use crate::northbound::configuration::{
    DistanceCfg, InstanceTraceOptions, MultipathCfg, RouteSelectionCfg,
};
use crate::packet::attribute::{
    Attrs, BaseAttrs, ClusterList, Comms, ExtComms, Extv6Comms, LargeComms,
    UnknownAttr,
};

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
    pub prefix_counters: HashMap<PeerIndex, PrefixCounters>,
}

// Per-peer prefix counters, maintained incrementally: prefixes received from
// the peer (Adj-RIB-In), installed in the Loc-RIB with the peer as origin,
// and advertised to the peer (post-policy Adj-RIB-Out).
#[derive(Clone, Copy, Debug, Default)]
pub struct PrefixCounters {
    pub received: u32,
    pub installed: u32,
    pub sent: u32,
}

#[derive(Debug, Default)]
pub struct Destination {
    pub local: Option<Box<LocalRoute>>,
    pub adj_rib: BTreeMap<PeerIndex, AdjRib>,
    pub redistribute: Option<Box<Redistribute>>,
}

#[derive(Debug, Default)]
pub struct AdjRib {
    adj_in: Option<Box<AdjRibIn>>,
    adj_out: Option<Box<AdjRibOut>>,
}

// Adj-RIB-In entry for a single peer.
#[derive(Debug)]
pub struct AdjRibIn {
    pub origin: RouteOrigin,
    pub route_type: RouteType,
    pub pre: Route,
    pub post: Option<(Route, SelectionState)>,
}

// Adj-RIB-Out entry for a single peer.
#[derive(Debug)]
pub struct AdjRibOut {
    pub pre: Route,
    pub post: Option<Route>,
}

// Locally redistributed route (participates in the Decision Process).
#[derive(Clone, Debug)]
pub struct Redistribute {
    pub origin: RouteOrigin,
    pub route_type: RouteType,
    pub attrs: Arc<RouteAttrs>,
    pub last_modified: Instant,
    pub selection: SelectionState,
}

// A candidate route considered by the Decision Process.
struct Candidate<'a> {
    origin: RouteOrigin,
    route_type: RouteType,
    attrs: &'a Arc<RouteAttrs>,
    last_modified: Instant,
    selection: &'a mut SelectionState,
}

// Winner of the Decision Process for a destination.
#[derive(Clone, Debug)]
pub struct BestRoute {
    pub origin: RouteOrigin,
    pub route_type: RouteType,
    // CLUSTER_ID of the route reflection client the route was learned from,
    // if any.
    pub client_cluster_id: Option<Ipv4Addr>,
    pub attrs: Arc<RouteAttrs>,
    pub last_modified: Instant,
    pub igp_cost: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRoute {
    pub origin: RouteOrigin,
    pub attrs: Arc<RouteAttrs>,
    pub route_type: RouteType,
    // CLUSTER_ID of the route reflection client the route was learned from,
    // if any.
    pub client_cluster_id: Option<Ipv4Addr>,
    pub last_modified: Instant,
    pub nexthops: Option<Box<[IpAddr]>>,
}

// A route at a single policy stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub attrs: Arc<RouteAttrs>,
    pub last_modified: Instant,
}

// Per-route state produced by the Decision Process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectionState {
    pub igp_cost: Option<u32>,
    pub ineligible_reason: Option<RouteIneligibleReason>,
    pub reject_reason: Option<RouteRejectReason>,
}

// Borrowed view of a route used by the Decision Process comparison.
#[derive(Clone, Copy)]
struct RouteRef<'a> {
    origin: RouteOrigin,
    route_type: RouteType,
    attrs: &'a Arc<RouteAttrs>,
    igp_cost: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    pub unknown: Option<Arc<AttrSet<UnknownAttrs>>>,
}

#[derive(Debug, Default)]
pub struct AttrSetsCxt {
    pub base: AttrSets<BaseAttrs>,
    pub comm: AttrSets<Comms>,
    pub ext_comm: AttrSets<ExtComms>,
    pub extv6_comm: AttrSets<Extv6Comms>,
    pub large_comm: AttrSets<LargeComms>,
    pub unknown: AttrSets<UnknownAttrs>,
    pub route: HashMap<RouteAttrsKey, Arc<RouteAttrs>>,
}

// Key identifying a unique combination of interned attribute sets by the
// index of each per-category set. Indices are always nonzero, so the optional
// fields fit in the same space as plain integers.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteAttrsKey {
    base: NonZeroU64,
    comm: Option<NonZeroU64>,
    ext_comm: Option<NonZeroU64>,
    extv6_comm: Option<NonZeroU64>,
    large_comm: Option<NonZeroU64>,
    unknown: Option<NonZeroU64>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AttrSets<T> {
    pub tree: BTreeMap<T, Arc<AttrSet<T>>>,
    next_index: NonZeroU64,
}

#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AttrSet<T> {
    pub index: NonZeroU64,
    pub value: T,
}

// Unknown attributes carried along with a route, interned as a set.
pub type UnknownAttrs = Box<[UnknownAttr]>;

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
    ClusterListLonger,
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
            prefix_counters: Default::default(),
        }
    }
}

// ===== impl AdjRib =====

impl AdjRib {
    pub(crate) fn adj_in(&self) -> Option<&AdjRibIn> {
        self.adj_in.as_deref()
    }

    pub(crate) fn in_pre(&self) -> Option<&Route> {
        self.adj_in.as_ref().map(|adj_in| &adj_in.pre)
    }

    pub(crate) fn in_post(&self) -> Option<&(Route, SelectionState)> {
        self.adj_in.as_ref().and_then(|adj_in| adj_in.post.as_ref())
    }

    pub(crate) fn out_pre(&self) -> Option<&Route> {
        self.adj_out.as_ref().map(|adj_out| &adj_out.pre)
    }

    pub(crate) fn out_post(&self) -> Option<&Route> {
        self.adj_out
            .as_ref()
            .and_then(|adj_out| adj_out.post.as_ref())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.adj_in.is_none() && self.adj_out.is_none()
    }

    // Sets or updates the pre-policy received route.
    pub(crate) fn update_in_pre(
        &mut self,
        origin: RouteOrigin,
        route_type: RouteType,
        route: Route,
        counters: &mut PrefixCounters,
    ) {
        match &mut self.adj_in {
            Some(adj_in) => adj_in.pre = route,
            None => {
                self.adj_in = Some(Box::new(AdjRibIn {
                    origin,
                    route_type,
                    pre: route,
                    post: None,
                }));
                counters.received = counters.received.saturating_add(1);
            }
        }
    }

    // Sets or updates the post-policy route, returning a reference to the
    // stored route on success.
    //
    // If the pre-policy route is gone (e.g. withdrawn while the import policy
    // was being applied), the route is dropped and None is returned.
    pub(crate) fn update_in_post(&mut self, route: Route) -> Option<&Route> {
        let adj_in = self.adj_in.as_mut()?;
        let (route, _) = adj_in.post.insert((route, SelectionState::default()));
        Some(route)
    }

    // Removes the post-policy route, returning it.
    pub(crate) fn remove_in_post(&mut self) -> Option<Route> {
        let (route, _) = self.adj_in.as_mut()?.post.take()?;
        Some(route)
    }

    // Removes the whole Adj-RIB-In entry, returning the post-policy route (for
    // nexthop untracking by the caller).
    pub(crate) fn remove_in(
        &mut self,
        counters: &mut PrefixCounters,
    ) -> Option<Route> {
        let adj_in = self.adj_in.take()?;
        counters.received = counters.received.saturating_sub(1);
        adj_in.post.map(|(route, _)| route)
    }

    // Sets or updates the pre-policy advertised route.
    pub(crate) fn update_out_pre(&mut self, route: Route) {
        match &mut self.adj_out {
            Some(adj_out) => adj_out.pre = route,
            None => {
                self.adj_out = Some(Box::new(AdjRibOut {
                    pre: route,
                    post: None,
                }));
            }
        }
    }

    // Sets or updates the post-policy advertised route, returning a reference
    // to the stored route on success.
    //
    // If the pre-policy route is gone, the route is dropped and None is
    // returned.
    pub(crate) fn update_out_post(
        &mut self,
        route: Route,
        counters: &mut PrefixCounters,
    ) -> Option<&Route> {
        let adj_out = self.adj_out.as_mut()?;
        if adj_out.post.is_none() {
            counters.sent = counters.sent.saturating_add(1);
        }
        Some(adj_out.post.insert(route))
    }

    // Removes the post-policy advertised route, returning it.
    pub(crate) fn remove_out_post(
        &mut self,
        counters: &mut PrefixCounters,
    ) -> Option<Route> {
        let route = self.adj_out.as_mut()?.post.take()?;
        counters.sent = counters.sent.saturating_sub(1);
        Some(route)
    }

    // Removes the whole Adj-RIB-Out entry, returning whether it had a
    // post-policy route (i.e. whether the route was actually advertised).
    pub(crate) fn remove_out(&mut self, counters: &mut PrefixCounters) -> bool {
        let Some(adj_out) = self.adj_out.take() else {
            return false;
        };
        if adj_out.post.is_none() {
            return false;
        }
        counters.sent = counters.sent.saturating_sub(1);
        true
    }
}

// ===== impl Route =====

impl Route {
    pub(crate) fn new(attrs: Arc<RouteAttrs>, last_modified: Instant) -> Route {
        Route {
            attrs,
            last_modified,
        }
    }

    pub(crate) fn nexthop<A>(&self) -> IpAddr
    where
        A: AddressFamily,
    {
        A::nexthop_rx_extract(&self.attrs.base.value)
    }
}

// ===== impl SelectionState =====

impl SelectionState {
    pub(crate) fn is_eligible(&self) -> bool {
        self.ineligible_reason.is_none()
    }
}

// ===== impl BestRoute =====

impl BestRoute {
    fn as_route_ref(&self) -> RouteRef<'_> {
        RouteRef {
            origin: self.origin,
            route_type: self.route_type,
            attrs: &self.attrs,
            igp_cost: self.igp_cost,
        }
    }
}

// ===== impl Candidate =====

impl Candidate<'_> {
    fn as_route_ref(&self) -> RouteRef<'_> {
        RouteRef {
            origin: self.origin,
            route_type: self.route_type,
            attrs: self.attrs,
            igp_cost: self.selection.igp_cost,
        }
    }
}

// ===== impl RouteRef =====

impl RouteRef<'_> {
    fn compare(
        &self,
        other: &RouteRef<'_>,
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
        //
        // Per RFC 4271 §9.1.2.2, the route with the lower interior cost
        // (shorter IGP path to the next-hop) must win. Local-origin routes
        // (redistribute-*, redistribute-direct, locally configured static)
        // have `igp_cost = None` because there is no next-hop to track —
        // the route originates here. They are treated as having the
        // highest interior preference over any iBGP route with a resolved
        // next-hop, matching standard BGP semantics where locally
        // originated routes win over iBGP-learned ones.
        if !selection_cfg.ignore_next_hop_igp_metric {
            let reason = RouteRejectReason::NexthopCostHigher;
            match (self.igp_cost, other.igp_cost) {
                (None, None) => {
                    // Both local — fall through to next tie-breaker.
                }
                (None, Some(_)) => {
                    // self is local, other is iBGP. Prefer local.
                    return RouteCompare::Preferred(reason);
                }
                (Some(_), None) => {
                    // self is iBGP, other is local. Prefer local (other).
                    return RouteCompare::LessPreferred(reason);
                }
                (Some(a), Some(b)) => match a.cmp(&b) {
                    Ordering::Less => {
                        return RouteCompare::Preferred(reason);
                    }
                    Ordering::Greater => {
                        return RouteCompare::LessPreferred(reason);
                    }
                    Ordering::Equal => {
                        // Move to next tie-breaker.
                    }
                },
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
        //
        // RFC 4456 - Section 9:
        // "If a route carries the ORIGINATOR_ID attribute, then in Step f)
        // the ORIGINATOR_ID SHOULD be treated as the BGP Identifier of the
        // BGP speaker that has advertised the route".
        if selection_cfg.external_compare_router_id
            && let (
                RouteOrigin::Neighbor { identifier: a, .. },
                RouteOrigin::Neighbor { identifier: b, .. },
            ) = (&self.origin, &other.origin)
        {
            let a = self.attrs.base.value.originator_id.unwrap_or(*a);
            let b = other.attrs.base.value.originator_id.unwrap_or(*b);
            let reason = RouteRejectReason::HigherRouterId;
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

        // Compare CLUSTER_LIST lengths.
        //
        // RFC 4456 - Section 9:
        // "In addition, the following rule SHOULD be inserted between Steps
        // f) and g): a BGP Speaker SHOULD prefer a route with the shorter
        // CLUSTER_LIST length.  The CLUSTER_LIST length is zero if a route
        // does not carry the CLUSTER_LIST attribute".
        let a = self.attrs.base.value.cluster_list.as_ref();
        let b = other.attrs.base.value.cluster_list.as_ref();
        let a = a.map_or(0, |cluster_list| cluster_list.0.len());
        let b = b.map_or(0, |cluster_list| cluster_list.0.len());
        let reason = RouteRejectReason::ClusterListLonger;
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
    pub(crate) fn key(&self) -> RouteAttrsKey {
        RouteAttrsKey {
            base: self.base.index,
            comm: self.comm.as_ref().map(|c| c.index),
            ext_comm: self.ext_comm.as_ref().map(|c| c.index),
            extv6_comm: self.extv6_comm.as_ref().map(|c| c.index),
            large_comm: self.large_comm.as_ref().map(|c| c.index),
            unknown: self.unknown.as_ref().map(|c| c.index),
        }
    }

    pub(crate) fn get(&self) -> Attrs {
        Attrs {
            base: self.base.value.clone(),
            comm: self.comm.as_ref().map(|set| set.value.clone()),
            ext_comm: self.ext_comm.as_ref().map(|set| set.value.clone()),
            extv6_comm: self.extv6_comm.as_ref().map(|set| set.value.clone()),
            large_comm: self.large_comm.as_ref().map(|set| set.value.clone()),
            unknown: self.unknown.as_ref().map(|set| set.value.clone()),
        }
    }
}

// ===== impl AttrSetsCxt =====

impl AttrSetsCxt {
    pub(crate) fn get_route_attr_sets(
        &mut self,
        attrs: &Attrs,
    ) -> Arc<RouteAttrs> {
        let route_attrs = RouteAttrs {
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
            unknown: attrs.unknown.as_ref().map(|u| self.unknown.get(u)),
        };
        let key = route_attrs.key();
        let route_attrs = self
            .route
            .entry(key)
            .or_insert_with(|| Arc::new(route_attrs));
        Arc::clone(route_attrs)
    }

    // Releases interned attribute sets that are no longer referenced by any
    // route, so the trees don't grow without bound as routes come and go. The
    // combinations are swept first so the per-category sets they hold are
    // released too.
    pub(crate) fn sweep(&mut self) {
        self.route
            .retain(|_, route_attrs| Arc::strong_count(route_attrs) > 1);
        self.base.sweep();
        self.comm.sweep();
        self.ext_comm.sweep();
        self.extv6_comm.sweep();
        self.large_comm.sweep();
        self.unknown.sweep();
    }
}

// ===== impl AttrSets =====

impl<T> AttrSets<T>
where
    T: Clone + Eq + std::hash::Hash + Ord + PartialEq + PartialOrd,
{
    fn get(&mut self, attr: &T) -> Arc<AttrSet<T>> {
        if let Some(attr_set) = self.tree.get(attr) {
            Arc::clone(attr_set)
        } else {
            let index = {
                #[cfg(not(feature = "deterministic"))]
                {
                    let index = self.next_index;
                    self.next_index = self.next_index.saturating_add(1);
                    index
                }
                #[cfg(feature = "deterministic")]
                {
                    use std::hash::Hasher;

                    use twox_hash::XxHash64;

                    // Collection lengths reach the hasher as usize, which is
                    // four bytes wide on a 32-bit target and eight on a
                    // 64-bit one. Write them at a fixed width so that the
                    // index does not depend on the target.
                    struct FixedWidth(XxHash64);
                    impl Hasher for FixedWidth {
                        fn finish(&self) -> u64 {
                            self.0.finish()
                        }
                        fn write(&mut self, bytes: &[u8]) {
                            self.0.write(bytes);
                        }
                        fn write_usize(&mut self, i: usize) {
                            self.0.write_u64(i as u64);
                        }
                    }

                    let mut hasher = FixedWidth(XxHash64::with_seed(0));
                    attr.hash(&mut hasher);
                    NonZeroU64::new(hasher.finish()).unwrap_or(NonZeroU64::MIN)
                }
            };
            let attr_set = Arc::new(AttrSet {
                index,
                value: attr.clone(),
            });
            self.tree.insert(attr.clone(), Arc::clone(&attr_set));
            attr_set
        }
    }

    // Drops tree entries whose only remaining holder is the tree itself (i.e. a
    // strong count of 1), meaning no route references them anymore.
    fn sweep(&mut self) {
        self.tree
            .retain(|_, attr_set| Arc::strong_count(attr_set) > 1);
    }
}

impl<T> Default for AttrSets<T> {
    fn default() -> AttrSets<T> {
        AttrSets {
            tree: Default::default(),
            next_index: NonZeroU64::MIN,
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
    best_route: &BestRoute,
    selection_cfg: &RouteSelectionCfg,
    mpath_cfg: &MultipathCfg,
) -> Option<Box<[IpAddr]>>
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
    let best_ref = best_route.as_route_ref();
    let mut nexthops = dest
        .adj_rib
        .values()
        .filter_map(|adj_rib| {
            let adj_in = adj_rib.adj_in()?;
            let (route, selection) = adj_in.post.as_ref()?;
            let route_ref = RouteRef {
                origin: adj_in.origin,
                route_type: adj_in.route_type,
                attrs: &route.attrs,
                igp_cost: selection.igp_cost,
            };
            (selection.is_eligible()
                && route_ref.compare(&best_ref, selection_cfg, Some(mpath_cfg))
                    == RouteCompare::MultipathEqual)
                .then(|| route.nexthop::<A>())
        })
        .collect::<Vec<_>>();
    nexthops.sort_unstable();
    nexthops.dedup();
    nexthops.truncate(max_paths as usize);
    Some(nexthops.into_boxed_slice())
}

// ===== global functions =====

pub(crate) fn best_path<A>(
    dest: &mut Destination,
    local_asn: u32,
    router_id: Ipv4Addr,
    neighbors: &Neighbors,
    nht: &HashMap<IpAddr, NhtEntry<A>>,
    selection_cfg: &RouteSelectionCfg,
) -> Option<Box<BestRoute>>
where
    A: AddressFamily,
{
    // Collect the post-policy Adj-RIB-In routes and the redistributed route.
    let candidates = dest
        .adj_rib
        .values_mut()
        .filter_map(|adj_rib| {
            let adj_in = adj_rib.adj_in.as_mut()?;
            let (route, selection) = adj_in.post.as_mut()?;
            Some(Candidate {
                origin: adj_in.origin,
                route_type: adj_in.route_type,
                attrs: &route.attrs,
                last_modified: route.last_modified,
                selection,
            })
        })
        .chain(dest.redistribute.as_mut().map(|r| Candidate {
            origin: r.origin,
            route_type: r.route_type,
            attrs: &r.attrs,
            last_modified: r.last_modified,
            selection: &mut r.selection,
        }));

    let mut best: Option<Candidate<'_>> = None;
    for cand in candidates {
        cand.selection.reject_reason = None;
        cand.selection.ineligible_reason = None;

        // First, check if the route is eligible.
        if cand.attrs.base.value.as_path.contains(local_asn) {
            cand.selection.ineligible_reason =
                Some(RouteIneligibleReason::AsLoop);
            continue;
        }

        // RFC 4456 - Section 8:
        // "A router that recognizes the ORIGINATOR_ID attribute SHOULD
        // ignore a route received with its BGP Identifier as the
        // ORIGINATOR_ID".
        if cand.attrs.base.value.originator_id == Some(router_id) {
            cand.selection.ineligible_reason =
                Some(RouteIneligibleReason::Originator);
            continue;
        }

        // RFC 4456 - Section 8:
        // "If the local CLUSTER_ID is found in the CLUSTER_LIST, the
        // advertisement received SHOULD be ignored".
        if let Some(cluster_list) = &cand.attrs.base.value.cluster_list
            && let RouteOrigin::Neighbor { remote_addr, .. } = cand.origin
            && let Some(nbr) = neighbors.get(&remote_addr)
            && cluster_list.0.contains(&nbr.cluster_id(router_id))
        {
            cand.selection.ineligible_reason =
                Some(RouteIneligibleReason::ClusterLoop);
            continue;
        }

        // Get interior cost to the route's nexthop.
        if !cand.origin.is_local() {
            let nexthop = A::nexthop_rx_extract(&cand.attrs.base.value);
            cand.selection.igp_cost =
                nht.get(&nexthop).and_then(|nht| nht.metric);
            if cand.selection.igp_cost.is_none() {
                cand.selection.ineligible_reason =
                    Some(RouteIneligibleReason::Unresolvable);
                continue;
            };
        }

        // Compare the current route with the best route found so far.
        match &mut best {
            None => {
                // Initialize the best route with the first eligible route.
                best = Some(cand)
            }
            Some(best_cand) => {
                // Update the best route if the current route is preferred.
                let result = cand.as_route_ref().compare(
                    &best_cand.as_route_ref(),
                    selection_cfg,
                    None,
                );
                match result {
                    RouteCompare::Preferred(reason) => {
                        best_cand.selection.reject_reason = Some(reason);
                        *best_cand = cand;
                    }
                    RouteCompare::LessPreferred(reason) => {
                        cand.selection.reject_reason = Some(reason);
                    }
                    RouteCompare::MultipathEqual
                    | RouteCompare::MultipathDifferent => unreachable!(),
                }
            }
        }
    }

    // Build the winning route, if any.
    best.map(|cand| {
        // Keep track of the route reflection client the route was learned
        // from, which decides who the route is reflected to.
        let client_cluster_id = match cand.origin {
            RouteOrigin::Neighbor { remote_addr, .. } => neighbors
                .get(&remote_addr)
                .and_then(|nbr| nbr.client_cluster_id(router_id)),
            RouteOrigin::Protocol(_) => None,
        };

        Box::new(BestRoute {
            origin: cand.origin,
            route_type: cand.route_type,
            client_cluster_id,
            attrs: cand.attrs.clone(),
            last_modified: cand.last_modified,
            igp_cost: cand.selection.igp_cost,
        })
    })
}

// Updates the Loc-RIB entry of the given destination, returning whether the
// entry has changed.
pub(crate) fn loc_rib_update<A>(
    prefix: A::IpNetwork,
    dest: &mut Destination,
    best_route: Option<Box<BestRoute>>,
    selection_cfg: &RouteSelectionCfg,
    mpath_cfg: &MultipathCfg,
    distance_cfg: &DistanceCfg,
    trace_opts: &InstanceTraceOptions,
    ibus_tx: &IbusChannelsTx,
) -> bool
where
    A: AddressFamily,
{
    if let Some(best_route) = best_route {
        if trace_opts.route {
            Debug::BestPathFound(prefix.into(), &best_route).log();
        }

        // Compute route nexthops, considering multipath configuration.
        let nexthops =
            compute_nexthops::<A>(dest, &best_route, selection_cfg, mpath_cfg);

        // Return early if no change in Loc-RIB is needed.
        if let Some(local_route) = &dest.local
            && local_route.origin == best_route.origin
            && local_route.attrs == best_route.attrs
            && local_route.route_type == best_route.route_type
            && local_route.client_cluster_id == best_route.client_cluster_id
            && local_route.nexthops == nexthops
        {
            return false;
        }

        // Create new local route.
        let local_route = LocalRoute {
            origin: best_route.origin,
            attrs: best_route.attrs,
            route_type: best_route.route_type,
            client_cluster_id: best_route.client_cluster_id,
            last_modified: best_route.last_modified,
            nexthops,
        };

        // Install local route in the global RIB.
        if !local_route.origin.is_local() {
            ibus::tx::route_install(
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
        if trace_opts.route {
            Debug::BestPathNotFound(prefix.into()).log();
        }

        // Remove route from the Loc-RIB, returning early if there's nothing
        // to remove.
        let Some(local_route) = dest.local.take() else {
            return false;
        };

        // Uninstall route from the global RIB.
        if !local_route.origin.is_local() {
            ibus::tx::route_uninstall(ibus_tx, prefix);
        }
    }

    true
}

// Updates route attributes before they are added to the neighbor's pre-policy
// Adj-RIB-Out. Export policies operate on the result of these updates and may
// overwrite any of them.
pub(crate) fn attrs_export_update<A>(
    attrs: &mut Attrs,
    nbr: &Neighbor,
    route: &BestRoute,
    router_id: Ipv4Addr,
) where
    A: AddressFamily,
{
    match nbr.peer_type {
        PeerType::Internal => {
            // Attach LOCAL_PREF with default value if it's missing.
            if attrs.base.local_pref.is_none() {
                attrs.base.local_pref = Some(DFLT_LOCAL_PREF);
            }

            // A route learned from an internal peer reaches another one only
            // by being reflected.
            if route.route_type == RouteType::Internal
                && let RouteOrigin::Neighbor { identifier, .. } = route.origin
            {
                // RFC 4456 - Section 8:
                // "A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute
                // if one already exists".
                if attrs.base.originator_id.is_none() {
                    attrs.base.originator_id = Some(identifier);
                }

                // RFC 4456 - Section 8:
                // "When an RR reflects a route, it MUST prepend the local
                // CLUSTER_ID to the CLUSTER_LIST.  If the CLUSTER_LIST is
                // empty, it MUST create a new one".
                //
                // The route leaves the cluster of the client it was learned
                // from, and enters the cluster of the client it's reflected
                // to, so the CLUSTER_ID of each is prepended, once if they're
                // the same.
                let cluster_list = attrs
                    .base
                    .cluster_list
                    .get_or_insert_with(|| ClusterList(vec![]));
                if let Some(cluster_id) = route.client_cluster_id {
                    cluster_list.0.insert(0, cluster_id);
                }
                if let Some(cluster_id) = nbr.client_cluster_id(router_id)
                    && route.client_cluster_id != Some(cluster_id)
                {
                    cluster_list.0.insert(0, cluster_id);
                }
            }
        }
        PeerType::External => {
            // Do not propagate the MULTI_EXIT_DISC attribute.
            attrs.base.med = None;

            // Remove the LOCAL_PREF attribute.
            attrs.base.local_pref = None;

            // Remove the ORIGINATOR_ID and CLUSTER_LIST attributes, which
            // only have meaning within the local AS.
            attrs.base.originator_id = None;
            attrs.base.cluster_list = None;
        }
    }

    // Update the next hop according to the route origin and the peer type.
    A::nexthop_tx_change(nbr, route.origin.is_local(), &mut attrs.base);
}

// Updates route attributes at transmission time, after export policies were
// applied. These updates are mandatory and can't be overwritten by policies.
pub(crate) fn attrs_tx_update<A>(
    attrs: &mut Attrs,
    nbr: &Neighbor,
    local_asn: u32,
) where
    A: AddressFamily,
{
    if let PeerType::External = nbr.peer_type {
        // Prepend local AS number.
        attrs.base.as_path.prepend(local_asn);

        // Remove the LOCAL_PREF attribute in case an export policy has set
        // it, as it can't be sent to external peers.
        attrs.base.local_pref = None;
    }

    // An unset next hop at this point means an export policy requested next
    // hop self. Resolve it to the source address of the session.
    if attrs.base.nexthop.is_none() {
        A::nexthop_tx_change(nbr, true, &mut attrs.base);
    }
}

// Updates the tracked nexthop of a route. Does nothing when the nexthop is
// unchanged.
pub(crate) fn nexthop_retrack<A>(
    nht: &mut HashMap<IpAddr, NhtEntry<A>>,
    prefix: A::IpNetwork,
    old_addr: Option<IpAddr>,
    addr: IpAddr,
    ibus_tx: &IbusChannelsTx,
) where
    A: AddressFamily,
{
    if old_addr == Some(addr) {
        return;
    }

    if let Some(old_addr) = old_addr {
        nexthop_untrack(nht, &prefix, old_addr, ibus_tx);
    }
    let nht = nht.entry(addr).or_insert_with(|| {
        ibus::tx::nexthop_track(ibus_tx, addr);
        Default::default()
    });
    *nht.prefixes.entry(prefix).or_default() += 1;
}

// Stops tracking the nexthop of a route.
pub(crate) fn nexthop_untrack<A>(
    nht: &mut HashMap<IpAddr, NhtEntry<A>>,
    prefix: &A::IpNetwork,
    addr: IpAddr,
    ibus_tx: &IbusChannelsTx,
) where
    A: AddressFamily,
{
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
            ibus::tx::nexthop_untrack(ibus_tx, addr);
            nht_e.remove();
        }
    }
}
