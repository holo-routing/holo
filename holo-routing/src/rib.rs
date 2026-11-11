//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap, hash_map};
use std::net::IpAddr;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use derive_new::new;
use holo_utils::ibus::{IbusClient, IbusClientId, IbusSender};
use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    LabelInstallMsg, LabelUninstallMsg, Nexthop, RouteKeyMsg, RouteKind,
    RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;
use prefix_trie::joint::map::JointPrefixMap;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};

use crate::dataplane::Dataplane;
use crate::ibus;
use crate::interface::Interfaces;

#[derive(Debug)]
pub struct Rib {
    pub ip: JointPrefixMap<IpNetwork, Vec<Route>>,
    pub mpls: BTreeMap<Label, Route>,
    // FTN (FEC-to-NHLFE map, RFC 3031): by IP prefix, the label of the MPLS
    // route whose outgoing labels the prefix's traffic takes.
    pub ftn: HashMap<IpNetwork, Label>,
    pub nht: HashMap<IpAddr, NhtEntry>,
    pub ip_update_queue: BTreeSet<IpNetwork>,
    pub mpls_update_queue: BTreeSet<Label>,
    pub update_queue_tx: UnboundedSender<()>,
    pub subscriptions: HashMap<usize, RedistributeSub>,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub protocol: Protocol,
    pub owner: IbusClientId,
    pub kind: RouteKind,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    pub opaque_attrs: RouteOpaqueAttrs,
    pub nexthops: Box<[Nexthop]>,
    // Nexthops as the owner installed them, kept aside while `nexthops` has
    // the FTN labels applied.
    pub owner_nexthops: Option<Box<[Nexthop]>>,
    pub last_updated: DateTime<Utc>,
    pub flags: RouteFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RouteFlags: u8 {
        const ACTIVE = 0x01;
        const REMOVED = 0x02;
    }
}

#[derive(Clone, Debug, Default)]
pub struct NhtEntry {
    pub resolution: Option<NhtResolution>,
    pub subscriptions: HashMap<usize, IbusSender>,
}

// Attributes of the route a tracked nexthop address resolves through that
// matter to its subscribers.
#[derive(Clone, Debug)]
pub struct NhtResolution {
    pub protocol: Protocol,
    pub metric: u32,
    pub nexthops: Box<[Nexthop]>,
}

#[derive(Debug)]
#[derive(new)]
pub struct RedistributeSub {
    pub protocols: BTreeSet<(AddressFamily, Protocol)>,
    pub tx: IbusSender,
}

// ===== impl Rib =====

impl Rib {
    pub(crate) fn new(update_queue_tx: UnboundedSender<()>) -> Self {
        Self {
            ip: Default::default(),
            mpls: Default::default(),
            ftn: Default::default(),
            nht: Default::default(),
            ip_update_queue: Default::default(),
            mpls_update_queue: Default::default(),
            update_queue_tx,
            subscriptions: Default::default(),
        }
    }

    // Adds IP route to the RIB.
    pub(crate) fn ip_route_add(&mut self, msg: RouteMsg, owner: IbusClientId) {
        let nexthops = self.resolve_nexthops(Some(msg.prefix), msg.nexthops);
        let rib_prefix = self.prefix_entry(msg.prefix);

        // A protocol has one route to a prefix, which is looked up by the
        // protocol rather than by its distance: the distance can change, as
        // when the best BGP path moves from an external peer to an internal
        // one, and another protocol can share it.
        let (idx, route) = match rib_prefix
            .iter()
            .position(|route| route.protocol == msg.protocol)
        {
            Some(idx) => {
                // Update the existing IP route with the new information.
                let mut route = rib_prefix.remove(idx);
                route.owner = owner;
                route.kind = msg.kind;
                route.distance = msg.distance;
                route.metric = msg.metric;
                route.tag = msg.tag;
                route.opaque_attrs = msg.opaque_attrs;
                route.nexthops = nexthops;
                route.owner_nexthops = None;
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
                (idx, route)
            }
            None => (
                rib_prefix.len(),
                Route::new(
                    msg.protocol,
                    owner,
                    msg.kind,
                    msg.distance,
                    msg.metric,
                    msg.tag,
                    msg.opaque_attrs,
                    nexthops,
                ),
            ),
        };

        // Put the route back where it was, or at the end if it's new, then
        // sort the list by distance. The sort keeps routes with the same
        // distance in their order, so when routes tie the one ahead stays
        // ahead, and updating a route doesn't change that.
        rib_prefix.insert(idx, route);
        rib_prefix.sort_by_key(|route| route.distance);

        // Add IP route to the update queue.
        self.ip_update_queue_add(msg.prefix);
    }

    // Removes IP route from the RIB.
    pub(crate) fn ip_route_del(&mut self, msg: RouteKeyMsg) {
        let Some(rib_prefix) = self.ip.get_mut(&msg.prefix) else {
            return;
        };

        // Find IP route entry from the same advertising protocol.
        if let Some(route) = rib_prefix
            .iter_mut()
            .find(|route| route.protocol == msg.protocol)
        {
            // Mark IP route as removed.
            route.flags.insert(RouteFlags::REMOVED);

            // Add IP route to the update queue.
            self.ip_update_queue_add(msg.prefix);
        }
    }

    // Adds MPLS route to the RIB, replacing the one with the same label, if
    // any.
    pub(crate) fn mpls_route_add(
        &mut self,
        msg: LabelInstallMsg,
        owner: IbusClientId,
    ) {
        let nexthops = self.resolve_nexthops(None, msg.nexthops);
        let route = Route::new(
            msg.protocol,
            owner,
            RouteKind::Unicast,
            0,
            0,
            None,
            RouteOpaqueAttrs::None,
            nexthops,
        );
        self.mpls.insert(msg.label, route);

        // Add MPLS route to the update queue.
        self.mpls_update_queue_add(msg.label);

        // Point the prefix's FTN entry to this MPLS route, and install the
        // prefix's route again with the new labels.
        if let Some(prefix) = msg.prefix {
            self.ftn.insert(prefix, msg.label);
            self.ip_update_queue_add(prefix);
        }
    }

    // Removes MPLS route from the RIB.
    pub(crate) fn mpls_route_del(&mut self, msg: LabelUninstallMsg) {
        // Find MPLS route entry.
        let Some(route) = self.mpls.get_mut(&msg.label) else {
            return;
        };
        if route.protocol != msg.protocol {
            return;
        }

        // Mark MPLS route as removed.
        route.flags.insert(RouteFlags::REMOVED);

        // Add MPLS route to the update queue.
        self.mpls_update_queue_add(msg.label);

        // Remove the prefix's FTN entry if it still points to this MPLS route,
        // and install the prefix's route again without the labels.
        if let Some(prefix) = msg.prefix
            && self.ftn.get(&prefix) == Some(&msg.label)
        {
            self.ftn.remove(&prefix);
            self.ip_update_queue_add(prefix);
        }
    }

    // Nexthop tracking registration.
    pub(crate) fn nht_add(&mut self, client: IbusClient, addr: IpAddr) {
        debug!(%addr, "nexthop tracking add");
        let resolution = self.nht_evaluate(&addr);
        let nhte = self.nht.entry(addr).or_default();
        nhte.resolution = resolution;
        nhte.subscriptions.insert(client.id, client.tx);
        ibus::notify_nht_update(addr, nhte);
    }

    // Nexthop tracking unregistration.
    pub(crate) fn nht_del(&mut self, id: IbusClientId, addr: IpAddr) {
        debug!(%addr, "nexthop tracking delete");
        if let hash_map::Entry::Occupied(mut o) = self.nht.entry(addr) {
            let nhte = o.get_mut();
            nhte.subscriptions.remove(&id);
            if nhte.subscriptions.is_empty() {
                o.remove();
            }
        }
    }

    // Evaluates the reachability of the given nexthop address and returns
    // the route used to reach it.
    fn nht_evaluate(&self, addr: &IpAddr) -> Option<NhtResolution> {
        self.prefix_longest_match(addr, None)
            .map(NhtResolution::new)
    }

    // Processes routes present in the update queue.
    pub(crate) fn process_rib_update_queue(
        &mut self,
        interfaces: &Interfaces,
        dataplane: &impl Dataplane,
    ) {
        // Process IP update queue.
        while let Some(prefix) = self.ip_update_queue.pop_first() {
            // Nexthops of the MPLS route the prefix's FTN entry points to,
            // if any.
            let ftn_nexthops = self
                .ftn
                .get(&prefix)
                .and_then(|label| self.mpls.get(label))
                .map(|route| &*route.nexthops);
            let rib_prefix = self.ip.entry(prefix).or_default();

            // Find the protocol of the old best route, if one exists.
            let old_best_protocol = rib_prefix
                .iter()
                .find(|route| route.flags.contains(RouteFlags::ACTIVE))
                .map(|route| route.protocol);

            // Remove routes marked with the REMOVED flag.
            rib_prefix
                .retain(|route| !route.flags.contains(RouteFlags::REMOVED));

            // Select the best route for this prefix: the first one, as they're
            // sorted by distance, that can be used to reach it.
            let best_idx =
                rib_prefix.iter().position(|route| route.is_usable());

            // (Re)install the best route, if any.
            for (idx, route) in rib_prefix.iter_mut().enumerate() {
                if Some(idx) == best_idx {
                    // Mark the route as the preferred one.
                    route.flags.insert(RouteFlags::ACTIVE);

                    // Apply the prefix's FTN labels, if any.
                    route.relabel(ftn_nexthops);

                    // Install the route in the dataplane.
                    if route.protocol != Protocol::DIRECT {
                        dataplane.ip_route_install(&prefix, route, interfaces);
                    }

                    // Notify protocol instances about the updated route.
                    for sub in self.subscriptions.values() {
                        ibus::notify_redistribute_add(sub, prefix, route);
                    }
                } else {
                    // Remove the preferred flag for other routes.
                    route.flags.remove(RouteFlags::ACTIVE);

                    // Drop the FTN labels the route took while preferred.
                    route.relabel(None);
                }
            }

            // Check if no route can be used for this prefix anymore.
            if best_idx.is_none()
                && let Some(protocol) = old_best_protocol
            {
                // Uninstall the old best route from the dataplane.
                if protocol != Protocol::DIRECT {
                    dataplane.ip_route_uninstall(&prefix, protocol);
                }

                // Notify protocol instances about the deleted route.
                for sub in self.subscriptions.values() {
                    ibus::notify_redistribute_del(sub, prefix, protocol);
                }
            }

            // Remove the prefix entry from the RIB once it has no routes left.
            if rib_prefix.is_empty() {
                self.ip.remove(&prefix);
            }
        }

        // Process MPLS update queue.
        while let Some(label) = self.mpls_update_queue.pop_first() {
            let Some(route) = self.mpls.get_mut(&label) else {
                continue;
            };

            // Check if the route was marked for removal.
            if route.flags.contains(RouteFlags::REMOVED) {
                // Uninstall the MPLS route from the dataplane.
                dataplane.mpls_route_uninstall(label, route.protocol);

                // Effectively remove the MPLS route.
                self.mpls.remove(&label);
                continue;
            }

            // Install the route in the dataplane, or uninstall any earlier
            // version of it if it can't be used anymore.
            if route.is_usable() {
                dataplane.mpls_route_install(label, route, interfaces);
            } else {
                dataplane.mpls_route_uninstall(label, route.protocol);
            }
        }

        // Reevaluate all registered nexthops.
        let mut nht = std::mem::take(&mut self.nht);
        for (addr, nhte) in &mut nht {
            // Check whether the route the address resolves through has
            // another protocol, metric or nexthops. Moving to a route of
            // another prefix doesn't count by itself, as nothing the
            // subscribers get depends on the prefix.
            let lpm = self.prefix_longest_match(addr, None);
            let unchanged = match (&nhte.resolution, lpm) {
                (Some(old), Some(route)) => old.matches(route),
                (None, None) => true,
                _ => false,
            };
            if unchanged {
                continue;
            }

            let new = lpm.map(NhtResolution::new);
            debug!(
                %addr, old = ?nhte.resolution, ?new,
                "nexthop tracking update"
            );
            nhte.resolution = new;
            ibus::notify_nht_update(*addr, nhte);
        }
        self.nht = nht;
    }

    // Returns RIB entry associated to the given IP prefix.
    //
    // The returned list of routes is sorted by administrative distance.
    fn prefix_entry(&mut self, prefix: IpNetwork) -> &mut Vec<Route> {
        self.ip.entry(prefix).or_default()
    }

    // Returns the route to the given IP address: the active route of the
    // longest prefix that contains it, skipping prefixes without an active
    // route that can be used.
    //
    // Two other kinds of prefixes are skipped as well:
    // - The given prefix, if any, as resolving a route's nexthops through its
    //   own prefix would make the route depend on itself once installed.
    // - Prefixes whose active route has a recursive nexthop to the address,
    //   as that route can only reach the address through whatever the address
    //   itself resolves through.
    fn prefix_longest_match(
        &self,
        addr: &IpAddr,
        skip_prefix: Option<IpNetwork>,
    ) -> Option<&Route> {
        self.ip
            .cover(&addr.to_host_prefix())
            .filter(|(prefix, _)| Some(*prefix) != skip_prefix)
            .filter_map(|(_, routes)| {
                routes
                    .iter()
                    .find(|route| route.flags.contains(RouteFlags::ACTIVE))
                    .filter(|route| route.is_usable())
            })
            .filter(|route| !route.has_recursive_nexthop(addr))
            .last()
    }

    // Resolves the recursive next-hops in the provided set of next-hops.
    //
    // Note that only one level of recursion is resolved. Recursive next-hops
    // of the resolving route are replaced by the next-hops they were resolved
    // to, so that resolved next-hops never nest.
    //
    // A route can't be resolved through its own prefix, as it would end up
    // using its own next-hops once it becomes the best route for the prefix.
    fn resolve_nexthops(
        &self,
        prefix: Option<IpNetwork>,
        nexthops: Vec<Nexthop>,
    ) -> Box<[Nexthop]> {
        nexthops
            .into_iter()
            .map(|mut nexthop| {
                if let Nexthop::Recursive {
                    addr,
                    resolved,
                    labels,
                } = &mut nexthop
                {
                    if let Some(route) = self.prefix_longest_match(addr, prefix)
                    {
                        if route.protocol == Protocol::DIRECT
                            && let Some(Nexthop::Interface { ifindex }) =
                                route.nexthops.first()
                        {
                            // When recursing over connected routes, preserve
                            // the original next-hop address.
                            *resolved = [Nexthop::Address {
                                ifindex: *ifindex,
                                addr: *addr,
                                labels: labels.clone(),
                            }]
                            .into();
                        } else {
                            // Copy next-hops of the resolving route.
                            *resolved = route.resolved_nexthops();
                        }
                    } else {
                        warn!(%addr, "failed to resolve recursive nexthop");
                    }
                }
                nexthop
            })
            .collect()
    }

    // Adds IP route to the update queue.
    fn ip_update_queue_add(&mut self, prefix: IpNetwork) {
        self.ip_update_queue.insert(prefix);
        let _ = self.update_queue_tx.send(());
    }

    // Adds MPLS label to the update queue.
    fn mpls_update_queue_add(&mut self, label: Label) {
        self.mpls_update_queue.insert(label);
        let _ = self.update_queue_tx.send(());
    }

    // Removes all IP and MPLS routes installed by the given client.
    pub(crate) fn route_remove_all_by_owner(&mut self, owner: IbusClientId) {
        // Remove all IP routes owned by the given client.
        for (prefix, rib_prefix) in self.ip.iter_mut() {
            for route in rib_prefix.iter_mut() {
                if route.owner == owner {
                    route.flags.insert(RouteFlags::REMOVED);
                    self.ip_update_queue.insert(prefix);
                }
            }
        }

        // Remove all MPLS routes owned by the given client.
        for (label, route) in &mut self.mpls {
            if route.owner == owner {
                route.flags.insert(RouteFlags::REMOVED);
                self.mpls_update_queue.insert(*label);
            }
        }

        // Remove all FTN entries corresponding to labels owned by the given
        // client, and install the prefixes' routes again without the labels.
        self.ftn.retain(|prefix, label| {
            let keep = self
                .mpls
                .get(label)
                .is_some_and(|route| route.owner != owner);
            if !keep {
                self.ip_update_queue.insert(*prefix);
            }
            keep
        });
        let _ = self.update_queue_tx.send(());
    }

    // Uninstall all routes.
    pub(crate) fn route_uninstall_all(&mut self, dataplane: &impl Dataplane) {
        for (prefix, rib_prefix) in &self.ip {
            if let Some(route) = rib_prefix
                .iter()
                .find(|route| route.flags.contains(RouteFlags::ACTIVE))
            {
                dataplane.ip_route_uninstall(&prefix, route.protocol);
            }
        }
        for (label, route) in &self.mpls {
            dataplane.mpls_route_uninstall(*label, route.protocol);
        }
    }
}

// ===== impl Route =====

impl Route {
    fn new(
        protocol: Protocol,
        owner: IbusClientId,
        kind: RouteKind,
        distance: u32,
        metric: u32,
        tag: Option<u32>,
        opaque_attrs: RouteOpaqueAttrs,
        nexthops: Box<[Nexthop]>,
    ) -> Route {
        Route {
            protocol,
            owner,
            kind,
            distance,
            metric,
            tag,
            opaque_attrs,
            nexthops,
            owner_nexthops: None,
            last_updated: Utc::now(),
            flags: RouteFlags::empty(),
        }
    }

    // Relabels the nexthops of the route: the outgoing labels of the given
    // FTN nexthops are applied to the nexthops that match them, as the owner
    // of the route installed them, in place of their own. Without FTN
    // nexthops, the route is left with the nexthops of its owner.
    fn relabel(&mut self, ftn_nexthops: Option<&[Nexthop]>) {
        // Start over from the nexthops installed by the owner.
        if let Some(owner_nexthops) = self.owner_nexthops.take() {
            self.nexthops = owner_nexthops;
        }
        let Some(ftn_nexthops) = ftn_nexthops else {
            return;
        };

        let mut nexthops = self.nexthops.clone();
        for nexthop in nexthops.iter_mut() {
            if let Some(ftn_nexthop) = ftn_nexthops
                .iter()
                .find(|ftn_nexthop| nexthop.matches_no_labels(ftn_nexthop))
            {
                nexthop.copy_labels(ftn_nexthop);
            }
        }

        // Keep the owner's nexthops aside only if they were changed.
        if nexthops != self.nexthops {
            let owner_nexthops =
                std::mem::replace(&mut self.nexthops, nexthops);
            self.owner_nexthops = Some(owner_nexthops);
        }
    }

    // Returns whether the route has a recursive nexthop to the given address.
    fn has_recursive_nexthop(&self, addr: &IpAddr) -> bool {
        self.nexthops.iter().any(|nexthop| {
            matches!(
                nexthop,
                Nexthop::Recursive { addr: nexthop_addr, .. }
                    if nexthop_addr == addr
            )
        })
    }

    // Returns the nexthops of the route, with the recursive ones replaced by
    // the nexthops they were resolved to.
    fn resolved_nexthops(&self) -> Box<[Nexthop]> {
        let mut nexthops = vec![];
        for nexthop in &self.nexthops {
            match nexthop {
                Nexthop::Recursive { resolved, .. } => {
                    nexthops.extend_from_slice(resolved)
                }
                _ => nexthops.push(nexthop.clone()),
            }
        }
        nexthops.into()
    }

    // Returns whether the route can be used. It can't once it's withdrawn, nor
    // when it's meant to forward traffic but none of its nexthops can, as when
    // its recursive nexthops failed to resolve.
    fn is_usable(&self) -> bool {
        if self.flags.contains(RouteFlags::REMOVED) {
            return false;
        }

        if self.kind == RouteKind::Unicast
            && !self.nexthops.iter().any(|nexthop| match nexthop {
                Nexthop::Recursive { resolved, .. } => !resolved.is_empty(),
                _ => true,
            })
        {
            return false;
        }

        true
    }
}

// ===== impl NhtResolution =====

impl NhtResolution {
    fn new(route: &Route) -> Self {
        NhtResolution {
            protocol: route.protocol,
            metric: route.metric,
            nexthops: route.nexthops.clone(),
        }
    }

    // Returns whether the given route has the same protocol, metric and
    // nexthops as the one recorded.
    fn matches(&self, route: &Route) -> bool {
        self.protocol == route.protocol
            && self.metric == route.metric
            && self.nexthops == route.nexthops
    }
}
