//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use derive_new::new;
use holo_utils::ibus::IbusSender;
use holo_utils::ip::{
    AddressFamily, IpNetworkExt, Ipv4NetworkExt, Ipv6NetworkExt,
};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    AddressFlags, AddressMsg, LabelInstallMsg, LabelUninstallMsg, Nexthop,
    RouteKeyMsg, RouteMsg, RouteOpaqueAttrs,
};
use holo_utils::{UnboundedReceiver, UnboundedSender};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use prefix_trie::map::PrefixMap;
use tokio::sync::mpsc;
use tracing::debug;

use crate::{ibus, netlink};

#[derive(Debug)]
pub struct Rib {
    pub ipv4: PrefixMap<Ipv4Network, BTreeMap<u32, Route>>,
    pub ipv6: PrefixMap<Ipv6Network, BTreeMap<u32, Route>>,
    pub mpls: BTreeMap<Label, Route>,
    pub nht: HashMap<IpAddr, Option<u32>>,
    pub ip_update_queue: BTreeSet<IpNetwork>,
    pub mpls_update_queue: BTreeSet<Label>,
    pub update_queue_tx: UnboundedSender<()>,
    pub update_queue_rx: UnboundedReceiver<()>,
}

#[derive(Clone, Debug, new)]
pub struct Route {
    pub protocol: Protocol,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    pub opaque_attrs: RouteOpaqueAttrs,
    pub nexthops: BTreeSet<Nexthop>,
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

// ===== impl Rib =====

impl Rib {
    // Adds connected route to the RIB.
    pub(crate) fn connected_route_add(&mut self, msg: AddressMsg) {
        // Ignore unnumbered addresses.
        if msg.flags.contains(AddressFlags::UNNUMBERED) {
            return;
        }

        let prefix = msg.addr.apply_mask();
        let rib_prefix = self.prefix_entry(prefix);
        let distance = 0;
        match rib_prefix.entry(distance) {
            btree_map::Entry::Vacant(v) => {
                // If the IP route does not exist, create a new entry.
                v.insert(Route::new(
                    Protocol::DIRECT,
                    distance,
                    0,
                    None,
                    RouteOpaqueAttrs::None,
                    Default::default(),
                    Utc::now(),
                    RouteFlags::empty(),
                ));
            }
            btree_map::Entry::Occupied(o) => {
                let route = o.into_mut();

                // Update the existing IP route with the new information.
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
            }
        }

        // Add IP route to the update queue.
        self.ip_update_queue_add(prefix);
    }

    // Removes connected route from the RIB.
    pub(crate) fn connected_route_del(&mut self, msg: AddressMsg) {
        // Ignore unnumbered addresses.
        if msg.flags.contains(AddressFlags::UNNUMBERED) {
            return;
        }

        // Find IP route entry from the same advertising protocol.
        let prefix = msg.addr.apply_mask();
        let rib_prefix = self.prefix_entry(prefix);
        if let Some(route) = rib_prefix
            .values_mut()
            .find(|route| route.protocol == Protocol::DIRECT)
        {
            // Mark IP route as removed.
            route.flags.insert(RouteFlags::REMOVED);

            // Add IP route to the update queue.
            self.ip_update_queue_add(prefix);
        }
    }

    // Adds IP route to the RIB.
    pub(crate) fn ip_route_add(&mut self, mut msg: RouteMsg) {
        msg.nexthops = self.resolve_nexthops(msg.nexthops);
        let rib_prefix = self.prefix_entry(msg.prefix);
        match rib_prefix.entry(msg.distance) {
            btree_map::Entry::Vacant(v) => {
                // If the IP route does not exist, create a new entry.
                v.insert(Route::new(
                    msg.protocol,
                    msg.distance,
                    msg.metric,
                    msg.tag,
                    msg.opaque_attrs,
                    msg.nexthops,
                    Utc::now(),
                    RouteFlags::empty(),
                ));
            }
            btree_map::Entry::Occupied(o) => {
                let route = o.into_mut();

                // Update the existing IP route with the new information.
                route.distance = msg.distance;
                route.metric = msg.metric;
                route.tag = msg.tag;
                route.opaque_attrs = msg.opaque_attrs;
                route.nexthops = msg.nexthops;
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
            }
        }

        // Add IP route to the update queue.
        self.ip_update_queue_add(msg.prefix);
    }

    // Removes IP route from the RIB.
    pub(crate) fn ip_route_del(&mut self, msg: RouteKeyMsg) {
        let rib_prefix = self.prefix_entry(msg.prefix);

        // Find IP route entry from the same advertising protocol.
        if let Some(route) = rib_prefix
            .values_mut()
            .find(|route| route.protocol == msg.protocol)
        {
            // Mark IP route as removed.
            route.flags.insert(RouteFlags::REMOVED);

            // Add IP route to the update queue.
            self.ip_update_queue_add(msg.prefix);
        }
    }

    // Adds MPLS route to the RIB.
    pub(crate) fn mpls_route_add(&mut self, mut msg: LabelInstallMsg) {
        msg.nexthops = self.resolve_nexthops(msg.nexthops);
        match self.mpls.entry(msg.label) {
            btree_map::Entry::Vacant(v) => {
                // If the MPLS route does not exist, create a new entry.
                v.insert(Route::new(
                    msg.protocol,
                    0,
                    0,
                    None,
                    RouteOpaqueAttrs::None,
                    msg.nexthops.clone(),
                    Utc::now(),
                    RouteFlags::empty(),
                ));
            }
            btree_map::Entry::Occupied(o) => {
                let route = o.into_mut();

                // Update the existing MPLS route with the new information.
                route.protocol = msg.protocol;
                if msg.replace {
                    route.replace_nexthops(&msg.nexthops);
                } else {
                    route.merge_nexthops(&msg.nexthops);
                }
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
            }
        }

        // Add MPLS route to the update queue.
        self.mpls_update_queue_add(msg.label);

        // Check for the associated IP route.
        if let Some((protocol, prefix)) = msg.route {
            let rib_prefix = self.prefix_entry(prefix);
            if let Some(route) = rib_prefix
                .values_mut()
                .find(|route| route.protocol == protocol)
            {
                // Update route's nexthop labels.
                if msg.replace {
                    route.replace_nexthops_labels(&msg.nexthops);
                } else {
                    route.merge_nexthops_labels(&msg.nexthops);
                }

                // Add IP route to the update queue.
                self.ip_update_queue_add(prefix);
            }
        }
    }

    // Removes MPLS route from the RIB.
    pub(crate) fn mpls_route_del(&mut self, msg: LabelUninstallMsg) {
        // Find MPLS route entry.
        let btree_map::Entry::Occupied(mut o) = self.mpls.entry(msg.label)
        else {
            return;
        };
        let route = o.get_mut();
        if route.protocol != msg.protocol {
            return;
        }

        if msg.nexthops.is_empty() {
            // Mark MPLS route as removed.
            route.flags.insert(RouteFlags::REMOVED);

            // Add MPLS route to the update queue.
            self.mpls_update_queue_add(msg.label);

            // Check for the associated IP route.
            if let Some((protocol, prefix)) = msg.route {
                let rib_prefix = self.prefix_entry(prefix);
                if let Some(route) = rib_prefix
                    .values_mut()
                    .find(|route| route.protocol == protocol)
                {
                    // Remove route's nexthop labels.
                    route.remove_nexthops_labels();

                    // Add IP route to the update queue.
                    self.ip_update_queue_add(prefix);
                }
            }
        } else {
            // Remove nexthops from the MPLS route.
            let mut route_nhs =
                route.nexthops.clone().into_iter().collect::<Vec<_>>();
            for route_nh in route_nhs.iter_mut() {
                if msg.nexthops.iter().any(|msg_nh| route_nh.matches(msg_nh)) {
                    route_nh.remove_labels();
                }
            }
            route.nexthops = route_nhs.into_iter().collect();

            // Add MPLS route to the update queue.
            self.mpls_update_queue_add(msg.label);

            // Check for the associated IP route.
            if let Some((protocol, prefix)) = msg.route {
                let rib_prefix = self.prefix_entry(prefix);
                if let Some(route) = rib_prefix
                    .values_mut()
                    .find(|route| route.protocol == protocol)
                {
                    // Remove nexthop labels from the IP route.
                    let mut route_nhs =
                        route.nexthops.clone().into_iter().collect::<Vec<_>>();
                    for route_nh in route_nhs.iter_mut() {
                        if msg
                            .nexthops
                            .iter()
                            .any(|msg_nh| route_nh.matches(msg_nh))
                        {
                            route_nh.remove_labels();
                        }
                    }
                    route.nexthops = route_nhs.into_iter().collect();
                }

                // Add IP route to the update queue.
                self.ip_update_queue_add(prefix);
            }
        }
    }

    // Nexthop tracking registration.
    pub(crate) fn nht_add(&mut self, addr: IpAddr, ibus_tx: &IbusSender) {
        debug!(%addr, "nexthop tracking add");
        let metric = self.nht_evaluate(&addr);
        ibus::notify_nht_update(ibus_tx, addr, metric);
        self.nht.entry(addr).or_insert(metric);
    }

    // Nexthop tracking unregistration.
    pub(crate) fn nht_del(&mut self, addr: IpAddr) {
        debug!(%addr, "nexthop tracking delete");
        self.nht.remove(&addr);
    }

    // Evaluates the reachability of the given nexthop address and returns
    // the metric of the route used to reach it.
    fn nht_evaluate(&self, addr: &IpAddr) -> Option<u32> {
        self.prefix_longest_match(addr).map(|route| route.metric)
    }

    // Processes routes present in the update queue.
    pub(crate) async fn process_rib_update_queue(
        &mut self,
        netlink_handle: &rtnetlink::Handle,
        ibus_tx: &IbusSender,
    ) {
        // Process IP update queue.
        while let Some(prefix) = self.ip_update_queue.pop_first() {
            let rib_prefix = self.prefix_entry(prefix);

            // Find the protocol of the old best route, if one exists.
            let old_best_protocol = rib_prefix
                .values()
                .find(|route| route.flags.contains(RouteFlags::ACTIVE))
                .map(|route| route.protocol);

            // Remove routes marked with the REMOVED flag.
            rib_prefix
                .retain(|_, route| !route.flags.contains(RouteFlags::REMOVED));

            // Select and (re)install the best route for this prefix.
            for (idx, route) in rib_prefix.values_mut().enumerate() {
                if idx == 0 {
                    // Mark the route as the preferred one.
                    route.flags.insert(RouteFlags::ACTIVE);

                    // Install the route using the netlink handle.
                    if route.protocol != Protocol::DIRECT {
                        netlink::ip_route_install(
                            netlink_handle,
                            &prefix,
                            route,
                        )
                        .await;
                    }

                    // Notify protocol instances about the updated route.
                    ibus::notify_redistribute_add(ibus_tx, prefix, route);
                } else {
                    // Remove the preferred flag for other routes.
                    route.flags.remove(RouteFlags::ACTIVE);
                }
            }

            // Check if there are no routes left for this prefix.
            if rib_prefix.is_empty() {
                if let Some(protocol) = old_best_protocol {
                    // Uninstall the old best route using the netlink handle.
                    if protocol != Protocol::DIRECT {
                        netlink::ip_route_uninstall(
                            netlink_handle,
                            &prefix,
                            protocol,
                        )
                        .await;
                    }

                    // Notify protocol instances about the deleted route.
                    ibus::notify_redistribute_del(ibus_tx, prefix, protocol);
                }

                // Remove prefix entry from the RIB.
                match prefix {
                    IpNetwork::V4(prefix) => {
                        self.ipv4.remove(&prefix);
                    }
                    IpNetwork::V6(prefix) => {
                        self.ipv6.remove(&prefix);
                    }
                }
            }
        }

        // Process MPLS update queue.
        while let Some(label) = self.mpls_update_queue.pop_first() {
            let Some(route) = self.mpls.get_mut(&label) else {
                continue;
            };

            // Check if the route was marked for removal.
            if route.flags.contains(RouteFlags::REMOVED) {
                // Uninstall the MPLS route using the netlink handle.
                netlink::mpls_route_uninstall(
                    netlink_handle,
                    label,
                    route.protocol,
                )
                .await;

                // Effectively remove the MPLS route.
                self.mpls.remove(&label);
                continue;
            }

            // Install the route using the netlink handle.
            netlink::mpls_route_install(netlink_handle, label, route).await;
        }

        // Reevaluate all registered nexthops.
        let mut nht = std::mem::take(&mut self.nht);
        for (addr, metric) in &mut nht {
            let new_metric = self.nht_evaluate(addr);
            if new_metric != *metric {
                debug!(
                    %addr, old_metric = ?metric, ?new_metric,
                    "nexthop tracking update"
                );
                *metric = new_metric;
                ibus::notify_nht_update(ibus_tx, *addr, *metric);
            }
        }
        self.nht = nht;
    }

    // Processes route redistribution request.
    pub(crate) fn redistribute_request(
        &mut self,
        protocol: Protocol,
        af: Option<AddressFamily>,
        ibus_tx: &IbusSender,
    ) {
        debug!(%protocol, "route redistribution request");

        let redistribute_prefix = |prefix, routes: &BTreeMap<u32, Route>| {
            if let Some(best_route) = routes
                .values()
                .find(|route| route.protocol == protocol)
                .filter(|route| {
                    route.flags.contains(RouteFlags::ACTIVE)
                        && !route.flags.contains(RouteFlags::REMOVED)
                })
            {
                ibus::notify_redistribute_add(ibus_tx, prefix, best_route);
            }
        };

        if af.is_none() || af == Some(AddressFamily::Ipv4) {
            for (prefix, routes) in &self.ipv4 {
                redistribute_prefix((*prefix).into(), routes);
            }
        }
        if af.is_none() || af == Some(AddressFamily::Ipv6) {
            for (prefix, routes) in &self.ipv6 {
                redistribute_prefix((*prefix).into(), routes);
            }
        }
    }

    // Returns RIB entry associated to the given IP prefix.
    fn prefix_entry(&mut self, prefix: IpNetwork) -> &mut BTreeMap<u32, Route> {
        match prefix {
            IpNetwork::V4(prefix) => self.ipv4.entry(prefix).or_default(),
            IpNetwork::V6(prefix) => self.ipv6.entry(prefix).or_default(),
        }
    }

    // Returns the longest matching route for the given IP address.
    fn prefix_longest_match(&self, addr: &IpAddr) -> Option<&Route> {
        let lpm = match addr {
            IpAddr::V4(addr) => {
                let prefix =
                    Ipv4Network::new(*addr, Ipv4Network::MAX_PREFIXLEN)
                        .unwrap();
                let (_, lpm) = self.ipv4.get_lpm(&prefix)?;
                lpm
            }
            IpAddr::V6(addr) => {
                let prefix =
                    Ipv6Network::new(*addr, Ipv6Network::MAX_PREFIXLEN)
                        .unwrap();
                let (_, lpm) = self.ipv6.get_lpm(&prefix)?;
                lpm
            }
        };
        lpm.values()
            .next()
            .filter(|route| route.flags.contains(RouteFlags::ACTIVE))
            .filter(|route| !route.flags.contains(RouteFlags::REMOVED))
    }

    // Resolves the recursive next-hops in the provided set of next-hops.
    //
    // Note that only one level of recursion is resolved. If the resolved
    // next-hops contain recursive next-hops themselves, those will not be
    // resolved further.
    fn resolve_nexthops(
        &self,
        nexthops: BTreeSet<Nexthop>,
    ) -> BTreeSet<Nexthop> {
        nexthops
            .into_iter()
            .map(|mut nexthop| {
                if let Nexthop::Recursive { addr, resolved, .. } = &mut nexthop
                {
                    if let Some(route) = self.prefix_longest_match(addr) {
                        resolved.clone_from(&route.nexthops);
                    } else {
                        debug!(%addr, "failed to resolve recursive nexthop");
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
}

impl Default for Rib {
    fn default() -> Self {
        let (update_queue_tx, update_queue_rx) = mpsc::unbounded_channel();
        Self {
            ipv4: Default::default(),
            ipv6: Default::default(),
            mpls: Default::default(),
            nht: Default::default(),
            ip_update_queue: Default::default(),
            mpls_update_queue: Default::default(),
            update_queue_tx,
            update_queue_rx,
        }
    }
}

// ===== impl Route =====

impl Route {
    // Merges the provided set of nexthops into this route.
    //
    // If a matching nexthop is found, its labels are copied. Otherwise, the
    // nexthop is added.
    fn merge_nexthops(&mut self, other_nhs: &BTreeSet<Nexthop>) {
        let mut nhs = self.nexthops.clone().into_iter().collect::<Vec<_>>();
        for other_nh in other_nhs.iter() {
            if let Some(nh) =
                nhs.iter_mut().find(|nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            } else {
                nhs.push(other_nh.clone());
            }
        }
        self.nexthops = nhs.into_iter().collect();
    }

    // Merges the provided nexthop labels from another set into this route.
    //
    // If a matching nexthop is found, its labels are copied. Otherwise, the
    // nexthop is ignored.
    fn merge_nexthops_labels(&mut self, other_nhs: &BTreeSet<Nexthop>) {
        let mut nhs = self.nexthops.clone().into_iter().collect::<Vec<_>>();
        for nh in nhs.iter_mut() {
            if let Some(other_nh) = other_nhs
                .iter()
                .find(|other_nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            }
        }
        self.nexthops = nhs.into_iter().collect();
    }

    // Replaces the nexthops in this route with the provided set of nexthops.
    fn replace_nexthops(&mut self, other_nhs: &BTreeSet<Nexthop>) {
        self.nexthops.clone_from(other_nhs);
    }

    // Replaces the provided next hop labels from another set into this route.
    //
    // It matches and copies labels for existing nexthops and removes labels
    // for unmatched nexthops.
    fn replace_nexthops_labels(&mut self, other_nhs: &BTreeSet<Nexthop>) {
        let mut nhs = self.nexthops.clone().into_iter().collect::<Vec<_>>();
        for nh in nhs.iter_mut() {
            if let Some(other_nh) = other_nhs
                .iter()
                .find(|other_nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            } else {
                nh.remove_labels();
            }
        }
        self.nexthops = nhs.into_iter().collect();
    }

    // Removes labels from all nexthops of the route.
    fn remove_nexthops_labels(&mut self) {
        let mut nhs = self.nexthops.clone().into_iter().collect::<Vec<_>>();
        for nh in nhs.iter_mut() {
            nh.remove_labels();
        }
        self.nexthops = nhs.into_iter().collect();
    }
}
