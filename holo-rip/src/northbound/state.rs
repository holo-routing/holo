//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::neighbor::Neighbor;
use crate::northbound::yang_gen::rip;
use crate::route::{Route, RouteFlags};
use crate::version::{Ripng, Ripv2, Version};

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = V::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!("/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-rip:rip", V::PROTOCOL.to_yang(), self.name)
    }
}

// ===== YANG impls =====

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::Rip {
    type ParentListEntry = ();

    fn new(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<Self> {
        let instance_state = instance.state.as_ref()?;
        let next_triggered_update = instance_state.next_triggered_update().map(|d| d.as_secs().saturating_into());
        Some(Self {
            next_triggered_update: next_triggered_update.ignore_in_testing(),
            num_of_routes: Some(instance_state.routes.len().saturating_into()),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for rip::interfaces::interface::Interface<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Interface<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if !instance.is_active() {
            return None;
        };
        let iter = instance.interfaces.iter();
        Some(iter)
    }

    fn new(instance: &'a Instance<V>, iface: &Self::ListEntry) -> Self {
        // The same update interval is shared by all interfaces.
        let mut next_full_update = None;
        if let Some(instance_state) = &instance.state
            && iface.state.active
        {
            next_full_update = Some(instance_state.next_update().as_secs().saturating_into());
        }
        Self {
            interface: Cow::Borrowed(&iface.name),
            oper_status: Some((if iface.state.active { "up" } else { "down" }).into()),
            next_full_update: next_full_update.ignore_in_testing(),
            valid_address: Some(!iface.system.addr_list.is_empty()),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::interfaces::interface::statistics::Statistics {
    type ParentListEntry = &'a Interface<V>;

    fn new(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: iface.state.statistics.discontinuity_time,
            bad_packets_rcvd: Some(iface.state.statistics.bad_packets_rcvd),
            bad_routes_rcvd: Some(iface.state.statistics.bad_routes_rcvd),
            updates_sent: Some(iface.state.statistics.updates_sent),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance<Ripv2>> for rip::ipv4::neighbors::neighbor::Neighbor {
    type ParentListEntry = ();
    type ListEntry = &'a Neighbor<Ripv2>;

    fn iter(instance: &'a Instance<Ripv2>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ripv2>, nbr: &Self::ListEntry) -> Self {
        Self {
            ipv4_address: nbr.addr,
            last_update: Some(nbr.last_update).ignore_in_testing(),
            bad_packets_rcvd: Some(nbr.bad_packets_rcvd).ignore_in_testing(),
            bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ripv2>> for rip::ipv4::routes::route::Route<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Route<Ripv2>;

    fn iter(instance: &'a Instance<Ripv2>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let routes = &instance.state.as_ref()?.routes;
        let iter = routes.values();
        Some(iter)
    }

    fn new(instance: &'a Instance<Ripv2>, route: &Self::ListEntry) -> Self {
        Self {
            ipv4_prefix: route.prefix,
            next_hop: route.nexthop,
            interface: instance.interfaces.get_by_ifindex(route.ifindex).map(|(_, iface)| Cow::Borrowed(iface.name.as_str())),
            redistributed: Some(false),
            route_type: Some(route.route_type.to_yang()),
            metric: Some(route.metric.get()),
            expire_time: route.timeout_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            deleted: Some(false),
            need_triggered_update: Some(route.flags.contains(RouteFlags::CHANGED)),
            inactive: Some(route.garbage_collect_task.is_some()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ripng>> for rip::ipv6::neighbors::neighbor::Neighbor {
    type ParentListEntry = ();
    type ListEntry = &'a Neighbor<Ripng>;

    fn iter(instance: &'a Instance<Ripng>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ripng>, nbr: &Self::ListEntry) -> Self {
        Self {
            ipv6_address: nbr.addr,
            last_update: Some(nbr.last_update).ignore_in_testing(),
            bad_packets_rcvd: Some(nbr.bad_packets_rcvd).ignore_in_testing(),
            bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ripng>> for rip::ipv6::routes::route::Route<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Route<Ripng>;

    fn iter(instance: &'a Instance<Ripng>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let routes = &instance.state.as_ref()?.routes;
        let iter = routes.values();
        Some(iter)
    }

    fn new(instance: &'a Instance<Ripng>, route: &Self::ListEntry) -> Self {
        Self {
            ipv6_prefix: route.prefix,
            next_hop: route.nexthop,
            interface: instance.interfaces.get_by_ifindex(route.ifindex).map(|(_, iface)| Cow::Borrowed(iface.name.as_str())),
            redistributed: Some(false),
            route_type: Some(route.route_type.to_yang()),
            metric: Some(route.metric.get()),
            expire_time: route.timeout_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            deleted: Some(false),
            need_triggered_update: Some(route.flags.contains(RouteFlags::CHANGED)),
            inactive: Some(route.garbage_collect_task.is_some()),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::statistics::Statistics {
    type ParentListEntry = ();

    fn new(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<Self> {
        let statistics = &instance.state.as_ref()?.statistics;
        Some(Self {
            discontinuity_time: statistics.discontinuity_time,
            requests_rcvd: Some(statistics.requests_rcvd),
            requests_sent: Some(statistics.requests_sent),
            responses_rcvd: Some(statistics.responses_rcvd),
            responses_sent: Some(statistics.responses_sent),
        })
        .ignore_in_testing()
    }
}
