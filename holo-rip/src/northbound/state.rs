//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
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
    type ListEntry<'a> = ListEntry<'a, V>;
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a, V: Version> {
    #[default]
    None,
    Interface(&'a Interface<V>),
    Neighbor(&'a Neighbor<V>),
    Route(&'a Route<V>),
}

pub type ListIterator<'a, V> = Box<dyn Iterator<Item = ListEntry<'a, V>> + 'a>;

impl<V> ListEntryKind for ListEntry<'_, V> where V: Version {}

// ===== YANG impls =====

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::Rip {
    fn new(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let instance_state = instance.state.as_ref()?;
        let next_triggered_update = instance_state.next_triggered_update().map(|d| d.as_secs().saturating_into());
        Some(Self {
            next_triggered_update: next_triggered_update.ignore_in_testing(),
            num_of_routes: Some(instance_state.routes.len().saturating_into()),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for rip::interfaces::interface::Interface<'a> {
    fn iter(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<ListIterator<'a, V>> {
        if !instance.is_active() {
            return None;
        };
        let iter = instance.interfaces.iter().map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        let mut next_full_update = None;
        if let Some(instance_state) = &instance.state
            && iface.state.active
        {
            // The same update interval is shared by all interfaces.
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

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::interfaces::interface::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        Some(Self {
            discontinuity_time: iface.state.statistics.discontinuity_time.as_ref().map(Cow::Borrowed),
            bad_packets_rcvd: Some(iface.state.statistics.bad_packets_rcvd),
            bad_routes_rcvd: Some(iface.state.statistics.bad_routes_rcvd),
            updates_sent: Some(iface.state.statistics.updates_sent),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance<Ripv2>> for rip::ipv4::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance<Ripv2>, _list_entry: &ListEntry<'a, Ripv2>) -> Option<ListIterator<'a, Ripv2>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.values().map(ListEntry::Neighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ripv2>, list_entry: &ListEntry<'a, Ripv2>) -> Self {
        let nbr = list_entry.as_neighbor().unwrap();
        Self {
            ipv4_address: Cow::Borrowed(&nbr.addr),
            last_update: Some(Cow::Borrowed(&nbr.last_update)).ignore_in_testing(),
            bad_packets_rcvd: Some(nbr.bad_packets_rcvd).ignore_in_testing(),
            bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ripv2>> for rip::ipv4::routes::route::Route<'a> {
    fn iter(instance: &'a Instance<Ripv2>, _list_entry: &ListEntry<'a, Ripv2>) -> Option<ListIterator<'a, Ripv2>> {
        let routes = &instance.state.as_ref()?.routes;
        let iter = routes.values().map(ListEntry::Route);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<Ripv2>, list_entry: &ListEntry<'a, Ripv2>) -> Self {
        let route = list_entry.as_route().unwrap();
        Self {
            ipv4_prefix: Cow::Borrowed(&route.prefix),
            next_hop: route.nexthop.as_ref().map(Cow::Borrowed),
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

impl<'a> YangList<'a, Instance<Ripng>> for rip::ipv6::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance<Ripng>, _list_entry: &ListEntry<'a, Ripng>) -> Option<ListIterator<'a, Ripng>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.values().map(ListEntry::Neighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance<Ripng>, list_entry: &ListEntry<'a, Ripng>) -> Self {
        let nbr = list_entry.as_neighbor().unwrap();
        Self {
            ipv6_address: Cow::Borrowed(&nbr.addr),
            last_update: Some(Cow::Borrowed(&nbr.last_update)).ignore_in_testing(),
            bad_packets_rcvd: Some(nbr.bad_packets_rcvd).ignore_in_testing(),
            bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ripng>> for rip::ipv6::routes::route::Route<'a> {
    fn iter(instance: &'a Instance<Ripng>, _list_entry: &ListEntry<'a, Ripng>) -> Option<ListIterator<'a, Ripng>> {
        let routes = &instance.state.as_ref()?.routes;
        let iter = routes.values().map(ListEntry::Route);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance<Ripng>, list_entry: &ListEntry<'a, Ripng>) -> Self {
        let route = list_entry.as_route().unwrap();
        Self {
            ipv6_prefix: Cow::Borrowed(&route.prefix),
            next_hop: route.nexthop.as_ref().map(Cow::Borrowed),
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

impl<'a, V: Version> YangContainer<'a, Instance<V>> for rip::statistics::Statistics<'a> {
    fn new(instance: &'a Instance<V>, _list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let statistics = &instance.state.as_ref()?.statistics;
        Some(Self {
            discontinuity_time: statistics.discontinuity_time.as_ref().map(Cow::Borrowed),
            requests_rcvd: Some(statistics.requests_rcvd),
            requests_sent: Some(statistics.requests_sent),
            responses_rcvd: Some(statistics.responses_rcvd),
            responses_sent: Some(statistics.responses_sent),
        })
        .ignore_in_testing()
    }
}
