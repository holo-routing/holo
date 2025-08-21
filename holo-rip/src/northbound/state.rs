//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::rip;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::neighbor::Neighbor;
use crate::route::{Route, RouteFlags};
use crate::version::{Ripng, Ripv2, Version};

pub static CALLBACKS_RIPV2: Lazy<Callbacks<Instance<Ripv2>>> =
    Lazy::new(load_callbacks_ripv2);
pub static CALLBACKS_RIPNG: Lazy<Callbacks<Instance<Ripng>>> =
    Lazy::new(load_callbacks_ripng);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a, V: Version> {
    #[default]
    None,
    Interface(&'a Interface<V>),
    Ipv4Neighbor(&'a Neighbor<V>),
    Ipv4Route(&'a Route<V>),
    Ipv6Neighbor(&'a Neighbor<V>),
    Ipv6Route(&'a Route<V>),
}

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(rip::PATH)
        .get_object(|instance, _args| {
            use rip::Rip;
            let mut next_triggered_update = None;
            let mut num_of_routes = None;
            if let Some(instance_state) = &instance.state {
                next_triggered_update = instance_state
                    .next_triggered_update()
                    .map(|d| d.as_secs().saturating_into());
                num_of_routes =
                    Some(instance_state.routes.len().saturating_into());
            }
            Box::new(Rip {
                next_triggered_update: next_triggered_update
                    .ignore_in_testing(),
                num_of_routes,
            })
        })
        .path(rip::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            if !instance.is_active() {
                return None;
            };
            let iter = instance.interfaces.iter().map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use rip::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            let mut next_full_update = None;
            if let Some(instance_state) = &instance.state
                && iface.state.active
            {
                // The same update interval is shared by all interfaces.
                next_full_update = Some(
                    instance_state.next_update().as_secs().saturating_into(),
                );
            }
            Box::new(Interface {
                interface: iface.name.as_str().into(),
                oper_status: Some(
                    (if iface.state.active { "up" } else { "down" }).into(),
                ),
                next_full_update: next_full_update.ignore_in_testing(),
                valid_address: Some(!iface.system.addr_list.is_empty()),
            })
        })
        .path(rip::interfaces::interface::statistics::PATH)
        .get_object(|_instance, args| {
            use rip::interfaces::interface::statistics::Statistics;
            let iface = args.list_entry.as_interface().unwrap();
            let discontinuity_time =
                iface.state.statistics.discontinuity_time.as_ref();
            let bad_packets_rcvd =
                Some(iface.state.statistics.bad_packets_rcvd);
            let bad_routes_rcvd = Some(iface.state.statistics.bad_routes_rcvd);
            let updates_sent = Some(iface.state.statistics.updates_sent);
            Box::new(Statistics {
                discontinuity_time: discontinuity_time
                    .map(Cow::Borrowed)
                    .ignore_in_testing(),
                bad_packets_rcvd: bad_packets_rcvd.ignore_in_testing(),
                bad_routes_rcvd: bad_routes_rcvd.ignore_in_testing(),
                updates_sent: updates_sent.ignore_in_testing(),
            })
        })
        .path(rip::statistics::PATH)
        .get_object(|instance, _args| {
            use rip::statistics::Statistics;
            let mut discontinuity_time = None;
            let mut requests_rcvd = None;
            let mut requests_sent = None;
            let mut responses_rcvd = None;
            let mut responses_sent = None;
            if let Some(instance_state) = &instance.state {
                discontinuity_time =
                    instance_state.statistics.discontinuity_time.as_ref();
                requests_rcvd = Some(instance_state.statistics.requests_rcvd);
                requests_sent = Some(instance_state.statistics.requests_sent);
                responses_rcvd = Some(instance_state.statistics.responses_rcvd);
                responses_sent = Some(instance_state.statistics.responses_sent);
            }
            Box::new(Statistics {
                discontinuity_time: discontinuity_time
                    .map(Cow::Borrowed)
                    .ignore_in_testing(),
                requests_rcvd: requests_rcvd.ignore_in_testing(),
                requests_sent: requests_sent.ignore_in_testing(),
                responses_rcvd: responses_rcvd.ignore_in_testing(),
                responses_sent: responses_sent.ignore_in_testing(),
            })
        })
        .build()
}

fn load_callbacks_ripv2() -> Callbacks<Instance<Ripv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(rip::ipv4::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else {
                return None;
            };
            let iter = instance_state
                .neighbors
                .values()
                .map(ListEntry::Ipv4Neighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use rip::ipv4::neighbors::neighbor::Neighbor;
            let nbr = args.list_entry.as_ipv4_neighbor().unwrap();
            Box::new(Neighbor {
                ipv4_address: Cow::Borrowed(&nbr.addr),
                last_update: Some(Cow::Borrowed(&nbr.last_update))
                    .ignore_in_testing(),
                bad_packets_rcvd: Some(nbr.bad_packets_rcvd)
                    .ignore_in_testing(),
                bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
            })
        })
        .path(rip::ipv4::routes::route::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else {
                return None;
            };
            let iter = instance_state.routes.values().map(ListEntry::Ipv4Route);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use rip::ipv4::routes::route::Route;
            let route = args.list_entry.as_ipv4_route().unwrap();
            Box::new(Route {
                ipv4_prefix: Cow::Borrowed(&route.prefix),
                next_hop: route.nexthop.as_ref().map(Cow::Borrowed),
                interface: instance
                    .interfaces
                    .get_by_ifindex(route.ifindex)
                    .map(|(_, iface)| iface.name.as_str().into()),
                redistributed: Some(false),
                route_type: Some(route.route_type.to_yang()),
                metric: Some(route.metric.get()),
                expire_time: route
                    .timeout_remaining()
                    .map(|d| d.as_secs().saturating_into())
                    .ignore_in_testing(),
                deleted: Some(false),
                need_triggered_update: Some(
                    route.flags.contains(RouteFlags::CHANGED),
                ),
                inactive: Some(route.garbage_collect_task.is_some()),
            })
        })
        .build()
}

fn load_callbacks_ripng() -> Callbacks<Instance<Ripng>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(rip::ipv6::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else {
                return None;
            };
            let iter = instance_state
                .neighbors
                .values()
                .map(ListEntry::Ipv6Neighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use rip::ipv6::neighbors::neighbor::Neighbor;
            let nbr = args.list_entry.as_ipv6_neighbor().unwrap();
            Box::new(Neighbor {
                ipv6_address: Cow::Borrowed(&nbr.addr),
                last_update: Some(Cow::Borrowed(&nbr.last_update))
                    .ignore_in_testing(),
                bad_packets_rcvd: Some(nbr.bad_packets_rcvd)
                    .ignore_in_testing(),
                bad_routes_rcvd: Some(nbr.bad_routes_rcvd).ignore_in_testing(),
            })
        })
        .path(rip::ipv6::routes::route::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else {
                return None;
            };
            let iter = instance_state.routes.values().map(ListEntry::Ipv6Route);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use rip::ipv6::routes::route::Route;
            let route = args.list_entry.as_ipv6_route().unwrap();
            Box::new(Route {
                ipv6_prefix: Cow::Borrowed(&route.prefix),
                next_hop: route.nexthop.as_ref().map(Cow::Borrowed),
                interface: instance
                    .interfaces
                    .get_by_ifindex(route.ifindex)
                    .map(|(_, iface)| iface.name.as_str().into()),
                redistributed: Some(false),
                route_type: Some(route.route_type.to_yang()),
                metric: Some(route.metric.get()),
                expire_time: route
                    .timeout_remaining()
                    .map(|d| d.as_secs().saturating_into())
                    .ignore_in_testing(),
                deleted: Some(false),
                need_triggered_update: Some(
                    route.flags.contains(RouteFlags::CHANGED),
                ),
                inactive: Some(route.garbage_collect_task.is_some()),
            })
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = ListEntry<'a, V>;

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::state_callbacks()
    }
}

// ===== impl ListEntry =====

impl<V> ListEntryKind for ListEntry<'_, V> where V: Version {}
