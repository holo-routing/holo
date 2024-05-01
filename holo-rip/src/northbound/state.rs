//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, NodeAttributes, Provider,
};
use holo_northbound::yang::control_plane_protocol::rip;
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
    CallbacksBuilder::default()
        .path(rip::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter =
                    instance.core.interfaces.iter().map(ListEntry::Interface);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(rip::interfaces::interface::neighbors::neighbor::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(rip::interfaces::interface::oper_status::PATH)
        .get_element_string(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            let status = if iface.is_active() { "up" } else { "down" };
            Some(status.to_owned())
        })
        .path(rip::interfaces::interface::next_full_update::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u32(|instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            if iface.is_active() {
                // The same update interval is shared by all interfaces.
                instance.as_up().map(|instance| {
                    let remaining = instance.state.next_update();
                    u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX)
                })
            } else {
                None
            }
        })
        .path(rip::interfaces::interface::valid_address::PATH)
        .get_element_bool(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(!iface.core().system.addr_list.is_empty())
        })
        .path(rip::interfaces::interface::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            if let Interface::Up(iface) = iface {
                iface.state.statistics.discontinuity_time
            } else {
                None
            }
        })
        .path(rip::interfaces::interface::statistics::bad_packets_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            if let Interface::Up(iface) = iface {
                Some(iface.state.statistics.bad_packets_rcvd)
            } else {
                None
            }
        })
        .path(rip::interfaces::interface::statistics::bad_routes_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            if let Interface::Up(iface) = iface {
                Some(iface.state.statistics.bad_routes_rcvd)
            } else {
                None
            }
        })
        .path(rip::interfaces::interface::statistics::updates_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            if let Interface::Up(iface) = iface {
                Some(iface.state.statistics.updates_sent)
            } else {
                None
            }
        })
        .path(rip::next_triggered_update::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u32(|instance, _args| {
            instance.as_up().and_then(|instance| {
                instance.state.next_triggered_update().map(|remaining| {
                    u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX)
                })
            })
        })
        .path(rip::num_of_routes::PATH)
        .get_element_u32(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let num_of_routes = u32::try_from(instance.state.routes.len())
                    .unwrap_or(u32::MAX);
                Some(num_of_routes)
            } else {
                None
            }
        })
        .path(rip::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|instance, _args| {
            instance.as_up().and_then(|instance| {
                instance.state.statistics.discontinuity_time
            })
        })
        .path(rip::statistics::requests_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance
                .as_up()
                .map(|instance| instance.state.statistics.requests_rcvd)
        })
        .path(rip::statistics::requests_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance
                .as_up()
                .map(|instance| instance.state.statistics.requests_sent)
        })
        .path(rip::statistics::responses_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance
                .as_up()
                .map(|instance| instance.state.statistics.responses_rcvd)
        })
        .path(rip::statistics::responses_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance
                .as_up()
                .map(|instance| instance.state.statistics.responses_sent)
        })
        .build()
}

fn load_callbacks_ripv2() -> Callbacks<Instance<Ripv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(rip::ipv4::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .state
                    .neighbors
                    .values()
                    .map(ListEntry::Ipv4Neighbor);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(rip::ipv4::neighbors::neighbor::last_update::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_ipv4_neighbor().unwrap();
            Some(nbr.last_update)
        })
        .path(rip::ipv4::neighbors::neighbor::bad_packets_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_ipv4_neighbor().unwrap();
            Some(nbr.bad_packets_rcvd)
        })
        .path(rip::ipv4::neighbors::neighbor::bad_routes_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_ipv4_neighbor().unwrap();
            Some(nbr.bad_routes_rcvd)
        })
        .path(rip::ipv4::routes::route::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter =
                    instance.state.routes.values().map(ListEntry::Ipv4Route);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(rip::ipv4::routes::route::next_hop::PATH)
        .get_element_ipv4(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            route.nexthop
        })
        .path(rip::ipv4::routes::route::interface::PATH)
        .get_element_string(|instance, args| {
            let instance = instance.as_up().unwrap();
            let route = args.list_entry.as_ipv4_route().unwrap();
            if let Some((_, iface)) =
                instance.core.interfaces.get_by_ifindex(route.ifindex)
            {
                Some(iface.core().name.clone())
            } else {
                None
            }
        })
        .path(rip::ipv4::routes::route::redistributed::PATH)
        .get_element_bool(|_instance, _args| Some(false))
        .path(rip::ipv4::routes::route::route_type::PATH)
        .get_element_string(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            Some(route.route_type.to_yang().into())
        })
        .path(rip::ipv4::routes::route::metric::PATH)
        .get_element_u8(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            Some(route.metric.get())
        })
        .path(rip::ipv4::routes::route::expire_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            route.timeout_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(rip::ipv4::routes::route::deleted::PATH)
        .get_element_bool(|_instance, _args| Some(false))
        .path(rip::ipv4::routes::route::need_triggered_update::PATH)
        .get_element_bool(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            Some(route.flags.contains(RouteFlags::CHANGED))
        })
        .path(rip::ipv4::routes::route::inactive::PATH)
        .get_element_bool(|_instance, args| {
            let route = args.list_entry.as_ipv4_route().unwrap();
            Some(route.garbage_collect_task.is_some())
        })
        .build()
}

fn load_callbacks_ripng() -> Callbacks<Instance<Ripng>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(rip::ipv6::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .state
                    .neighbors
                    .values()
                    .map(ListEntry::Ipv6Neighbor);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(rip::ipv6::neighbors::neighbor::last_update::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_ipv6_neighbor().unwrap();
            Some(nbr.last_update)
        })
        .path(rip::ipv6::neighbors::neighbor::bad_packets_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_ipv6_neighbor().unwrap();
            Some(nbr.bad_packets_rcvd)
        })
        .path(rip::ipv6::neighbors::neighbor::bad_routes_rcvd::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_ipv6_neighbor().unwrap();
            Some(nbr.bad_routes_rcvd)
        })
        .path(rip::ipv6::routes::route::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter =
                    instance.state.routes.values().map(ListEntry::Ipv6Route);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(rip::ipv6::routes::route::next_hop::PATH)
        .get_element_ipv6(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            route.nexthop
        })
        .path(rip::ipv6::routes::route::interface::PATH)
        .get_element_string(|instance, args| {
            let instance = instance.as_up().unwrap();
            let route = args.list_entry.as_ipv6_route().unwrap();
            if let Some((_, iface)) =
                instance.core.interfaces.get_by_ifindex(route.ifindex)
            {
                Some(iface.core().name.clone())
            } else {
                None
            }
        })
        .path(rip::ipv6::routes::route::redistributed::PATH)
        .get_element_bool(|_instance, _args| Some(false))
        .path(rip::ipv6::routes::route::route_type::PATH)
        .get_element_string(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            Some(route.route_type.to_yang().into())
        })
        .path(rip::ipv6::routes::route::metric::PATH)
        .get_element_u8(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            Some(route.metric.get())
        })
        .path(rip::ipv6::routes::route::expire_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            route.timeout_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(rip::ipv6::routes::route::deleted::PATH)
        .get_element_bool(|_instance, _args| Some(false))
        .path(rip::ipv6::routes::route::need_triggered_update::PATH)
        .get_element_bool(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            Some(route.flags.contains(RouteFlags::CHANGED))
        })
        .path(rip::ipv6::routes::route::inactive::PATH)
        .get_element_bool(|_instance, args| {
            let route = args.list_entry.as_ipv6_route().unwrap();
            Some(route.garbage_collect_task.is_some())
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    const STATE_PATH: &'static str = V::STATE_PATH;

    type ListEntry<'a> = ListEntry<'a, V>;

    fn callbacks() -> Option<&'static Callbacks<Instance<V>>> {
        V::state_callbacks()
    }
}

// ===== impl ListEntry =====

impl<'a, V> ListEntryKind for ListEntry<'a, V>
where
    V: Version,
{
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::Interface(iface) => {
                use rip::interfaces::interface::list_keys;
                let keys = list_keys(&iface.core().name);
                Some(keys)
            }
            ListEntry::Ipv4Neighbor(nbr) => {
                use rip::ipv4::neighbors::neighbor::list_keys;
                let keys = list_keys(nbr.addr);
                Some(keys)
            }
            ListEntry::Ipv4Route(route) => {
                use rip::ipv4::routes::route::list_keys;
                let keys = list_keys(route.prefix);
                Some(keys)
            }
            ListEntry::Ipv6Neighbor(nbr) => {
                use rip::ipv6::neighbors::neighbor::list_keys;
                let keys = list_keys(nbr.addr);
                Some(keys)
            }
            ListEntry::Ipv6Route(route) => {
                use rip::ipv6::routes::route::list_keys;
                let keys = list_keys(route.prefix);
                Some(keys)
            }
        }
    }
}
