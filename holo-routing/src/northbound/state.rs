//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::sync::LazyLock as Lazy;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol;
use holo_northbound::paths::routing::ribs;
use holo_northbound::paths::routing::segment_routing::sr_mpls;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteOpaqueAttrs};
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::rib::{Route, RouteFlags};
use crate::{InstanceId, Master};

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    ProtocolInstance(ProtocolInstance<'a>),
    Rib(RibAddressFamily),
    Route(RouteDestination<'a>, &'a Route),
    Nexthop(&'a Nexthop),
    Label((usize, &'a Label)),
}

#[derive(Debug, new)]
pub struct ProtocolInstance<'a> {
    id: &'a InstanceId,
    nb_tx: &'a NbDaemonSender,
}

#[derive(Debug)]
pub enum RibAddressFamily {
    Ipv4,
    Ipv6,
    Mpls,
}

#[derive(Debug, EnumAsInner, new)]
pub enum RouteDestination<'a> {
    Ipv4(&'a Ipv4Network),
    Ipv6(&'a Ipv6Network),
    Label(&'a Label),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(control_plane_protocol::PATH)
        .get_iterate(|master, _args| {
            let iter = master
                .instances
                .iter()
                .map(|(instance_id, nb_tx)| {
                    ProtocolInstance::new(instance_id, nb_tx)
                })
                .map(ListEntry::ProtocolInstance);
            Some(Box::new(iter))
        })
        .path(control_plane_protocol::static_routes::ipv4::route::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(control_plane_protocol::static_routes::ipv4::route::next_hop::next_hop_list::next_hop::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(control_plane_protocol::static_routes::ipv6::route::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(control_plane_protocol::static_routes::ipv6::route::next_hop::next_hop_list::next_hop::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(sr_mpls::bindings::connected_prefix_sid_map::connected_prefix_sid::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(sr_mpls::srgb::srgb::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(sr_mpls::srlb::srlb::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(ribs::rib::PATH)
        .get_iterate(|_master, _args| {
            let iter = [
                RibAddressFamily::Ipv4,
                RibAddressFamily::Ipv6,
                RibAddressFamily::Mpls
            ]
            .into_iter()
            .map(ListEntry::Rib);
            Some(Box::new(iter))
        })
        .path(ribs::rib::routes::route::PATH)
        .get_iterate(|master, args| {
            let af = args.parent_list_entry.as_rib().unwrap();
            match af {
                RibAddressFamily::Ipv4 => {
                    let iter = master
                        .rib
                        .ipv4
                        .iter()
                        .flat_map(|(dest, routes)| {
                            routes.values()
                                .filter(|route| !route.flags.contains(RouteFlags::REMOVED))
                                .map(|route| {
                                let dest = RouteDestination::new_ipv4(dest);
                                ListEntry::Route(dest, route)
                            })
                        });
                    Some(Box::new(iter))
                }
                RibAddressFamily::Ipv6 => {
                    let iter = master
                        .rib
                        .ipv6
                        .iter()
                        .flat_map(|(dest, routes)| {
                            routes.values()
                                .filter(|route| !route.flags.contains(RouteFlags::REMOVED))
                                .map(|route| {
                                let dest = RouteDestination::new_ipv6(dest);
                                ListEntry::Route(dest, route)
                            })
                        });
                    Some(Box::new(iter))
                }
                RibAddressFamily::Mpls => {
                    let iter = master
                        .rib
                        .mpls
                        .iter()
                        .filter(|(_, route)| !route.flags.contains(RouteFlags::REMOVED))
                        .map(|(dest, route)| {
                            let dest = RouteDestination::new_label(dest);
                            ListEntry::Route(dest, route)
                        });
                    Some(Box::new(iter))
                }
            }
        })
        .path(ribs::rib::routes::route::ipv4_destination_prefix::PATH)
        .get_element_prefixv4(|_master, args| {
            let (dest, _) = args.list_entry.as_route().unwrap();
            if let RouteDestination::Ipv4(dest) = *dest {
                Some(*dest)
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::ipv6_destination_prefix::PATH)
        .get_element_prefixv6(|_master, args| {
            let (dest, _) = args.list_entry.as_route().unwrap();
            if let RouteDestination::Ipv6(dest) = *dest {
                Some(*dest)
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::mpls_destination_prefix::PATH)
        .get_element_string(|_master, args| {
            let (dest, _) = args.list_entry.as_route().unwrap();
            if let RouteDestination::Label(label) = *dest {
                Some(label.to_yang().into())
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::route_preference::PATH)
        .get_element_u32(|_master, args| {
            let (dest, route) = args.list_entry.as_route().unwrap();
            if let RouteDestination::Label(_) = dest {
                None
            } else {
                Some(route.distance)
            }
        })
        .path(ribs::rib::routes::route::next_hop::outgoing_interface::PATH)
        .get_element_string(|_master, _args| {
            // TODO: implement me!
            None
        })
        .path(ribs::rib::routes::route::next_hop::special_next_hop::PATH)
        .get_element_string(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();

            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                if let Nexthop::Special(nexthop) = nexthop {
                    return Some(nexthop.to_yang().into());
                }
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::ipv4_next_hop_address::PATH)
        .get_element_ipv4(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();

            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                if let Nexthop::Address {
                    addr: IpAddr::V4(addr),
                    ..
                }
                | Nexthop::Recursive {
                    addr: IpAddr::V4(addr),
                    ..
                } = nexthop
                {
                    return Some(*addr);
                }
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::ipv6_next_hop_address::PATH)
        .get_element_ipv6(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();

            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                if let Nexthop::Address {
                    addr: IpAddr::V6(addr),
                    ..
                }
                | Nexthop::Recursive {
                    addr: IpAddr::V6(addr),
                    ..
                } = nexthop
                {
                    return Some(*addr);
                }
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::mpls_label_stack::entry::PATH)
        .get_iterate(|_master, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();

            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                if let Nexthop::Address { labels, .. } = nexthop {
                    let iter = labels.iter().enumerate().map(ListEntry::Label);
                    return Some(Box::new(iter));
                }
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::mpls_label_stack::entry::label::PATH)
        .get_element_string(|_master, args| {
            let (_, label) = args.list_entry.as_label().unwrap();
            Some(label.to_yang().into())
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::PATH)
        .get_iterate(|_master, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();

            if route.nexthops.len() > 1 {
                let iter = route.nexthops.iter().map(ListEntry::Nexthop);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::outgoing_interface::PATH)
        .get_element_string(|_master, _args| {
            // TODO: implement me!
            None
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::ipv4_address::PATH)
        .get_element_ipv4(|_master, args| {
            let nexthop = args.list_entry.as_nexthop().unwrap();
            if let Nexthop::Address {
                addr: IpAddr::V4(addr),
                ..
            }
            | Nexthop::Recursive {
                addr: IpAddr::V4(addr),
                ..
            } = nexthop
            {
                return Some(*addr);
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::ipv6_address::PATH)
        .get_element_ipv6(|_master, args| {
            let nexthop = args.list_entry.as_nexthop().unwrap();
            if let Nexthop::Address {
                addr: IpAddr::V6(addr),
                ..
            }
            | Nexthop::Recursive {
                addr: IpAddr::V6(addr),
                ..
            } = nexthop
            {
                return Some(*addr);
            }

            None
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::PATH)
        .get_iterate(|_master, args| {
            let nexthop = args.parent_list_entry.as_nexthop().unwrap();
            if let Nexthop::Address { labels, .. } = nexthop {
                let iter = labels.iter().enumerate().map(ListEntry::Label);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::label::PATH)
        .get_element_string(|_master, args| {
            let (_, label) = args.list_entry.as_label().unwrap();
            Some(label.to_yang().into())
        })
        .path(ribs::rib::routes::route::source_protocol::PATH)
        .get_element_string(|_master, args| {
            let (dest, route) = args.list_entry.as_route().unwrap();
            if dest.is_label() {
                None
            } else {
                Some(route.protocol.to_yang().into())
            }
        })
        .path(ribs::rib::routes::route::active::PATH)
        .get_element_empty(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            route.flags.contains(RouteFlags::ACTIVE).then_some(())
        })
        .path(ribs::rib::routes::route::last_updated::PATH)
        .get_element_date_and_time(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            Some(route.last_updated)
        })
        .path(ribs::rib::routes::route::mpls_enabled::PATH)
        .get_element_bool(|_master, _args| {
            // TODO: implement me!
            None
        })
        .path(ribs::rib::routes::route::mpls_local_label::PATH)
        .get_element_string(|_master, _args| {
            // TODO: implement me!
            None
        })
        .path(ribs::rib::routes::route::route_context::PATH)
        .get_element_string(|_master, _args| {
            // TODO: implement me!
            None
        })
        .path(ribs::rib::routes::route::metric::PATH)
        .get_element_u32(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            if matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3) {
                Some(route.metric)
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::tag::PATH)
        .get_element_u32(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            if matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3) {
                route.tag
            } else {
                None
            }
        })
        .path(ribs::rib::routes::route::route_type::PATH)
        .get_element_string(|_master, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            if let RouteOpaqueAttrs::Ospf { route_type } = &route.opaque_attrs {
                Some(route_type.to_yang().into())
            } else {
                None
            }
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-routing:routing";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys = [
            holo_bfd::northbound::state::CALLBACKS.keys(),
            holo_bgp::northbound::state::CALLBACKS.keys(),
            holo_ldp::northbound::state::CALLBACKS.keys(),
            holo_ospf::northbound::state::CALLBACKS_OSPFV2.keys(),
            holo_ospf::northbound::state::CALLBACKS_OSPFV3.keys(),
            holo_rip::northbound::state::CALLBACKS_RIPV2.keys(),
            holo_rip::northbound::state::CALLBACKS_RIPNG.keys(),
        ]
        .concat();

        Some(keys)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::ProtocolInstance(instance) => {
                use control_plane_protocol::list_keys;
                let keys = list_keys(
                    instance.id.protocol.to_yang(),
                    &instance.id.name,
                );
                Some(keys)
            }
            ListEntry::Rib(rib_af) => {
                use ribs::rib::list_keys;
                let name = match rib_af {
                    RibAddressFamily::Ipv4 => "ipv4",
                    RibAddressFamily::Ipv6 => "ipv6",
                    RibAddressFamily::Mpls => "mpls",
                };
                let keys = list_keys(name);
                Some(keys)
            }
            ListEntry::Label((label_idx, _)) => {
                use ribs::rib::routes::route::next_hop::mpls_label_stack::entry::list_keys;
                let keys = list_keys(label_idx.to_string());
                Some(keys)
            }
            ListEntry::Route(..) | ListEntry::Nexthop(..) => {
                // Keyless lists.
                None
            }
        }
    }

    fn child_task(&self) -> Option<NbDaemonSender> {
        match self {
            ListEntry::ProtocolInstance(instance) => {
                Some(instance.nb_tx.clone())
            }
            _ => None,
        }
    }
}
