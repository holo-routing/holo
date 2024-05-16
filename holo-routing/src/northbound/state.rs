//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::LazyLock as Lazy;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol;
use holo_northbound::yang::routing::ribs;
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteOpaqueAttrs};
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::rib::{Route, RouteFlags};
use crate::{InstanceId, Master};

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    ProtocolInstance(ProtocolInstance<'a>),
    Rib(RibAddressFamily),
    Route(RouteDestination<'a>, &'a Route),
    Nexthop(&'a Nexthop),
    Label((usize, &'a Label)),
}

#[derive(Debug)]
#[derive(new)]
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

#[derive(Debug)]
#[derive(EnumAsInner, new)]
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
            let iter = master.instances.iter().map(|(instance_id, nb_tx)| ProtocolInstance::new(instance_id, nb_tx)).map(ListEntry::ProtocolInstance);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use control_plane_protocol::ControlPlaneProtocol;
            let instance = args.list_entry.as_protocol_instance().unwrap();
            Box::new(ControlPlaneProtocol {
                r#type: instance.id.protocol.to_yang(),
                name: instance.id.name.as_str().into(),
            })
        })
        .path(ribs::rib::PATH)
        .get_iterate(|_master, _args| {
            let iter = [RibAddressFamily::Ipv4, RibAddressFamily::Ipv6, RibAddressFamily::Mpls].into_iter().map(ListEntry::Rib);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use ribs::rib::Rib;
            let rib = args.list_entry.as_rib().unwrap();
            let name = match rib {
                RibAddressFamily::Ipv4 => "ipv4",
                RibAddressFamily::Ipv6 => "ipv6",
                RibAddressFamily::Mpls => "mpls",
            };
            Box::new(Rib {
                name: name.into(),
            })
        })
        .path(ribs::rib::routes::route::PATH)
        .get_iterate(|master, args| {
            let af = args.parent_list_entry.as_rib().unwrap();
            match af {
                RibAddressFamily::Ipv4 => {
                    let iter = master.rib.ipv4.iter().flat_map(|(dest, routes)| {
                        routes.values().filter(|route| !route.flags.contains(RouteFlags::REMOVED)).map(|route| {
                            let dest = RouteDestination::new_ipv4(dest);
                            ListEntry::Route(dest, route)
                        })
                    });
                    Some(Box::new(iter))
                }
                RibAddressFamily::Ipv6 => {
                    let iter = master.rib.ipv6.iter().flat_map(|(dest, routes)| {
                        routes.values().filter(|route| !route.flags.contains(RouteFlags::REMOVED)).map(|route| {
                            let dest = RouteDestination::new_ipv6(dest);
                            ListEntry::Route(dest, route)
                        })
                    });
                    Some(Box::new(iter))
                }
                RibAddressFamily::Mpls => {
                    let iter = master.rib.mpls.iter().filter(|(_, route)| !route.flags.contains(RouteFlags::REMOVED)).map(|(dest, route)| {
                        let dest = RouteDestination::new_label(dest);
                        ListEntry::Route(dest, route)
                    });
                    Some(Box::new(iter))
                }
            }
        })
        .get_object(|_master, args| {
            use ribs::rib::routes::route::Route;
            let (dest, route) = args.list_entry.as_route().unwrap();
            let mut route_preference = None;
            let mut source_protocol = None;
            let mut metric = None;
            let mut tag = None;
            let mut route_type = None;
            if !dest.is_label() {
                route_preference = Some(route.distance);
                source_protocol = Some(route.protocol.to_yang());
            }
            if matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3) {
                metric = Some(route.metric);
                tag = route.tag;
            }
            if let RouteOpaqueAttrs::Ospf {
                route_type: rtype,
            } = &route.opaque_attrs
            {
                route_type = Some(rtype.to_yang());
            }

            // TODO: multiple unimplemented fields.
            Box::new(Route {
                route_preference,
                source_protocol,
                active: route.flags.contains(RouteFlags::ACTIVE).then_some(()),
                last_updated: Some(&route.last_updated),
                ipv4_destination_prefix: dest.as_ipv4().copied().map(Cow::Borrowed),
                ipv6_destination_prefix: dest.as_ipv6().copied().map(Cow::Borrowed),
                mpls_enabled: None,
                mpls_local_label: None,
                mpls_destination_prefix: dest.as_label().map(|label| label.to_yang()),
                route_context: None,
                metric,
                tag,
                route_type,
            })
        })
        .path(ribs::rib::routes::route::next_hop::PATH)
        .get_object(|_master, args| {
            use ribs::rib::routes::route::next_hop::NextHop;
            let (_, route) = args.list_entry.as_route().unwrap();
            let mut ipv4_next_hop_address = None;
            let mut ipv6_next_hop_address = None;
            let mut special_next_hop = None;
            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                match nexthop {
                    Nexthop::Address {
                        addr, ..
                    }
                    | Nexthop::Recursive {
                        addr, ..
                    } => match addr {
                        IpAddr::V4(addr) => ipv4_next_hop_address = Some(Cow::Borrowed(addr)),
                        IpAddr::V6(addr) => ipv6_next_hop_address = Some(Cow::Borrowed(addr)),
                    },
                    Nexthop::Special(nexthop) => {
                        special_next_hop = Some(nexthop.to_yang());
                    }
                    _ => (),
                };
            }
            Box::new(NextHop {
                // TODO
                outgoing_interface: None,
                ipv4_next_hop_address,
                ipv6_next_hop_address,
                special_next_hop,
            })
        })
        .path(ribs::rib::routes::route::next_hop::mpls_label_stack::entry::PATH)
        .get_iterate(|_master, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();

            if route.nexthops.len() == 1 {
                let nexthop = route.nexthops.first().unwrap();
                if let Nexthop::Address {
                    labels, ..
                } = nexthop
                {
                    let iter = labels.iter().enumerate().map(ListEntry::Label);
                    return Some(Box::new(iter));
                }
            }

            None
        })
        .get_object(|_master, args| {
            use ribs::rib::routes::route::next_hop::mpls_label_stack::entry::Entry;
            let (id, label) = args.list_entry.as_label().unwrap();
            Box::new(Entry {
                id: *id as u8,
                label: Some(label.to_yang()),
            })
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
        .get_object(|_master, args| {
            use ribs::rib::routes::route::next_hop::next_hop_list::next_hop::NextHop;
            let nexthop = args.list_entry.as_nexthop().unwrap();

            let (ipv4_address, ipv6_address) = match nexthop {
                Nexthop::Address {
                    addr, ..
                }
                | Nexthop::Recursive {
                    addr, ..
                } => match addr {
                    IpAddr::V4(addr) => (Some(Cow::Borrowed(addr)), None),
                    IpAddr::V6(addr) => (None, Some(Cow::Borrowed(addr))),
                },
                _ => (None, None),
            };
            Box::new(NextHop {
                // TODO
                outgoing_interface: None,
                ipv4_address,
                ipv6_address,
            })
        })
        .path(ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::PATH)
        .get_iterate(|_master, args| {
            let nexthop = args.parent_list_entry.as_nexthop().unwrap();
            if let Nexthop::Address {
                labels, ..
            } = nexthop
            {
                let iter = labels.iter().enumerate().map(ListEntry::Label);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_master, args| {
            use ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::Entry;
            let (id, label) = args.list_entry.as_label().unwrap();
            Box::new(Entry {
                id: *id as u8,
                label: Some(label.to_yang()),
            })
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
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "bfd")]
            holo_bfd::northbound::state::CALLBACKS.keys(),
            #[cfg(feature = "bgp")]
            holo_bgp::northbound::state::CALLBACKS.keys(),
            #[cfg(feature = "ldp")]
            holo_ldp::northbound::state::CALLBACKS.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::state::CALLBACKS_OSPFV2.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::state::CALLBACKS_OSPFV3.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::state::CALLBACKS_RIPV2.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::state::CALLBACKS_RIPNG.keys(),
        ];

        Some(keys.concat())
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn child_task(&self) -> Option<NbDaemonSender> {
        match self {
            ListEntry::ProtocolInstance(instance) => {
                Some(instance.nb_tx.clone())
            }
            _ => None,
        }
    }
}
