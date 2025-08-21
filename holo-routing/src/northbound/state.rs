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
use holo_northbound::yang::routing::{birts, ribs};
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_utils::bier::{BfrId, Bsl};
use holo_utils::ip::JointPrefixMapExt;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKind};
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::northbound::configuration::NexthopSpecial;
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
    SubDomainId(u8),
    BfrId(BfrId),
    // FIXME: Should be Bsl but issue with yang-rs
    Bsl(u8),
    BirtEntry((u8, IpAddr, IpAddr)),
    BirtKey((u8, u16, Bsl)),
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
            let iter = master.instances.iter().map(|(instance_id, instance)| ProtocolInstance::new(instance_id, &instance.nb_tx)).map(ListEntry::ProtocolInstance);
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
                    let iter = master.rib.ip.ipv4().iter().flat_map(|(dest, routes)| {
                        routes.values().filter(|route| !route.flags.contains(RouteFlags::REMOVED)).map(|route| {
                            let dest = RouteDestination::new_ipv4(dest);
                            ListEntry::Route(dest, route)
                        })
                    });
                    Some(Box::new(iter))
                }
                RibAddressFamily::Ipv6 => {
                    let iter = master.rib.ip.ipv6().iter().flat_map(|(dest, routes)| {
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
            // TODO: multiple unimplemented fields.
            Box::new(Route {
                route_preference: (!dest.is_label()).then_some(route.distance),
                source_protocol: (!dest.is_label()).then_some(route.protocol.to_yang()),
                active: route.flags.contains(RouteFlags::ACTIVE).then_some(()),
                last_updated: Some(Cow::Borrowed(&route.last_updated)),
                ipv4_destination_prefix: dest.as_ipv4().copied().map(Cow::Borrowed),
                ipv6_destination_prefix: dest.as_ipv6().copied().map(Cow::Borrowed),
                mpls_enabled: None,
                mpls_local_label: None,
                mpls_destination_prefix: dest.as_label().map(|label| label.to_yang()),
                route_context: None,
                ospf_metric: matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3).then_some(route.metric),
                ospf_tag: if matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3) { route.tag } else { None },
                ospf_route_type: route.opaque_attrs.as_ospf().map(|route_type| route_type.to_yang()),
                isis_metric: (route.protocol == Protocol::ISIS).then_some(route.metric),
                isis_tag: None,
                isis_route_type: route.opaque_attrs.as_isis().map(|route_type| route_type.to_yang()),
            })
        })
        .path(ribs::rib::routes::route::next_hop::PATH)
        .get_object(|master, args| {
            use ribs::rib::routes::route::next_hop::NextHop;
            let (_, route) = args.list_entry.as_route().unwrap();
            let mut outgoing_interface = None;
            let mut ipv4_next_hop_address = None;
            let mut ipv6_next_hop_address = None;
            let mut special_next_hop = None;

            match route.kind {
                RouteKind::Unicast if route.nexthops.len() == 1 => {
                    let nexthop = route.nexthops.first().unwrap();
                    match nexthop {
                        Nexthop::Address { ifindex, addr, .. } => {
                            if let Some(iface) =
                                master.interfaces.get_by_ifindex(*ifindex)
                            {
                                outgoing_interface =
                                    Some(Cow::Borrowed(iface.name.as_str()));
                            }
                            match addr {
                                IpAddr::V4(addr) => {
                                    ipv4_next_hop_address =
                                        Some(Cow::Borrowed(addr))
                                }
                                IpAddr::V6(addr) => {
                                    ipv6_next_hop_address =
                                        Some(Cow::Borrowed(addr))
                                }
                            }
                        }
                        Nexthop::Interface { ifindex } => {
                            if let Some(iface) =
                                master.interfaces.get_by_ifindex(*ifindex)
                            {
                                outgoing_interface =
                                    Some(Cow::Borrowed(iface.name.as_str()));
                            }
                        }
                        Nexthop::Recursive { addr, .. } => match addr {
                            IpAddr::V4(addr) => {
                                ipv4_next_hop_address =
                                    Some(Cow::Borrowed(addr))
                            }
                            IpAddr::V6(addr) => {
                                ipv6_next_hop_address =
                                    Some(Cow::Borrowed(addr))
                            }
                        },
                    }
                }
                RouteKind::Blackhole => {
                    special_next_hop = Some(NexthopSpecial::Blackhole.to_yang())
                }
                RouteKind::Unreachable => {
                    special_next_hop =
                        Some(NexthopSpecial::Unreachable.to_yang())
                }
                RouteKind::Prohibit => {
                    special_next_hop = Some(NexthopSpecial::Prohibit.to_yang())
                }
		_ => (),
            }

            Box::new(NextHop {
                outgoing_interface,
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
        .get_object(|master, args| {
            use ribs::rib::routes::route::next_hop::next_hop_list::next_hop::NextHop;
            let nexthop = args.list_entry.as_nexthop().unwrap();
            let outgoing_interface =
                if let Nexthop::Address { ifindex, .. }
                | Nexthop::Interface { ifindex } = nexthop
                {
                    master
                        .interfaces
                        .get_by_ifindex(*ifindex)
                        .map(|iface| Cow::Borrowed(iface.name.as_str()))
                } else {
                    None
                };
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
                outgoing_interface,
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
        .path(birts::birt::PATH)
        .get_iterate(|master, _args| {
            let iter = master.birt.entries.keys().map(|(sd_id, _bfr_id, _bsl)| ListEntry::SubDomainId(*sd_id));
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use birts::birt::Birt;
            let sub_domain_id = args.list_entry.as_sub_domain_id().unwrap();
            Box::new(Birt{sub_domain_id: *sub_domain_id})
        })
        .path(birts::birt::bfr_id::PATH)
        .get_iterate(|master, args| {
            let sd_id_arg = *args.parent_list_entry.as_sub_domain_id().unwrap();
            let iter = master.birt.entries.keys().filter_map(move |(sd_id, bfr_id, _bsl)| {
                if *sd_id == sd_id_arg {
                    Some(ListEntry::BfrId(*bfr_id))
                } else {
                    None
                }
            });
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use birts::birt::bfr_id::BfrId;
            let bfr_id = args.list_entry.as_bfr_id().unwrap();
            Box::new(BfrId{bfr_id: *bfr_id})
        })
        .path(birts::birt::bfr_id::birt_entry::PATH)
        .get_iterate(|master, args| {
            let bfr_id_arg = *args.parent_list_entry.as_bfr_id().unwrap();
            let iter = master.birt.entries.keys().filter_map(move |(sd_id, bfr_id, bsl)| {
                if *bfr_id == bfr_id_arg {
                    Some(ListEntry::BirtKey((*sd_id, *bfr_id, *bsl)))
                } else {
                    None
                }
            });
            Some(Box::new(iter))
        })
        .get_object(|master, args| {
            use birts::birt::bfr_id::birt_entry::BirtEntry;
            let birt_key = args.list_entry.as_birt_key().unwrap();
            let birt_entry = master.birt.entries.get(birt_key).unwrap();
            let bsl = birt_key.2;
            let bfr_prefix = Some(Cow::Borrowed(&birt_entry.bfr_prefix));
            let bfr_nbr = Some(Cow::Borrowed(&birt_entry.bfr_nbr));
            Box::new(BirtEntry{bsl: bsl.into(), bfr_prefix, bfr_nbr})
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "bfd")]
            holo_bfd::northbound::state::CALLBACKS.keys(),
            #[cfg(feature = "bgp")]
            holo_bgp::northbound::state::CALLBACKS.keys(),
            #[cfg(feature = "isis")]
            holo_isis::northbound::state::CALLBACKS.keys(),
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

impl ListEntryKind for ListEntry<'_> {
    fn child_task(&self, module_name: &str) -> Option<NbDaemonSender> {
        match self {
            ListEntry::ProtocolInstance(instance) => {
                match (module_name, instance.id.protocol) {
                    ("ietf-bfd", Protocol::BFD)
                    | ("ietf-bgp", Protocol::BGP)
                    | ("ietf-isis", Protocol::ISIS)
                    | ("ietf-mpls-ldp", Protocol::LDP)
                    | ("ietf-ospf", Protocol::OSPFV2 | Protocol::OSPFV3)
                    | ("ietf-rip", Protocol::RIPV2 | Protocol::RIPNG) => {
                        Some(instance.nb_tx.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
