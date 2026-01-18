//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::NbDaemonSender;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::bier::{BfrId, Bsl};
use holo_utils::ip::JointPrefixMapExt;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKind};
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::northbound::configuration::NexthopSpecial;
use crate::northbound::yang_gen::{self, routing};
use crate::rib::{Route, RouteFlags};
use crate::{InstanceId, Master};

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

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

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {
    fn child_task(&self, module_name: &str) -> Option<NbDaemonSender> {
        match self {
            ListEntry::ProtocolInstance(instance) => match (module_name, instance.id.protocol) {
                ("ietf-bfd", Protocol::BFD)
                | ("ietf-bgp", Protocol::BGP)
                | ("ietf-igmp-mld", Protocol::IGMP)
                | ("ietf-isis", Protocol::ISIS)
                | ("ietf-mpls-ldp", Protocol::LDP)
                | ("ietf-ospf", Protocol::OSPFV2 | Protocol::OSPFV3)
                | ("ietf-rip", Protocol::RIPV2 | Protocol::RIPNG) => Some(instance.nb_tx.clone()),
                _ => None,
            },
            _ => None,
        }
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for routing::control_plane_protocols::control_plane_protocol::ControlPlaneProtocol<'a> {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.instances.iter().map(|(instance_id, instance)| ProtocolInstance::new(instance_id, &instance.nb_tx)).map(ListEntry::ProtocolInstance);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let instance = list_entry.as_protocol_instance().unwrap();
        Self {
            r#type: instance.id.protocol.to_yang(),
            name: Cow::Borrowed(&instance.id.name),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::Rib<'a> {
    fn iter(_master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = [RibAddressFamily::Ipv4, RibAddressFamily::Ipv6, RibAddressFamily::Mpls].into_iter().map(ListEntry::Rib);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let rib = list_entry.as_rib().unwrap();
        let name = match rib {
            RibAddressFamily::Ipv4 => "ipv4",
            RibAddressFamily::Ipv6 => "ipv6",
            RibAddressFamily::Mpls => "mpls",
        };
        Self {
            name: name.into(),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::Route<'a> {
    fn iter(master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let af = list_entry.as_rib().unwrap();
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
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let (dest, route) = list_entry.as_route().unwrap();
        // TODO: multiple unimplemented fields.
        Self {
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
            #[cfg(feature = "ospf")]
            ospf_metric: matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3).then_some(route.metric),
            #[cfg(feature = "ospf")]
            ospf_tag: if matches!(route.protocol, Protocol::OSPFV2 | Protocol::OSPFV3) { route.tag } else { None },
            #[cfg(feature = "ospf")]
            ospf_route_type: route.opaque_attrs.as_ospf().map(|route_type| route_type.to_yang()),
            #[cfg(feature = "isis")]
            isis_metric: (route.protocol == Protocol::ISIS).then_some(route.metric),
            #[cfg(feature = "isis")]
            isis_tag: None,
            #[cfg(feature = "isis")]
            isis_route_type: route.opaque_attrs.as_isis().map(|route_type| route_type.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Master> for routing::ribs::rib::routes::route::next_hop::NextHop<'a> {
    fn new(master: &'a Master, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, route) = list_entry.as_route().unwrap();
        let mut outgoing_interface = None;
        let mut ipv4_next_hop_address = None;
        let mut ipv6_next_hop_address = None;
        let mut special_next_hop = None;

        match route.kind {
            RouteKind::Unicast if route.nexthops.len() == 1 => {
                let nexthop = route.nexthops.first().unwrap();
                match nexthop {
                    Nexthop::Address {
                        ifindex,
                        addr,
                        ..
                    } => {
                        if let Some(iface) = master.interfaces.get_by_ifindex(*ifindex) {
                            outgoing_interface = Some(Cow::Borrowed(iface.name.as_str()));
                        }
                        match addr {
                            IpAddr::V4(addr) => ipv4_next_hop_address = Some(Cow::Borrowed(addr)),
                            IpAddr::V6(addr) => ipv6_next_hop_address = Some(Cow::Borrowed(addr)),
                        }
                    }
                    Nexthop::Interface {
                        ifindex,
                    } => {
                        if let Some(iface) = master.interfaces.get_by_ifindex(*ifindex) {
                            outgoing_interface = Some(Cow::Borrowed(&iface.name));
                        }
                    }
                    Nexthop::Recursive {
                        addr, ..
                    } => match addr {
                        IpAddr::V4(addr) => ipv4_next_hop_address = Some(Cow::Borrowed(addr)),
                        IpAddr::V6(addr) => ipv6_next_hop_address = Some(Cow::Borrowed(addr)),
                    },
                }
            }
            RouteKind::Blackhole => special_next_hop = Some(NexthopSpecial::Blackhole.to_yang()),
            RouteKind::Unreachable => special_next_hop = Some(NexthopSpecial::Unreachable.to_yang()),
            RouteKind::Prohibit => special_next_hop = Some(NexthopSpecial::Prohibit.to_yang()),
            _ => (),
        }

        Some(Self {
            outgoing_interface,
            ipv4_next_hop_address,
            ipv6_next_hop_address,
            special_next_hop,
        })
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::mpls_label_stack::entry::Entry<'a> {
    fn iter(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_route().unwrap();

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
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let (id, label) = list_entry.as_label().unwrap();
        Self {
            id: *id as u8,
            label: Some(label.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::next_hop_list::next_hop::NextHop<'a> {
    fn iter(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_route().unwrap();
        if route.nexthops.len() > 1 {
            let iter = route.nexthops.iter().map(ListEntry::Nexthop);
            Some(Box::new(iter))
        } else {
            None
        }
    }

    fn new(master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let nexthop = list_entry.as_nexthop().unwrap();
        let outgoing_interface = if let Nexthop::Address {
            ifindex, ..
        }
        | Nexthop::Interface {
            ifindex,
        } = nexthop
        {
            master.interfaces.get_by_ifindex(*ifindex).map(|iface| Cow::Borrowed(iface.name.as_str()))
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
        Self {
            outgoing_interface,
            ipv4_address,
            ipv6_address,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::Entry<'a> {
    fn iter(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nexthop = list_entry.as_nexthop().unwrap();
        if let Nexthop::Address {
            labels, ..
        } = nexthop
        {
            let iter = labels.iter().enumerate().map(ListEntry::Label);
            Some(Box::new(iter))
        } else {
            None
        }
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let (id, label) = list_entry.as_label().unwrap();
        Self {
            id: *id as u8,
            label: Some(label.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::Birt {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.birt.entries.keys().map(|(sd_id, _bfr_id, _bsl)| ListEntry::SubDomainId(*sd_id));
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let sub_domain_id = list_entry.as_sub_domain_id().unwrap();
        Self {
            sub_domain_id: *sub_domain_id,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::bfr_id::BfrId {
    fn iter(master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let sd_id_arg = *list_entry.as_sub_domain_id().unwrap();
        let iter = master.birt.entries.keys().filter_map(move |(sd_id, bfr_id, _bsl)| if *sd_id == sd_id_arg { Some(ListEntry::BfrId(*bfr_id)) } else { None });
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let bfr_id = list_entry.as_bfr_id().unwrap();
        Self {
            bfr_id: *bfr_id,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::bfr_id::birt_entry::BirtEntry<'a> {
    fn iter(master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let bfr_id_arg = *list_entry.as_bfr_id().unwrap();
        let iter = master
            .birt
            .entries
            .keys()
            .filter_map(move |(sd_id, bfr_id, bsl)| if *bfr_id == bfr_id_arg { Some(ListEntry::BirtKey((*sd_id, *bfr_id, *bsl))) } else { None });
        Some(Box::new(iter))
    }

    fn new(master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let birt_key = list_entry.as_birt_key().unwrap();
        let birt_entry = master.birt.entries.get(birt_key).unwrap();
        let bsl = birt_key.2;
        let bfr_prefix = Some(Cow::Borrowed(&birt_entry.bfr_prefix));
        let bfr_nbr = Some(Cow::Borrowed(&birt_entry.bfr_nbr));
        Self {
            bsl: bsl.into(),
            bfr_prefix,
            bfr_nbr,
        }
    }
}
