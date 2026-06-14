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
use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
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
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        "/ietf-routing:routing".to_owned()
    }
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
pub enum RouteDestination {
    Ipv4(Ipv4Network),
    Ipv6(Ipv6Network),
    Label(Label),
}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for routing::control_plane_protocols::control_plane_protocol::ControlPlaneProtocol<'a> {
    type ParentListEntry = ();
    type ListEntry = ProtocolInstance<'a>;

    fn iter(master: &'a Master, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.instances.iter().map(|(instance_id, instance)| ProtocolInstance::new(instance_id, &instance.nb_tx));
        Some(iter)
    }

    fn new(_master: &'a Master, instance: &Self::ListEntry) -> Self {
        Self {
            r#type: instance.id.protocol.to_yang(),
            name: Cow::Borrowed(&instance.id.name),
        }
    }

    fn child_task(instance: &Self::ListEntry, module_name: &str) -> Option<NbDaemonSender> {
        match (module_name, instance.id.protocol) {
            ("ietf-bfd", Protocol::BFD)
            | ("ietf-bgp", Protocol::BGP)
            | ("ietf-igmp-mld", Protocol::IGMP)
            | ("ietf-isis", Protocol::ISIS)
            | ("ietf-mpls-ldp", Protocol::LDP)
            | ("ietf-ospf", Protocol::OSPFV2 | Protocol::OSPFV3)
            | ("ietf-rip", Protocol::RIPV2 | Protocol::RIPNG) => Some(instance.nb_tx.clone()),
            _ => None,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::Rib<'a> {
    type ParentListEntry = ();
    type ListEntry = RibAddressFamily;

    fn iter(_master: &'a Master, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = [RibAddressFamily::Ipv4, RibAddressFamily::Ipv6, RibAddressFamily::Mpls].into_iter();
        Some(iter)
    }

    fn new(_master: &'a Master, rib: &Self::ListEntry) -> Self {
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
    type ParentListEntry = RibAddressFamily;
    type ListEntry = (RouteDestination, &'a Route);

    fn iter(master: &'a Master, af: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter: Box<dyn Iterator<Item = Self::ListEntry> + 'a> = match af {
            RibAddressFamily::Ipv4 => {
                let iter = master.rib.ip.ipv4().iter().flat_map(|(dest, routes)| {
                    routes.values().filter(|route| !route.flags.contains(RouteFlags::REMOVED)).map(move |route| {
                        let dest = RouteDestination::new_ipv4(dest);
                        (dest, route)
                    })
                });
                Box::new(iter)
            }
            RibAddressFamily::Ipv6 => {
                let iter = master.rib.ip.ipv6().iter().flat_map(|(dest, routes)| {
                    routes.values().filter(|route| !route.flags.contains(RouteFlags::REMOVED)).map(move |route| {
                        let dest = RouteDestination::new_ipv6(dest);
                        (dest, route)
                    })
                });
                Box::new(iter)
            }
            RibAddressFamily::Mpls => {
                let iter = master.rib.mpls.iter().filter(|(_, route)| !route.flags.contains(RouteFlags::REMOVED)).map(|(dest, route)| {
                    let dest = RouteDestination::new_label(*dest);
                    (dest, route)
                });
                Box::new(iter)
            }
        };
        Some(iter)
    }

    fn new(_master: &'a Master, (dest, route): &Self::ListEntry) -> Self {
        // TODO: multiple unimplemented fields.
        Self {
            route_preference: (!dest.is_label()).then_some(route.distance),
            source_protocol: (!dest.is_label()).then_some(route.protocol.to_yang()),
            active: route.flags.contains(RouteFlags::ACTIVE).then_some(()),
            last_updated: Some(route.last_updated),
            v4ur_destination_prefix: dest.as_ipv4().copied(),
            v6ur_destination_prefix: dest.as_ipv6().copied(),
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
        }
    }
}

impl<'a> YangContainer<'a, Master> for routing::ribs::rib::routes::route::next_hop::NextHop<'a> {
    type ParentListEntry = (RouteDestination, &'a Route);

    fn new(master: &'a Master, (_, route): &Self::ParentListEntry) -> Option<Self> {
        let mut outgoing_interface = None;
        let mut v4ur_next_hop_address = None;
        let mut v6ur_next_hop_address = None;
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
                            IpAddr::V4(addr) => v4ur_next_hop_address = Some(*addr),
                            IpAddr::V6(addr) => v6ur_next_hop_address = Some(*addr),
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
                        IpAddr::V4(addr) => v4ur_next_hop_address = Some(*addr),
                        IpAddr::V6(addr) => v6ur_next_hop_address = Some(*addr),
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
            v4ur_next_hop_address,
            v6ur_next_hop_address,
            special_next_hop,
        })
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::mpls_label_stack::entry::Entry<'a> {
    type ParentListEntry = (RouteDestination, &'a Route);
    type ListEntry = (usize, &'a Label);

    fn iter(_master: &'a Master, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if route.nexthops.len() == 1 {
            let nexthop = route.nexthops.first().unwrap();
            if let Nexthop::Address {
                labels, ..
            } = nexthop
            {
                let iter = labels.iter().enumerate();
                return Some(iter);
            }
        }

        None
    }

    fn new(_master: &'a Master, (id, label): &Self::ListEntry) -> Self {
        Self {
            id: *id as u8,
            label: Some(label.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::next_hop_list::next_hop::NextHop<'a> {
    type ParentListEntry = (RouteDestination, &'a Route);
    type ListEntry = &'a Nexthop;

    fn iter(_master: &'a Master, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if route.nexthops.len() > 1 {
            let iter = route.nexthops.iter();
            Some(iter)
        } else {
            None
        }
    }

    fn new(master: &'a Master, nexthop: &Self::ListEntry) -> Self {
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
        let (v4ur_address, v6ur_address) = match nexthop {
            Nexthop::Address {
                addr, ..
            }
            | Nexthop::Recursive {
                addr, ..
            } => match addr {
                IpAddr::V4(addr) => (Some(*addr), None),
                IpAddr::V6(addr) => (None, Some(*addr)),
            },
            _ => (None, None),
        };
        Self {
            outgoing_interface,
            v4ur_address,
            v6ur_address,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::ribs::rib::routes::route::next_hop::next_hop_list::next_hop::mpls_label_stack::entry::Entry<'a> {
    type ParentListEntry = &'a Nexthop;
    type ListEntry = (usize, &'a Label);

    fn iter(_master: &'a Master, nexthop: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if let Nexthop::Address {
            labels, ..
        } = nexthop
        {
            let iter = labels.iter().enumerate();
            Some(iter)
        } else {
            None
        }
    }

    fn new(_master: &'a Master, (id, label): &Self::ListEntry) -> Self {
        Self {
            id: *id as u8,
            label: Some(label.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::Birt {
    type ParentListEntry = ();
    type ListEntry = u8;

    fn iter(master: &'a Master, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.birt.entries.keys().map(|(sd_id, _bfr_id, _bsl)| *sd_id);
        Some(iter)
    }

    fn new(_master: &'a Master, sub_domain_id: &Self::ListEntry) -> Self {
        Self {
            sub_domain_id: *sub_domain_id,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::bfr_id::BfrId {
    type ParentListEntry = u8;
    type ListEntry = BfrId;

    fn iter(master: &'a Master, &sd_id_arg: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.birt.entries.keys().filter_map(move |(sd_id, bfr_id, _bsl)| if *sd_id == sd_id_arg { Some(*bfr_id) } else { None });
        Some(iter)
    }

    fn new(_master: &'a Master, bfr_id: &Self::ListEntry) -> Self {
        Self {
            bfr_id: *bfr_id,
        }
    }
}

impl<'a> YangList<'a, Master> for routing::birts::birt::bfr_id::birt_entry::BirtEntry {
    type ParentListEntry = BfrId;
    type ListEntry = (u8, BfrId, Bsl);

    fn iter(master: &'a Master, &bfr_id_arg: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.birt.entries.keys().filter_map(move |(sd_id, bfr_id, bsl)| if *bfr_id == bfr_id_arg { Some((*sd_id, *bfr_id, *bsl)) } else { None });
        Some(iter)
    }

    fn new(master: &'a Master, birt_key: &Self::ListEntry) -> Self {
        let birt_entry = master.birt.entries.get(birt_key).unwrap();
        let bsl = birt_key.2;
        let bfr_prefix = Some(birt_entry.bfr_prefix);
        let bfr_nbr = Some(birt_entry.bfr_nbr);
        Self {
            bsl: bsl.into(),
            bfr_prefix,
            bfr_nbr,
        }
    }
}
