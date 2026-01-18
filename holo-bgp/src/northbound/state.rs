//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::{Arc, atomic};

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::bgp::AfiSafi;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};
use prefix_trie::PrefixMap;

use crate::instance::Instance;
use crate::neighbor::{Neighbor, fsm};
use crate::northbound::yang_gen::{self, bgp};
use crate::packet::attribute::{AsPathSegment, BaseAttrs, Comms, ExtComms, Extv6Comms, LargeComms, UnknownAttr};
use crate::packet::consts::{Afi, AttrFlags, Safi};
use crate::packet::message::{AddPathTuple, Capability};
use crate::rib::{AttrSet, Destination, LocalRoute, Route};

pub static AFI_SAFIS: [AfiSafi; 2] = [AfiSafi::Ipv4Unicast, AfiSafi::Ipv6Unicast];

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    GlobalAfiSafi(AfiSafi),
    Neighbor(&'a Neighbor),
    NeighborAfiSafi(&'a Neighbor, AfiSafi),
    Capability(usize, &'a Capability),
    AddPathTuple(&'a AddPathTuple),
    Rib(AfiSafi),
    RibBaseAttrs(&'a Arc<AttrSet<BaseAttrs>>),
    RibComms(&'a Arc<AttrSet<Comms>>),
    RibExtComms(&'a Arc<AttrSet<ExtComms>>),
    RibExtv6Comms(&'a Arc<AttrSet<Extv6Comms>>),
    RibLargeComms(&'a Arc<AttrSet<LargeComms>>),
    RibAsPathSegment(&'a AsPathSegment),
    RibNeighbor(&'a Neighbor),
    RibV4LocRoute(&'a Ipv4Network, &'a Box<LocalRoute>),
    RibV6LocRoute(&'a Ipv6Network, &'a Box<LocalRoute>),
    RibV4Route(&'a Ipv4Network, &'a Route),
    RibV6Route(&'a Ipv6Network, &'a Route),
    RouteUnknownAttr(&'a UnknownAttr),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangList<'a, Instance> for bgp::global::afi_safis::afi_safi::AfiSafi<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let _ = instance.state.as_ref()?;
        let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi)).map(ListEntry::GlobalAfiSafi);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let afi_safi = list_entry.as_global_afi_safi().unwrap();
        Self {
            name: afi_safi.to_yang(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::global::afi_safis::afi_safi::statistics::Statistics {
    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let afi_safi = list_entry.as_global_afi_safi().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let total_prefixes = match afi_safi {
            AfiSafi::Ipv4Unicast => rib.tables.ipv4_unicast.prefixes.len(),
            AfiSafi::Ipv6Unicast => rib.tables.ipv6_unicast.prefixes.len(),
        };
        Some(Self {
            total_paths: None, // TODO
            total_prefixes: Some(total_prefixes as u32),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::global::statistics::Statistics {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let rib = &instance.state.as_ref()?.rib;
        let total_ipv4 = rib.tables.ipv4_unicast.prefixes.len();
        let total_ipv6 = rib.tables.ipv6_unicast.prefixes.len();
        let total_prefixes = total_ipv4 as u32 + total_ipv6 as u32;
        Some(Self {
            total_paths: None, // TODO
            total_prefixes: Some(total_prefixes),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = instance.neighbors.values().map(ListEntry::Neighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let nbr = list_entry.as_neighbor().unwrap();
        let mut local_address = None;
        let mut local_port = None;
        let mut remote_port = None;
        if let Some(conn_info) = &nbr.conn_info {
            local_address = Some(Cow::Borrowed(&conn_info.local_addr));
            local_port = Some(conn_info.local_port);
            remote_port = Some(conn_info.remote_port);
        }
        Self {
            remote_address: Cow::Borrowed(&nbr.remote_addr),
            local_address,
            local_port: local_port.ignore_in_testing(),
            remote_port: remote_port.ignore_in_testing(),
            peer_type: Some(nbr.peer_type.to_yang()),
            identifier: nbr.identifier.map(Cow::Owned),
            dynamically_configured: None,
            session_state: Some(nbr.state.to_yang()),
            last_established: nbr.last_established.as_ref().map(Cow::Borrowed).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::timers::Timers {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            negotiated_hold_time: nbr.holdtime_nego,
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::afi_safis::afi_safi::AfiSafi<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_neighbor().unwrap();

        // If the peer doesn't support BGP capabilities, the IPv4 unicast
        // address-family is enabled by default.
        if nbr.capabilities_nego.is_empty() {
            let iter = std::iter::once(ListEntry::NeighborAfiSafi(nbr, AfiSafi::Ipv4Unicast));
            return Some(Box::new(iter));
        }

        let iter = nbr.capabilities_nego.iter().filter_map(|cap| {
            let (afi, safi) = cap.as_multi_protocol()?;
            let afi_safi = afi_safi_tuple(*afi, *safi)?;
            Some(ListEntry::NeighborAfiSafi(nbr, afi_safi))
        });
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (_, afi_safi) = list_entry.as_neighbor_afi_safi().unwrap();
        Self {
            name: afi_safi.to_yang(),
            active: None,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::Prefixes {
    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (nbr, afi_safi) = list_entry.as_neighbor_afi_safi().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        fn count_stats<K>(prefixes: &PrefixMap<K, Destination>, addr: &IpAddr) -> (u32, u32, u32) {
            prefixes
                .values()
                .filter_map(|dest| dest.adj_rib.get(addr))
                .fold((0, 0, 0), |(r, s, i), adj| (r + adj.in_pre().is_some() as u32, s + adj.out_post().is_some() as u32, i + adj.in_post().is_some() as u32))
        }
        let (r, s, i) = match afi_safi {
            AfiSafi::Ipv4Unicast => count_stats(&rib.tables.ipv4_unicast.prefixes, &nbr.remote_addr),
            AfiSafi::Ipv6Unicast => count_stats(&rib.tables.ipv6_unicast.prefixes, &nbr.remote_addr),
        };
        Some(Self {
            received: Some(r),
            sent: Some(s),
            installed: Some(i),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::Capabilities<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        let negotiated_capabilities = nbr.capabilities_nego.iter().map(|cap| cap.code().to_yang());
        Some(Self {
            negotiated_capabilities: Some(Box::new(negotiated_capabilities)),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::AdvertisedCapabilities<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_neighbor().unwrap();
        let iter = nbr.capabilities_adv.iter().enumerate().map(|(index, cap)| ListEntry::Capability(index, cap));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (index, cap) = list_entry.as_capability().unwrap();
        Self {
            code: cap.code() as u8,
            index: *index as u8,
            name: Some(cap.code().to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::Mpbgp<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, cap) = list_entry.as_capability().unwrap();
        let (c_afi, c_safi) = cap.as_multi_protocol()?;
        Some(Self {
            afi: Some(c_afi.to_yang()),
            safi: Some(c_safi.to_yang()),
            name: afi_safi_tuple(*c_afi, *c_safi).map(|afi_safi| afi_safi.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::asn32::Asn32 {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, cap) = list_entry.as_capability().unwrap();
        Some(Self {
            r#as: cap.as_four_octet_as_number().copied(),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::AfiSafis<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, cap) = list_entry.as_capability().unwrap();
        let cap = cap.as_add_path()?;
        let iter = cap.iter().map(ListEntry::AddPathTuple);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let ap = list_entry.as_add_path_tuple().unwrap();
        Self {
            afi: Some(ap.afi.to_yang()),
            safi: Some(ap.safi.to_yang()),
            mode: Some(ap.mode.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::ReceivedCapabilities<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_neighbor().unwrap();
        let iter = nbr.capabilities_rcvd.iter().enumerate().map(|(index, cap)| ListEntry::Capability(index, cap));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (index, cap) = list_entry.as_capability().unwrap();
        Self {
            code: cap.code() as u8,
            index: *index as u8,
            name: Some(cap.code().to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::Mpbgp<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, cap) = list_entry.as_capability().unwrap();
        let (c_afi, c_safi) = cap.as_multi_protocol()?;
        Some(Self {
            afi: Some(c_afi.to_yang()),
            safi: Some(c_safi.to_yang()),
            name: afi_safi_tuple(*c_afi, *c_safi).map(|afi_safi| afi_safi.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::asn32::Asn32 {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, cap) = list_entry.as_capability().unwrap();
        Some(Self {
            r#as: cap.as_four_octet_as_number().copied(),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::AfiSafis<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, cap) = list_entry.as_capability().unwrap();
        let cap = cap.as_add_path()?;
        let iter = cap.iter().map(ListEntry::AddPathTuple);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let ap = list_entry.as_add_path_tuple().unwrap();
        Self {
            afi: Some(ap.afi.to_yang()),
            safi: Some(ap.safi.to_yang()),
            mode: Some(ap.mode.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::errors::received::Received<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        let (time, notif) = nbr.notification_rcvd.as_ref()?;
        Some(Self {
            last_notification: Some(Cow::Borrowed(time)),
            last_error: Some(notif.to_yang()),
            last_error_code: Some(notif.error_code),
            last_error_subcode: Some(notif.error_subcode),
            last_error_data: Some(notif.data.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::errors::sent::Sent<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        let (time, notif) = nbr.notification_sent.as_ref()?;
        Some(Self {
            last_notification: Some(Cow::Borrowed(time)),
            last_error: Some(notif.to_yang()),
            last_error_code: Some(notif.error_code),
            last_error_subcode: Some(notif.error_subcode),
            last_error_data: Some(notif.data.as_ref()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::statistics::Statistics {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            established_transitions: Some(nbr.statistics.established_transitions).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::statistics::messages::Messages {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            total_received: Some(nbr.statistics.msgs_rcvd.total.load(atomic::Ordering::Relaxed)),
            total_sent: Some(nbr.statistics.msgs_sent.total.load(atomic::Ordering::Relaxed)),
            updates_received: Some(nbr.statistics.msgs_rcvd.updates),
            updates_sent: Some(nbr.statistics.msgs_sent.updates),
            erroneous_updates_withdrawn: Some(nbr.statistics.erroneous_updates_withdrawn),
            erroneous_updates_attribute_discarded: Some(nbr.statistics.erroneous_updates_attribute_discarded),
            in_update_elapsed_time: Some(nbr.statistics.in_update_elapsed_time.as_secs() as u32),
            notifications_received: Some(nbr.statistics.msgs_rcvd.notifications),
            notifications_sent: Some(nbr.statistics.msgs_sent.notifications),
            route_refreshes_received: Some(nbr.statistics.msgs_rcvd.route_refreshes),
            route_refreshes_sent: Some(nbr.statistics.msgs_sent.route_refreshes),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::attr_sets::attr_set::AttrSet {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.base.tree.values().map(ListEntry::RibBaseAttrs);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        Self {
            index: attr_set.index,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::Attributes<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        let cluster_list = attr_set.value.cluster_list.as_ref().map(|clist| Box::new(clist.0.iter().map(Cow::Borrowed)) as _);
        Some(Self {
            origin: Some(attr_set.value.origin.to_yang()),
            next_hop: attr_set.value.nexthop.as_ref().map(Cow::Borrowed),
            link_local_next_hop: attr_set.value.ll_nexthop.as_ref().map(Cow::Borrowed),
            med: attr_set.value.med,
            local_pref: attr_set.value.local_pref,
            atomic_aggregate: attr_set.value.atomic_aggregate.map(|_| true),
            originator_id: attr_set.value.originator_id.map(Cow::Owned),
            cluster_list,
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::as_path::segment::Segment<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        let iter = attr_set.value.as_path.segments.iter().map(ListEntry::RibAsPathSegment);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let aspath_seg = list_entry.as_rib_as_path_segment().unwrap();
        let members = aspath_seg.members.iter().copied();
        Self {
            r#type: Some(aspath_seg.seg_type.to_yang()),
            member: Some(Box::new(members)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::Segment<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        let as4_path = attr_set.value.as4_path.as_ref()?;
        let iter = as4_path.segments.iter().map(ListEntry::RibAsPathSegment);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let aspath_seg = list_entry.as_rib_as_path_segment().unwrap();
        let members = aspath_seg.members.iter().copied();
        Self {
            r#type: Some(aspath_seg.seg_type.to_yang()),
            member: Some(Box::new(members)),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::aggregator::Aggregator<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        let aggregator = attr_set.value.aggregator.as_ref()?;
        Some(Self {
            r#as: Some(aggregator.asn),
            identifier: Some(Cow::Owned(aggregator.identifier)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::aggregator4::Aggregator4<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let attr_set = list_entry.as_rib_base_attrs().unwrap();
        let as4_aggregator = attr_set.value.as4_aggregator.as_ref()?;
        Some(Self {
            as4: Some(as4_aggregator.asn),
            identifier: Some(Cow::Owned(as4_aggregator.identifier)),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::communities::community::Community<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.comm.tree.values().map(ListEntry::RibComms);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let comms = list_entry.as_rib_comms().unwrap();
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            community: Some(Box::new(communities)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::ext_communities::ext_community::ExtCommunity<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.ext_comm.tree.values().map(ListEntry::RibExtComms);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let comms = list_entry.as_rib_ext_comms().unwrap();
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            ext_community: Some(Box::new(communities)),
            ext_community_raw: None, // TODO
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::ipv6_ext_communities::ipv6_ext_community::Ipv6ExtCommunity<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.extv6_comm.tree.values().map(ListEntry::RibExtv6Comms);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let comms = list_entry.as_rib_extv6_comms().unwrap();
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            ipv6_ext_community: Some(Box::new(communities)),
            ipv6_ext_community_raw: None, // TODO
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::large_communities::large_community::LargeCommunity<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.large_comm.tree.values().map(ListEntry::RibLargeComms);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let comms = list_entry.as_rib_large_comms().unwrap();
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            large_community: Some(Box::new(communities)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::AfiSafi<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let _ = instance.state.as_ref()?;
        let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi)).map(ListEntry::Rib);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let afi_safi = list_entry.as_rib().unwrap();
        Self {
            name: afi_safi.to_yang(),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let afi_safi = list_entry.as_rib().unwrap();
        if *afi_safi != AfiSafi::Ipv4Unicast {
            return None;
        }
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| ListEntry::RibV4LocRoute(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v4_loc_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            origin: route.origin.to_yang(),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: None,
            ineligible_reason: None,
            reject_reason: None,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v4_loc_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let afi_safi = list_entry.as_rib().unwrap();
        if *afi_safi != AfiSafi::Ipv4Unicast {
            return None;
        }
        let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established).map(ListEntry::RibNeighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        Self {
            neighbor_address: Cow::Borrowed(&nbr.remote_addr),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| ListEntry::RibV4Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v4_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v4_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| ListEntry::RibV4Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v4_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            best_path: None, // TODO
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v4_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| ListEntry::RibV4Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v4_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v4_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| ListEntry::RibV4Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v4_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v4_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let afi_safi = list_entry.as_rib().unwrap();
        if *afi_safi != AfiSafi::Ipv6Unicast {
            return None;
        }
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| ListEntry::RibV6LocRoute(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v6_loc_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            origin: route.origin.to_yang(),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: None,
            ineligible_reason: None,
            reject_reason: None,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v6_loc_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::Neighbor<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let afi_safi = list_entry.as_rib().unwrap();
        if *afi_safi != AfiSafi::Ipv6Unicast {
            return None;
        }
        let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established).map(ListEntry::RibNeighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        Self {
            neighbor_address: Cow::Borrowed(&nbr.remote_addr),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| ListEntry::RibV6Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v6_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v6_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| ListEntry::RibV6Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v6_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            best_path: None, // TODO
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v6_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| ListEntry::RibV6Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v6_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v6_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_rib_neighbor().unwrap();
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| ListEntry::RibV6Route(prefix, route)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_rib_v6_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_rib_v6_route().unwrap();
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let attr = list_entry.as_route_unknown_attr().unwrap();
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(attr.value.as_ref()),
        }
    }
}

// ===== helper functions =====

fn afi_safi_tuple(afi: Afi, safi: Safi) -> Option<AfiSafi> {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => Some(AfiSafi::Ipv4Unicast),
        (Afi::Ipv6, Safi::Unicast) => Some(AfiSafi::Ipv6Unicast),
        _ => None,
    }
}
