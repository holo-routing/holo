//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::sync::{Arc, atomic};

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::bgp::AfiSafi;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;
use holo_yang::types::{Base64Str, Timeticks};
use ipnetwork::{Ipv4Network, Ipv6Network};
use prefix_trie::PrefixMap;

use crate::instance::Instance;
use crate::neighbor::{Neighbor, fsm};
use crate::northbound::yang_gen::{self, bgp};
use crate::packet::attribute::{AsPathSegment, AttrFlags, BaseAttrs, Comms, ExtComms, Extv6Comms, LargeComms, UnknownAttr};
use crate::packet::iana::{Afi, Safi};
use crate::packet::message::{AddPathTuple, Capability};
use crate::rib::{AttrSet, Destination, LocalRoute, Route};

pub static AFI_SAFIS: [AfiSafi; 2] = [AfiSafi::Ipv4Unicast, AfiSafi::Ipv6Unicast];

impl Provider for Instance {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!("/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-bgp:bgp", Protocol::BGP.to_yang(), self.name)
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Instance> for bgp::global::afi_safis::afi_safi::AfiSafi<'a> {
    type ParentListEntry = ();
    type ListEntry = AfiSafi;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let _ = instance.state.as_ref()?;
        let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi));
        Some(iter)
    }

    fn new(_instance: &'a Instance, afi_safi: &Self::ListEntry) -> Self {
        Self {
            name: afi_safi.to_yang(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::global::afi_safis::afi_safi::statistics::Statistics {
    type ParentListEntry = AfiSafi;

    fn new(instance: &'a Instance, afi_safi: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();
    type ListEntry = &'a Neighbor;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.neighbors.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, nbr: &Self::ListEntry) -> Self {
        let mut local_address = None;
        let mut local_port = None;
        let mut remote_port = None;
        if let Some(conn_info) = &nbr.conn_info {
            local_address = Some(conn_info.local_addr);
            local_port = Some(conn_info.local_port);
            remote_port = Some(conn_info.remote_port);
        }
        Self {
            remote_address: nbr.remote_addr,
            local_address,
            local_port: local_port.ignore_in_testing(),
            remote_port: remote_port.ignore_in_testing(),
            peer_type: Some(nbr.peer_type),
            identifier: nbr.identifier,
            dynamically_configured: None,
            session_state: Some(nbr.state.to_yang()),
            last_established: nbr.last_established.ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::timers::Timers {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            negotiated_hold_time: nbr.holdtime_nego,
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::afi_safis::afi_safi::AfiSafi<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (&'a Neighbor, AfiSafi);

    fn iter(_instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        // If the peer doesn't support BGP capabilities, the IPv4 unicast
        // address-family is enabled by default.
        if nbr.capabilities_nego.is_empty() {
            let iter = std::iter::once((nbr, AfiSafi::Ipv4Unicast));
            return Some(Box::new(iter) as Box<dyn Iterator<Item = _> + 'a>);
        }

        let iter = nbr.capabilities_nego.iter().filter_map(move |cap| {
            let (afi, safi) = cap.as_multi_protocol()?;
            let afi_safi = afi_safi_tuple(*afi, *safi)?;
            Some((nbr, afi_safi))
        });
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, (_, afi_safi): &Self::ListEntry) -> Self {
        Self {
            name: afi_safi.to_yang(),
            active: None,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::Prefixes {
    type ParentListEntry = (&'a Neighbor, AfiSafi);

    fn new(instance: &'a Instance, (nbr, afi_safi): &Self::ParentListEntry) -> Option<Self> {
        let rib = &instance.state.as_ref()?.rib;
        fn count_stats<K>(prefixes: &PrefixMap<K, Destination>, addr: &IpAddr) -> (u32, u32, u32)
        where
            K: prefix_trie::Prefix,
        {
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
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let negotiated_capabilities = nbr.capabilities_nego.iter().map(|cap| cap.code().to_yang());
        Some(Self {
            negotiated_capabilities: Some(Box::new(negotiated_capabilities)),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::AdvertisedCapabilities<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (usize, &'a Capability);

    fn iter(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = nbr.capabilities_adv.iter().enumerate();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (index, cap): &Self::ListEntry) -> Self {
        Self {
            code: cap.code() as u8,
            index: *index as u8,
            name: Some(cap.code().to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::Mpbgp<'a> {
    type ParentListEntry = (usize, &'a Capability);

    fn new(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<Self> {
        let (c_afi, c_safi) = cap.as_multi_protocol()?;
        Some(Self {
            afi: Some(c_afi.to_yang()),
            safi: Some(c_safi.to_yang()),
            name: afi_safi_tuple(*c_afi, *c_safi).map(|afi_safi| afi_safi.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::asn32::Asn32 {
    type ParentListEntry = (usize, &'a Capability);

    fn new(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#as: cap.as_four_octet_as_number().copied(),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::AfiSafis<'a> {
    type ParentListEntry = (usize, &'a Capability);
    type ListEntry = &'a AddPathTuple;

    fn iter(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let cap = cap.as_add_path()?;
        let iter = cap.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, ap: &Self::ListEntry) -> Self {
        Self {
            afi: Some(ap.afi.to_yang()),
            safi: Some(ap.safi.to_yang()),
            mode: Some(ap.mode.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::ReceivedCapabilities<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (usize, &'a Capability);

    fn iter(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = nbr.capabilities_rcvd.iter().enumerate();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (index, cap): &Self::ListEntry) -> Self {
        Self {
            code: cap.code() as u8,
            index: *index as u8,
            name: Some(cap.code().to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::Mpbgp<'a> {
    type ParentListEntry = (usize, &'a Capability);

    fn new(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<Self> {
        let (c_afi, c_safi) = cap.as_multi_protocol()?;
        Some(Self {
            afi: Some(c_afi.to_yang()),
            safi: Some(c_safi.to_yang()),
            name: afi_safi_tuple(*c_afi, *c_safi).map(|afi_safi| afi_safi.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::asn32::Asn32 {
    type ParentListEntry = (usize, &'a Capability);

    fn new(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#as: cap.as_four_octet_as_number().copied(),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::AfiSafis<'a> {
    type ParentListEntry = (usize, &'a Capability);
    type ListEntry = &'a AddPathTuple;

    fn iter(_instance: &'a Instance, (_, cap): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let cap = cap.as_add_path()?;
        let iter = cap.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, ap: &Self::ListEntry) -> Self {
        Self {
            afi: Some(ap.afi.to_yang()),
            safi: Some(ap.safi.to_yang()),
            mode: Some(ap.mode.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::errors::received::Received<'a> {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let (time, notif) = nbr.notification_rcvd.as_ref()?;
        Some(Self {
            last_notification: Some(*time),
            last_error: Some(notif.to_yang()),
            last_error_code: Some(notif.error_code),
            last_error_subcode: Some(notif.error_subcode),
            last_error_data: Some(Base64Str(notif.data.as_ref())),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::errors::sent::Sent<'a> {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let (time, notif) = nbr.notification_sent.as_ref()?;
        Some(Self {
            last_notification: Some(*time),
            last_error: Some(notif.to_yang()),
            last_error_code: Some(notif.error_code),
            last_error_subcode: Some(notif.error_subcode),
            last_error_data: Some(Base64Str(notif.data.as_ref())),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::statistics::Statistics {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            established_transitions: Some(nbr.statistics.established_transitions).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::neighbors::neighbor::statistics::messages::Messages {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = ();
    type ListEntry = &'a AttrSet<BaseAttrs>;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.base.tree.values().map(Arc::as_ref);
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr_set: &Self::ListEntry) -> Self {
        Self {
            index: attr_set.index,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::Attributes<'a> {
    type ParentListEntry = &'a AttrSet<BaseAttrs>;

    fn new(_instance: &'a Instance, attr_set: &Self::ParentListEntry) -> Option<Self> {
        let cluster_list = attr_set.value.cluster_list.as_ref().map(|clist| Box::new(clist.0.iter().copied()) as _);
        Some(Self {
            origin: Some(attr_set.value.origin),
            next_hop: attr_set.value.nexthop,
            link_local_next_hop: attr_set.value.ll_nexthop,
            med: attr_set.value.med,
            local_pref: attr_set.value.local_pref,
            atomic_aggregate: attr_set.value.atomic_aggregate.map(|_| true),
            originator_id: attr_set.value.originator_id,
            cluster_list,
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::as_path::segment::Segment<'a> {
    type ParentListEntry = &'a AttrSet<BaseAttrs>;
    type ListEntry = &'a AsPathSegment;

    fn iter(_instance: &'a Instance, attr_set: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = attr_set.value.as_path.segments.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, aspath_seg: &Self::ListEntry) -> Self {
        let members = aspath_seg.members.iter().copied();
        Self {
            r#type: Some(aspath_seg.seg_type.to_yang()),
            member: Some(Box::new(members)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::Segment<'a> {
    type ParentListEntry = &'a AttrSet<BaseAttrs>;
    type ListEntry = &'a AsPathSegment;

    fn iter(_instance: &'a Instance, attr_set: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let as4_path = attr_set.value.as4_path.as_ref()?;
        let iter = as4_path.segments.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, aspath_seg: &Self::ListEntry) -> Self {
        let members = aspath_seg.members.iter().copied();
        Self {
            r#type: Some(aspath_seg.seg_type.to_yang()),
            member: Some(Box::new(members)),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::aggregator::Aggregator {
    type ParentListEntry = &'a AttrSet<BaseAttrs>;

    fn new(_instance: &'a Instance, attr_set: &Self::ParentListEntry) -> Option<Self> {
        let aggregator = attr_set.value.aggregator.as_ref()?;
        Some(Self {
            r#as: Some(aggregator.asn),
            identifier: Some(aggregator.identifier),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for bgp::rib::attr_sets::attr_set::attributes::aggregator4::Aggregator4 {
    type ParentListEntry = &'a AttrSet<BaseAttrs>;

    fn new(_instance: &'a Instance, attr_set: &Self::ParentListEntry) -> Option<Self> {
        let as4_aggregator = attr_set.value.as4_aggregator.as_ref()?;
        Some(Self {
            as4: Some(as4_aggregator.asn),
            identifier: Some(as4_aggregator.identifier),
        })
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::communities::community::Community<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a AttrSet<Comms>;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.comm.tree.values().map(Arc::as_ref);
        Some(iter)
    }

    fn new(_instance: &'a Instance, comms: &Self::ListEntry) -> Self {
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            community: Some(Box::new(communities)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::ext_communities::ext_community::ExtCommunity<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a AttrSet<ExtComms>;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.ext_comm.tree.values().map(Arc::as_ref);
        Some(iter)
    }

    fn new(_instance: &'a Instance, comms: &Self::ListEntry) -> Self {
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            ext_community: Some(Box::new(communities)),
            ext_community_raw: None, // TODO
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::ipv6_ext_communities::ipv6_ext_community::Ipv6ExtCommunity<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a AttrSet<Extv6Comms>;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.extv6_comm.tree.values().map(Arc::as_ref);
        Some(iter)
    }

    fn new(_instance: &'a Instance, comms: &Self::ListEntry) -> Self {
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            ipv6_ext_community: Some(Box::new(communities)),
            ipv6_ext_community_raw: None, // TODO
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::large_communities::large_community::LargeCommunity<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a AttrSet<LargeComms>;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.attr_sets.large_comm.tree.values().map(Arc::as_ref);
        Some(iter)
    }

    fn new(_instance: &'a Instance, comms: &Self::ListEntry) -> Self {
        let communities = comms.value.0.iter().map(|c| c.to_yang());
        Self {
            index: comms.index,
            large_community: Some(Box::new(communities)),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::AfiSafi<'a> {
    type ParentListEntry = ();
    type ListEntry = AfiSafi;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let _ = instance.state.as_ref()?;
        let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi));
        Some(iter)
    }

    fn new(_instance: &'a Instance, afi_safi: &Self::ListEntry) -> Self {
        Self {
            name: afi_safi.to_yang(),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::Route<'a> {
    type ParentListEntry = AfiSafi;
    type ListEntry = (Ipv4Network, &'a Box<LocalRoute>);

    fn iter(instance: &'a Instance, afi_safi: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if *afi_safi != AfiSafi::Ipv4Unicast {
            return None;
        }
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            origin: route.origin.to_yang(),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: None,
            ineligible_reason: None,
            reject_reason: None,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv4Network, &'a Box<LocalRoute>);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::Neighbor {
    type ParentListEntry = AfiSafi;
    type ListEntry = &'a Neighbor;

    fn iter(instance: &'a Instance, afi_safi: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if *afi_safi != AfiSafi::Ipv4Unicast {
            return None;
        }
        let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established);
        Some(iter)
    }

    fn new(_instance: &'a Instance, nbr: &Self::ListEntry) -> Self {
        Self {
            neighbor_address: nbr.remote_addr,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv4Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv4Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv4Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            best_path: None, // TODO
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv4Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv4Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv4Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv4Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv4_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv4Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::Route<'a> {
    type ParentListEntry = AfiSafi;
    type ListEntry = (Ipv6Network, &'a Box<LocalRoute>);

    fn iter(instance: &'a Instance, afi_safi: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if *afi_safi != AfiSafi::Ipv6Unicast {
            return None;
        }
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            origin: route.origin.to_yang(),
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: None,
            ineligible_reason: None,
            reject_reason: None,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv6Network, &'a Box<LocalRoute>);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::Neighbor {
    type ParentListEntry = AfiSafi;
    type ListEntry = &'a Neighbor;

    fn iter(instance: &'a Instance, afi_safi: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if *afi_safi != AfiSafi::Ipv6Unicast {
            return None;
        }
        let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established);
        Some(iter)
    }

    fn new(_instance: &'a Instance, nbr: &Self::ListEntry) -> Self {
        Self {
            neighbor_address: nbr.remote_addr,
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv6Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv6Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv6Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            best_path: None, // TODO
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv6Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv6Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv6Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route<'a> {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = (Ipv6Network, &'a Route);

    fn iter(instance: &'a Instance, &nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.tables.ipv6_unicast.prefixes.iter();
        let iter = iter.filter_map(move |(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| (prefix, route)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            path_id: 0,
            attr_index: Some(route.attrs.base.index),
            community_index: route.attrs.comm.as_ref().map(|c| c.index),
            ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
            large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
            last_modified: Some(Timeticks(route.last_modified)).ignore_in_testing(),
            eligible_route: Some(route.is_eligible()),
            ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
            reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute<'a> {
    type ParentListEntry = (Ipv6Network, &'a Route);
    type ListEntry = &'a UnknownAttr;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unknown = route.attrs.unknown.as_ref()?;
        let iter = unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, attr: &Self::ListEntry) -> Self {
        Self {
            attr_type: attr.attr_type,
            optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
            transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
            partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
            attr_len: Some(attr.length),
            attr_value: Some(Base64Str(attr.value.as_ref())),
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
