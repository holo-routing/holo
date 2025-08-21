//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::{Arc, LazyLock as Lazy, atomic};

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::bgp;
use holo_utils::bgp::AfiSafi;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::instance::Instance;
use crate::neighbor::{Neighbor, fsm};
use crate::packet::attribute::{
    AsPathSegment, BaseAttrs, Comms, ExtComms, Extv6Comms, LargeComms,
    UnknownAttr,
};
use crate::packet::consts::{Afi, AttrFlags, Safi};
use crate::packet::message::{AddPathTuple, Capability};
use crate::rib::{AttrSet, LocalRoute, Route};

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);
pub static AFI_SAFIS: [AfiSafi; 2] =
    [AfiSafi::Ipv4Unicast, AfiSafi::Ipv6Unicast];

#[derive(Debug, Default, EnumAsInner)]
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

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(bgp::global::afi_safis::afi_safi::PATH)
        .get_iterate(|instance, _args| {
            let _ = instance.state.as_ref()?;
            let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi)).map(ListEntry::GlobalAfiSafi);
            Some(Box::new(iter))
        })
        .get_object(|_context, args| {
            use bgp::global::afi_safis::afi_safi::AfiSafi;
            let afi_safi = args.list_entry.as_global_afi_safi().unwrap();
            Box::new(AfiSafi {
                name: afi_safi.to_yang(),
            })
        })
        .path(bgp::global::afi_safis::afi_safi::statistics::PATH)
        .get_object(|instance, args| {
            use bgp::global::afi_safis::afi_safi::statistics::Statistics;
            let afi_safi = args.list_entry.as_global_afi_safi().unwrap();
            let state = instance.state.as_ref().unwrap();
            let total_prefixes = match afi_safi {
                AfiSafi::Ipv4Unicast => state.rib.tables.ipv4_unicast.prefixes.len(),
                AfiSafi::Ipv6Unicast => state.rib.tables.ipv6_unicast.prefixes.len(),
            };
            Box::new(Statistics {
                // TODO
                total_paths: None,
                total_prefixes: Some(total_prefixes as u32),
            })
        })
        .path(bgp::global::statistics::PATH)
        .get_object(|instance, _args| {
            use bgp::global::statistics::Statistics;
            let mut total_prefixes = None;
            if let Some(state) = &instance.state {
                let total_ipv4 = state.rib.tables.ipv4_unicast.prefixes.len();
                let total_ipv6 = state.rib.tables.ipv6_unicast.prefixes.len();
                total_prefixes = Some(total_ipv4 as u32 + total_ipv6 as u32);
            }
            Box::new(Statistics {
                // TODO
                total_paths: None,
                total_prefixes,
            })
        })
        .path(bgp::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.neighbors.values().map(ListEntry::Neighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::Neighbor;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let mut local_address = None;
            let mut local_port = None;
            let mut remote_port = None;
            if let Some(conn_info) = &nbr.conn_info {
                local_address = Some(Cow::Borrowed(&conn_info.local_addr));
                local_port = Some(conn_info.local_port);
                remote_port = Some(conn_info.remote_port);
            }
            Box::new(Neighbor {
                remote_address: Cow::Borrowed(&nbr.remote_addr),
                local_address,
                local_port: local_port.ignore_in_testing(),
                remote_port: remote_port.ignore_in_testing(),
                peer_type: Some(nbr.peer_type.to_yang()),
                identifier: nbr.identifier.map(Cow::Owned),
                dynamically_configured: None,
                session_state: Some(nbr.state.to_yang()),
                last_established: nbr.last_established.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(bgp::neighbors::neighbor::timers::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::timers::Timers;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(Timers {
                negotiated_hold_time: nbr.holdtime_nego,
            })
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::PATH)
        .get_iterate(|_instance, _args| {
            // TODO
            None
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::afi_safis::afi_safi::AfiSafi;
            let (_, afi_safi) = args.list_entry.as_neighbor_afi_safi().unwrap();
            Box::new(AfiSafi {
                name: afi_safi.to_yang(),
                active: None,
            })
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::PATH)
        .get_object(|_instance, _args| {
            use bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::Prefixes;
            // TODO
            Box::new(Prefixes {
                received: None,
                sent: None,
                installed: None,
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::Capabilities;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let negotiated_capabilities = nbr.capabilities_nego.iter().map(|cap| cap.code().to_yang());
            Box::new(Capabilities {
                negotiated_capabilities: Some(Box::new(negotiated_capabilities)),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = nbr.capabilities_adv.iter().enumerate().map(|(index, cap)| ListEntry::Capability(index, cap));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::advertised_capabilities::AdvertisedCapabilities;
            let (index, cap) = args.list_entry.as_capability().unwrap();
            Box::new(AdvertisedCapabilities {
                code: cap.code() as u8,
                index: *index as u8,
                name: Some(cap.code().to_yang()),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::Mpbgp;
            let (_, cap) = args.list_entry.as_capability().unwrap();
            let mut afi = None;
            let mut safi = None;
            let mut name = None;
            if let Some((c_afi, c_safi)) = cap.as_multi_protocol() {
                afi = Some(c_afi.to_yang());
                safi = Some(c_safi.to_yang());
                if let Some(afi_safi) = afi_safi_tuple(*c_afi, *c_safi) {
                    name = Some(afi_safi.to_yang());
                }
            }
            Box::new(Mpbgp {
                afi,
                safi,
                name,
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::asn32::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::asn32::Asn32;
            let (_, cap) = args.list_entry.as_capability().unwrap();
            Box::new(Asn32 {
                r#as: cap.as_four_octet_as_number().copied(),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::PATH)
        .get_iterate(|_instance, args| {
            let (_, cap) = args.parent_list_entry.as_capability().unwrap();
            let Capability::AddPath(cap) = cap else { return None };
            let iter = cap.iter().map(ListEntry::AddPathTuple);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::AfiSafis;
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Box::new(AfiSafis {
                afi: Some(ap.afi.to_yang()),
                safi: Some(ap.safi.to_yang()),
                mode: Some(ap.mode.to_yang()),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = nbr.capabilities_rcvd.iter().enumerate().map(|(index, cap)| ListEntry::Capability(index, cap));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::received_capabilities::ReceivedCapabilities;
            let (index, cap) = args.list_entry.as_capability().unwrap();
            Box::new(ReceivedCapabilities {
                code: cap.code() as u8,
                index: *index as u8,
                name: Some(cap.code().to_yang()),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::Mpbgp;
            let (_, cap) = args.list_entry.as_capability().unwrap();
            let mut afi = None;
            let mut safi = None;
            let mut name = None;
            if let Some((c_afi, c_safi)) = cap.as_multi_protocol() {
                afi = Some(c_afi.to_yang());
                safi = Some(c_safi.to_yang());
                if let Some(afi_safi) = afi_safi_tuple(*c_afi, *c_safi) {
                    name = Some(afi_safi.to_yang());
                }
            }
            Box::new(Mpbgp {
                afi,
                safi,
                name,
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::asn32::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::received_capabilities::value::asn32::Asn32;
            let (_, cap) = args.list_entry.as_capability().unwrap();
            Box::new(Asn32 {
                r#as: cap.as_four_octet_as_number().copied(),
            })
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::PATH)
        .get_iterate(|_instance, args| {
            let (_, cap) = args.parent_list_entry.as_capability().unwrap();
            let Capability::AddPath(cap) = cap else { return None };
            let iter = cap.iter().map(ListEntry::AddPathTuple);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::AfiSafis;
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Box::new(AfiSafis {
                afi: Some(ap.afi.to_yang()),
                safi: Some(ap.safi.to_yang()),
                mode: Some(ap.mode.to_yang()),
            })
        })
        .path(bgp::neighbors::neighbor::errors::received::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::errors::received::Received;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let mut last_notification = None;
            let mut last_error = None;
            let mut last_error_code = None;
            let mut last_error_subcode = None;
            let mut last_error_data = None;
            if let Some((time, notif)) = &nbr.notification_rcvd {
                last_notification = Some(Cow::Borrowed(time));
                last_error = Some(notif.to_yang());
                last_error_code = Some(notif.error_code);
                last_error_subcode = Some(notif.error_subcode);
                last_error_data = Some(notif.data.as_ref());
            }
            Box::new(Received {
                last_notification,
                last_error,
                last_error_code,
                last_error_subcode,
                last_error_data,
            })
        })
        .path(bgp::neighbors::neighbor::errors::sent::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::errors::sent::Sent;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let mut last_notification = None;
            let mut last_error = None;
            let mut last_error_code = None;
            let mut last_error_subcode = None;
            let mut last_error_data = None;
            if let Some((time, notif)) = &nbr.notification_sent {
                last_notification = Some(Cow::Borrowed(time));
                last_error = Some(notif.to_yang());
                last_error_code = Some(notif.error_code);
                last_error_subcode = Some(notif.error_subcode);
                last_error_data = Some(notif.data.as_ref());
            }
            Box::new(Sent {
                last_notification,
                last_error,
                last_error_code,
                last_error_subcode,
                last_error_data,
            })
        })
        .path(bgp::neighbors::neighbor::statistics::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::statistics::Statistics;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(Statistics {
                established_transitions: Some(nbr.statistics.established_transitions).ignore_in_testing(),
            })
        })
        .path(bgp::neighbors::neighbor::statistics::messages::PATH)
        .get_object(|_instance, args| {
            use bgp::neighbors::neighbor::statistics::messages::Messages;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(Messages {
                total_received: Some(nbr.statistics.msgs_rcvd.total.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                total_sent: Some(nbr.statistics.msgs_sent.total.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                updates_received: Some(nbr.statistics.msgs_rcvd.updates).ignore_in_testing(),
                updates_sent: Some(nbr.statistics.msgs_sent.updates).ignore_in_testing(),
                erroneous_updates_withdrawn: Some(nbr.statistics.erroneous_updates_withdrawn).ignore_in_testing(),
                erroneous_updates_attribute_discarded: Some(nbr.statistics.erroneous_updates_attribute_discarded).ignore_in_testing(),
                in_update_elapsed_time: Some(nbr.statistics.in_update_elapsed_time.as_secs() as u32).ignore_in_testing(),
                notifications_received: Some(nbr.statistics.msgs_rcvd.notifications).ignore_in_testing(),
                notifications_sent: Some(nbr.statistics.msgs_sent.notifications).ignore_in_testing(),
                route_refreshes_received: Some(nbr.statistics.msgs_rcvd.route_refreshes).ignore_in_testing(),
                route_refreshes_sent: Some(nbr.statistics.msgs_sent.route_refreshes).ignore_in_testing(),
            })
        })
        .path(bgp::rib::attr_sets::attr_set::PATH)
        .get_iterate(|instance, _args| {
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.attr_sets.base.tree.values().map(ListEntry::RibBaseAttrs);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::AttrSet;
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            Box::new(AttrSet {
                index: attr_set.index,
            })
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::PATH)
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::attributes::Attributes;
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            let cluster_list = attr_set.value.cluster_list.as_ref().map(|clist| Box::new(clist.0.iter().map(Cow::Borrowed)) as _);
            Box::new(Attributes {
                origin: Some(attr_set.value.origin.to_yang()),
                next_hop: attr_set.value.nexthop.as_ref().map(Cow::Borrowed),
                link_local_next_hop: attr_set.value.ll_nexthop.as_ref().map(Cow::Borrowed),
                med: attr_set.value.med,
                local_pref: attr_set.value.local_pref,
                atomic_aggregate: attr_set.value.atomic_aggregate.map(|_| true),
                originator_id: attr_set.value.originator_id.map(Cow::Owned),
                cluster_list,
            })
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as_path::segment::PATH)
        .get_iterate(|_instance, args| {
            let attr_set = args.parent_list_entry.as_rib_base_attrs().unwrap();
            let iter = attr_set.value.as_path.segments.iter().map(ListEntry::RibAsPathSegment);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::attributes::as_path::segment::Segment;
            let aspath_seg = args.list_entry.as_rib_as_path_segment().unwrap();
            let members = aspath_seg.members.iter().copied();
            Box::new(Segment {
                r#type: Some(aspath_seg.seg_type.to_yang()),
                member: Some(Box::new(members)),
            })
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::PATH)
        .get_iterate(|_instance, args| {
            let attr_set = args.parent_list_entry.as_rib_base_attrs().unwrap();
            let Some(as4_path) = &attr_set.value.as4_path else { return None };
            let iter = as4_path.segments.iter().map(ListEntry::RibAsPathSegment);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::Segment;
            let aspath_seg = args.list_entry.as_rib_as_path_segment().unwrap();
            let members = aspath_seg.members.iter().copied();
            Box::new(Segment {
                r#type: Some(aspath_seg.seg_type.to_yang()),
                member: Some(Box::new(members)),
            })
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator::PATH)
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::attributes::aggregator::Aggregator;
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            let mut r#as = None;
            let mut identifier = None;
            if let Some(aggregator) = &attr_set.value.aggregator {
                r#as = Some(aggregator.asn);
                identifier = Some(Cow::Owned(aggregator.identifier));
            }
            Box::new(Aggregator {
                r#as,
                identifier,
            })
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator4::PATH)
        .get_object(|_instance, args| {
            use bgp::rib::attr_sets::attr_set::attributes::aggregator4::Aggregator4;
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            let mut as4 = None;
            let mut identifier = None;
            if let Some(as4_aggregator) = &attr_set.value.as4_aggregator {
                as4 = Some(as4_aggregator.asn);
                identifier = Some(Cow::Owned(as4_aggregator.identifier));
            }
            Box::new(Aggregator4 {
                as4,
                identifier,
            })
        })
        .path(bgp::rib::communities::community::PATH)
        .get_iterate(|instance, _args| {
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.attr_sets.comm.tree.values().map(ListEntry::RibComms);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::communities::community::Community;
            let comms = args.list_entry.as_rib_comms().unwrap();
            let communities = comms.value.0.iter().map(|c| c.to_yang());
            Box::new(Community {
                index: comms.index,
                community: Some(Box::new(communities)),
            })
        })
        .path(bgp::rib::ext_communities::ext_community::PATH)
        .get_iterate(|instance, _args| {
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.attr_sets.ext_comm.tree.values().map(ListEntry::RibExtComms);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::ext_communities::ext_community::ExtCommunity;
            let comms = args.list_entry.as_rib_ext_comms().unwrap();
            let communities = comms.value.0.iter().map(|c| c.to_yang());
            Box::new(ExtCommunity {
                index: comms.index,
                ext_community: Some(Box::new(communities)),
                // TODO
                ext_community_raw: None,
            })
        })
        .path(bgp::rib::ipv6_ext_communities::ipv6_ext_community::PATH)
        .get_iterate(|instance, _args| {
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.attr_sets.extv6_comm.tree.values().map(ListEntry::RibExtv6Comms);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::ipv6_ext_communities::ipv6_ext_community::Ipv6ExtCommunity;
            let comms = args.list_entry.as_rib_extv6_comms().unwrap();
            let communities = comms.value.0.iter().map(|c| c.to_yang());
            Box::new(Ipv6ExtCommunity {
                index: comms.index,
                ipv6_ext_community: Some(Box::new(communities)),
                // TODO
                ipv6_ext_community_raw: None,
            })
        })
        .path(bgp::rib::large_communities::large_community::PATH)
        .get_iterate(|instance, _args| {
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.attr_sets.large_comm.tree.values().map(ListEntry::RibLargeComms);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::large_communities::large_community::LargeCommunity;
            let comms = args.list_entry.as_rib_large_comms().unwrap();
            let communities = comms.value.0.iter().map(|c| c.to_yang());
            Box::new(LargeCommunity {
                index: comms.index,
                large_community: Some(Box::new(communities)),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::PATH)
        .get_iterate(|instance, _args| {
            let _ = instance.state.as_ref()?;
            let iter = AFI_SAFIS.into_iter().filter(|afi_safi| instance.config.afi_safi.contains_key(afi_safi)).map(ListEntry::Rib);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::AfiSafi;
            let afi_safi = args.list_entry.as_rib().unwrap();
            Box::new(AfiSafi {
                name: afi_safi.to_yang(),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi != AfiSafi::Ipv4Unicast {
                return None;
            }
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv4_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| ListEntry::RibV4LocRoute(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_loc_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi != AfiSafi::Ipv4Unicast {
                return None;
            }

            let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established).map(ListEntry::RibNeighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::Neighbor;
            let nbr = args.list_entry.as_rib_neighbor().unwrap();
            Box::new(Neighbor {
                neighbor_address: Cow::Borrowed(&nbr.remote_addr),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv4_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| ListEntry::RibV4Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v4_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv4_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| ListEntry::RibV4Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v4_route().unwrap();
            Box::new(Route {
                prefix: Cow::Borrowed(prefix),
                path_id: 0,
                attr_index: Some(route.attrs.base.index),
                community_index: route.attrs.comm.as_ref().map(|c| c.index),
                ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
                large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
                last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
                eligible_route: Some(route.is_eligible()),
                ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
                // TODO
                best_path: None,
                reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv4_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| ListEntry::RibV4Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v4_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv4_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| ListEntry::RibV4Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v4_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi != AfiSafi::Ipv6Unicast {
                return None;
            }
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv6_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.local.as_ref().map(|route| ListEntry::RibV6LocRoute(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_loc_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi != AfiSafi::Ipv6Unicast {
                return None;
            }

            let iter = instance.neighbors.values().filter(|nbr| nbr.state == fsm::State::Established).map(ListEntry::RibNeighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::Neighbor;
            let nbr = args.list_entry.as_rib_neighbor().unwrap();
            Box::new(Neighbor {
                neighbor_address: Cow::Borrowed(&nbr.remote_addr),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv6_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_pre()).map(|route| ListEntry::RibV6Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v6_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv6_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.in_post()).map(|route| ListEntry::RibV6Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v6_route().unwrap();
            Box::new(Route {
                prefix: Cow::Borrowed(prefix),
                path_id: 0,
                attr_index: Some(route.attrs.base.index),
                community_index: route.attrs.comm.as_ref().map(|c| c.index),
                ext_community_index: route.attrs.ext_comm.as_ref().map(|c| c.index),
                large_community_index: route.attrs.large_comm.as_ref().map(|c| c.index),
                last_modified: Some(Cow::Borrowed(&route.last_modified)).ignore_in_testing(),
                eligible_route: Some(route.is_eligible()),
                ineligible_reason: route.ineligible_reason.as_ref().map(|r| r.to_yang()),
                // TODO
                best_path: None,
                reject_reason: route.reject_reason.as_ref().map(|r| r.to_yang()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv6_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_pre()).map(|route| ListEntry::RibV6Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v6_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_rib_neighbor().unwrap();
            let Some(state) = &instance.state else { return None };
            let iter = state.rib.tables.ipv6_unicast.prefixes.iter();
            let iter = iter.filter_map(|(prefix, dest)| dest.adj_rib.get(&nbr.remote_addr).and_then(|adj_rib| adj_rib.out_post()).map(|route| ListEntry::RibV6Route(prefix, route)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::Route;
            let (prefix, route) = args.list_entry.as_rib_v6_route().unwrap();
            Box::new(Route {
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
            })
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_route().unwrap();
            let Some(unknown) = &route.attrs.unknown else { return None };
            let iter = unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::UnknownAttribute;
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Box::new(UnknownAttribute {
                attr_type: attr.attr_type,
                optional: Some(attr.flags.contains(AttrFlags::OPTIONAL)),
                transitive: Some(attr.flags.contains(AttrFlags::TRANSITIVE)),
                partial: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                extended: Some(attr.flags.contains(AttrFlags::EXTENDED)),
                attr_len: Some(attr.length),
                attr_value: Some(attr.value.as_ref()),
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}

// ===== helper functions =====

fn afi_safi_tuple(afi: Afi, safi: Safi) -> Option<AfiSafi> {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => Some(AfiSafi::Ipv4Unicast),
        (Afi::Ipv6, Safi::Unicast) => Some(AfiSafi::Ipv6Unicast),
        _ => None,
    }
}
