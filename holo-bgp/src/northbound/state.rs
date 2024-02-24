//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::sync::{atomic, Arc, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::bgp;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, NodeAttributes, Provider,
};
use holo_utils::bgp::AfiSafi;
use holo_yang::ToYang;
use ipnetwork::{Ipv4Network, Ipv6Network};
use itertools::Itertools;

use crate::instance::Instance;
use crate::neighbor::{fsm, Neighbor};
use crate::packet::attribute::{
    AsPathSegment, BaseAttrs, Comm, Comms, ExtComm, ExtComms, Extv6Comm,
    Extv6Comms, LargeComm, LargeComms, UnknownAttr,
};
use crate::packet::consts::{Afi, AttrFlags, Safi};
use crate::packet::message::{AddPathTuple, Capability};
use crate::rib::{AttrSet, LocalRoute, Route};

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    GlobalAfiSafi(AfiSafi),
    Neighbor(&'a Neighbor),
    CapabilityAdv(usize, &'a Capability),
    CapabilityRcvd(usize, &'a Capability),
    CapabilityNego(String),
    AddPathTuple(&'a AddPathTuple),
    Rib(AfiSafi),
    RibBaseAttrs(&'a Arc<AttrSet<BaseAttrs>>),
    RibComms(&'a Arc<AttrSet<Comms>>),
    RibComm(&'a Comm),
    RibExtComms(&'a Arc<AttrSet<ExtComms>>),
    RibExtComm(&'a ExtComm),
    RibExtv6Comms(&'a Arc<AttrSet<Extv6Comms>>),
    RibExtv6Comm(&'a Extv6Comm),
    RibLargeComms(&'a Arc<AttrSet<LargeComms>>),
    RibLargeComm(&'a LargeComm),
    RibAsPathSegment(&'a AsPathSegment),
    RibAsPathSegmentMember(u32),
    RibClusterList(Ipv4Addr),
    RibNeighbor(AfiSafi, &'a Neighbor),
    RibV4LocRoute(&'a Ipv4Network, &'a LocalRoute),
    RibV6LocRoute(&'a Ipv6Network, &'a LocalRoute),
    RibV4AdjInPreRoute(&'a Ipv4Network, &'a Route),
    RibV6AdjInPreRoute(&'a Ipv6Network, &'a Route),
    RibV4AdjInPostRoute(&'a Ipv4Network, &'a Route),
    RibV6AdjInPostRoute(&'a Ipv6Network, &'a Route),
    RibV4AdjOutPreRoute(&'a Ipv4Network, &'a Route),
    RibV6AdjOutPreRoute(&'a Ipv6Network, &'a Route),
    RibV4AdjOutPostRoute(&'a Ipv4Network, &'a Route),
    RibV6AdjOutPostRoute(&'a Ipv6Network, &'a Route),
    RouteUnknownAttr(&'a UnknownAttr),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(bgp::global::afi_safis::afi_safi::PATH)
        .get_iterate(|instance, _args| {
            if instance.state.is_some() {
                let iter = [AfiSafi::Ipv4Unicast, AfiSafi::Ipv6Unicast]
                    .into_iter()
                    .map(ListEntry::GlobalAfiSafi);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::global::afi_safis::afi_safi::statistics::total_paths::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::global::afi_safis::afi_safi::statistics::total_prefixes::PATH)
        .get_element_u32(|instance, args| {
            let afi_safi = args.list_entry.as_global_afi_safi().unwrap();
            let state = instance.state.as_ref().unwrap();
            let total = match afi_safi {
                AfiSafi::Ipv4Unicast => state.rib.tables.ipv4_unicast.prefixes.len(),
                AfiSafi::Ipv6Unicast => state.rib.tables.ipv6_unicast.prefixes.len(),
            };
            Some(total as u32)
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::import_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::global::afi_safis::afi_safi::apply_policy::export_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::global::afi_safis::afi_safi::ipv4_unicast::prefix_limit::prefix_limit_exceeded::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::global::afi_safis::afi_safi::ipv6_unicast::prefix_limit::prefix_limit_exceeded::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::global::apply_policy::import_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::global::apply_policy::export_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::global::statistics::total_paths::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::global::statistics::total_prefixes::PATH)
        .get_element_u32(|instance, _args| {
            if let Some(state) = &instance.state {
                let total = state.rib.tables.ipv4_unicast.prefixes.len()
                    + state.rib.tables.ipv6_unicast.prefixes.len();
                Some(total as u32)
            } else {
                None
            }
        })
        .path(bgp::neighbors::neighbor::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance
                .neighbors
                .values()
                .map(ListEntry::Neighbor);
            Some(Box::new(iter))
        })
        .path(bgp::neighbors::neighbor::local_address::PATH)
        .get_element_ip(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.local_addr)
        })
        .path(bgp::neighbors::neighbor::local_port::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.local_port)
        })
        .path(bgp::neighbors::neighbor::remote_port::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.remote_port)
        })
        .path(bgp::neighbors::neighbor::peer_type::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.peer_type.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::identifier::PATH)
        .get_element_ipv4(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.identifier
        })
        .path(bgp::neighbors::neighbor::dynamically_configured::PATH)
        .get_element_empty(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::timers::negotiated_hold_time::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.holdtime_nego
        })
        .path(bgp::neighbors::neighbor::apply_policy::import_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::neighbors::neighbor::apply_policy::export_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::neighbors::neighbor::prefix_limit::prefix_limit_exceeded::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::active::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::received::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::sent::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::prefixes::installed::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::import_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::apply_policy::export_policy::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv4_unicast::prefix_limit::prefix_limit_exceeded::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::afi_safis::afi_safi::ipv6_unicast::prefix_limit::prefix_limit_exceeded::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::last_established::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.last_established
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = nbr
                .capabilities_adv
                .iter()
                .enumerate()
                .map(|(index, cap)| ListEntry::CapabilityAdv(index, cap));
            Some(Box::new(iter))
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::name::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_adv().unwrap();
            Some(cap.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::afi::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_adv().unwrap();
            cap.as_multi_protocol().map(|(afi, _)| afi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::safi::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_adv().unwrap();
            cap.as_multi_protocol().map(|(_, safi)| safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::mpbgp::name::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_adv().unwrap();
            cap.as_multi_protocol()
                .and_then(|(afi, safi)| afi_safi_tuple(*afi, *safi))
                .map(|afi_safi| afi_safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::asn32::r#as::PATH)
        .get_element_u32(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_adv().unwrap();
            cap.as_four_octet_as_number().map(|asn| asn.0)
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::PATH)
        .get_iterate(|_instance, args| {
            let (_, cap) = args.parent_list_entry.as_capability_adv().unwrap();
            if let Capability::AddPath(cap) = cap {
                let iter = cap.iter().map(ListEntry::AddPathTuple);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::afi::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.afi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::safi::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::advertised_capabilities::value::add_paths::afi_safis::mode::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.mode.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = nbr
                .capabilities_rcvd
                .iter()
                .enumerate()
                .map(|(index, cap)| ListEntry::CapabilityRcvd(index, cap));
            Some(Box::new(iter))
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::name::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_rcvd().unwrap();
            Some(cap.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::afi::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_rcvd().unwrap();
            cap.as_multi_protocol().map(|(afi, _)| afi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::safi::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_rcvd().unwrap();
            cap.as_multi_protocol().map(|(_, safi)| safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::mpbgp::name::PATH)
        .get_element_string(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_rcvd().unwrap();
            cap.as_multi_protocol()
                .and_then(|(afi, safi)| afi_safi_tuple(*afi, *safi))
                .map(|afi_safi| afi_safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::asn32::r#as::PATH)
        .get_element_u32(|_instance, args| {
            let (_, cap) = args.list_entry.as_capability_rcvd().unwrap();
            cap.as_four_octet_as_number().map(|asn| asn.0)
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::PATH)
        .get_iterate(|_instance, args| {
            let (_, cap) = args.parent_list_entry.as_capability_rcvd().unwrap();
            if let Capability::AddPath(cap) = cap {
                let iter = cap.iter().map(ListEntry::AddPathTuple);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::afi::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.afi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::safi::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.safi.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::received_capabilities::value::add_paths::afi_safis::mode::PATH)
        .get_element_string(|_instance, args| {
            let ap = args.list_entry.as_add_path_tuple().unwrap();
            Some(ap.mode.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::capabilities::negotiated_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = nbr
                .capabilities_adv
                .iter()
                .map(|cap| cap.to_yang().into())
                .dedup()
                .map(ListEntry::CapabilityNego);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let cap = args.list_entry.as_capability_nego().unwrap();
            Some(cap.clone())
        })
        .path(bgp::neighbors::neighbor::errors::received::last_notification::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_rcvd.as_ref().map(|(time, _)| *time)
        })
        .path(bgp::neighbors::neighbor::errors::received::last_error::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_rcvd.as_ref().map(|(_, notif)| notif.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::errors::received::last_error_code::PATH)
        .get_element_u8(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_rcvd.as_ref().map(|(_, notif)| notif.error_code)
        })
        .path(bgp::neighbors::neighbor::errors::received::last_error_subcode::PATH)
        .get_element_u8(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_rcvd.as_ref().map(|(_, notif)| notif.error_subcode)
        })
        .path(bgp::neighbors::neighbor::errors::received::last_error_data::PATH)
        .get_element_binary(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_rcvd.as_ref().map(|(_, notif)| notif.data.clone())
        })
        .path(bgp::neighbors::neighbor::errors::sent::last_notification::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_sent.as_ref().map(|(time, _)| *time)
        })
        .path(bgp::neighbors::neighbor::errors::sent::last_error::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_sent.as_ref().map(|(_, notif)| notif.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::errors::sent::last_error_code::PATH)
        .get_element_u8(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_sent.as_ref().map(|(_, notif)| notif.error_code)
        })
        .path(bgp::neighbors::neighbor::errors::sent::last_error_subcode::PATH)
        .get_element_u8(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_sent.as_ref().map(|(_, notif)| notif.error_code)
        })
        .path(bgp::neighbors::neighbor::errors::sent::last_error_data::PATH)
        .get_element_binary(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.notification_sent.as_ref().map(|(_, notif)| notif.data.clone())
        })
        .path(bgp::neighbors::neighbor::session_state::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.state.to_yang().into())
        })
        .path(bgp::neighbors::neighbor::statistics::established_transitions::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.established_transitions)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::total_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.total.load(atomic::Ordering::Relaxed))
        })
        .path(bgp::neighbors::neighbor::statistics::messages::total_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.total.load(atomic::Ordering::Relaxed))
        })
        .path(bgp::neighbors::neighbor::statistics::messages::updates_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.updates)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::updates_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.updates)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::erroneous_updates_withdrawn::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.erroneous_updates_withdrawn)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::erroneous_updates_attribute_discarded::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.erroneous_updates_attribute_discarded)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::in_update_elapsed_time::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.in_update_elapsed_time.as_secs() as u32)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::notifications_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.notifications)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::notifications_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.notifications)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::route_refreshes_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.route_refreshes)
        })
        .path(bgp::neighbors::neighbor::statistics::messages::route_refreshes_sent::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.route_refreshes)
        })
        .path(bgp::neighbors::neighbor::statistics::queues::input::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::neighbors::neighbor::statistics::queues::output::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::rib::attr_sets::attr_set::PATH)
        .get_iterate(|instance, _args| {
            if let Some(state) = &instance.state {
                let iter = state
                    .rib
                    .attr_sets
                    .base
                    .tree
                    .values()
                    .map(ListEntry::RibBaseAttrs);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::origin::PATH)
        .get_element_string(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            Some(attr_set.value.origin.to_yang().into())
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as_path::segment::PATH)
        .get_iterate(|_instance, args| {
            let attr_set = args.parent_list_entry.as_rib_base_attrs().unwrap();
            let iter = attr_set
                .value
                .as_path
                .segments
                .iter()
                .map(ListEntry::RibAsPathSegment);
            Some(Box::new(iter))
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as_path::segment::r#type::PATH)
        .get_element_string(|_instance, args| {
            let aspath_seg = args.list_entry.as_rib_as_path_segment().unwrap();
            Some(aspath_seg.seg_type.to_yang().into())
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as_path::segment::member::PATH)
        .get_iterate(|_instance, args| {
            let aspath_seg =
                args.parent_list_entry.as_rib_as_path_segment().unwrap();
            let iter = aspath_seg
                .members
                .iter()
                .copied()
                .map(ListEntry::RibAsPathSegmentMember);
            Some(Box::new(iter))
        })
        .get_element_u32(|_instance, args| {
            let asn = args.list_entry.as_rib_as_path_segment_member().unwrap();
            Some(*asn)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::next_hop::PATH)
        .get_element_ip(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.nexthop
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::link_local_next_hop::PATH)
        .get_element_ipv6(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.ll_nexthop
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::med::PATH)
        .get_element_u32(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.med
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::local_pref::PATH)
        .get_element_u32(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.local_pref
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::PATH)
        .get_iterate(|_instance, args| {
            let attr_set = args.parent_list_entry.as_rib_base_attrs().unwrap();
            if let Some(as4_path) = &attr_set.value.as4_path {
                let iter = as4_path
                    .segments
                    .iter()
                    .map(ListEntry::RibAsPathSegment);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::r#type::PATH)
        .get_element_string(|_instance, args| {
            let aspath_seg = args.list_entry.as_rib_as_path_segment().unwrap();
            Some(aspath_seg.seg_type.to_yang().into())
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::as4_path::segment::member::PATH)
        .get_iterate(|_instance, args| {
            let aspath_seg =
                args.parent_list_entry.as_rib_as_path_segment().unwrap();
            let iter = aspath_seg
                .members
                .iter()
                .copied()
                .map(ListEntry::RibAsPathSegmentMember);
            Some(Box::new(iter))
        })
        .get_element_u32(|_instance, args| {
            let asn = args.list_entry.as_rib_as_path_segment_member().unwrap();
            Some(*asn)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator::r#as::PATH)
        .get_element_u32(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.aggregator.as_ref().map(|aggregator| aggregator.asn)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator::identifier::PATH)
        .get_element_ipv4(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.aggregator.as_ref().map(|aggregator| aggregator.identifier)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator4::as4::PATH)
        .get_element_u32(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.as4_aggregator.as_ref().map(|aggregator| aggregator.asn)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::aggregator4::identifier::PATH)
        .get_element_ipv4(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.as4_aggregator.as_ref().map(|aggregator| aggregator.identifier)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::atomic_aggregate::PATH)
        .get_element_bool(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            Some(attr_set.value.atomic_aggregate)
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::originator_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let attr_set = args.list_entry.as_rib_base_attrs().unwrap();
            attr_set.value.originator_id
        })
        .path(bgp::rib::attr_sets::attr_set::attributes::cluster_list::PATH)
        .get_iterate(|_instance, args| {
            let attr_set = args.parent_list_entry.as_rib_base_attrs().unwrap();
            if let Some(cluster_list) = &attr_set.value.cluster_list {
                let iter = cluster_list.0
                    .iter()
                    .copied()
                    .map(ListEntry::RibClusterList);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_ipv4(|_instance, args| {
            let addr = args.list_entry.as_rib_cluster_list().unwrap();
            Some(*addr)
        })
        .path(bgp::rib::communities::community::PATH)
        .get_iterate(|instance, _args| {
            if let Some(state) = &instance.state {
                let iter = state
                    .rib
                    .attr_sets
                    .comm
                    .tree
                    .values()
                    .map(ListEntry::RibComms);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::communities::community::community::PATH)
        .get_iterate(|_instance, args| {
            let comms = args.parent_list_entry.as_rib_comms().unwrap();
            let iter = comms.value.0.iter().map(ListEntry::RibComm);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let comm = args.list_entry.as_rib_comm().unwrap();
            Some(comm.to_yang().into())
        })
        .path(bgp::rib::ext_communities::ext_community::PATH)
        .get_iterate(|instance, _args| {
            if let Some(state) = &instance.state {
                let iter = state
                    .rib
                    .attr_sets
                    .ext_comm
                    .tree
                    .values()
                    .map(ListEntry::RibExtComms);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::ext_communities::ext_community::ext_community::PATH)
        .get_iterate(|_instance, args| {
            let comms = args.parent_list_entry.as_rib_ext_comms().unwrap();
            let iter = comms.value.0.iter().map(ListEntry::RibExtComm);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let comm = args.list_entry.as_rib_ext_comm().unwrap();
            Some(comm.to_yang().into())
        })
        .path(bgp::rib::ext_communities::ext_community::ext_community_raw::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::rib::ipv6_ext_communities::ipv6_ext_community::PATH)
        .get_iterate(|instance, _args| {
            if let Some(state) = &instance.state {
                let iter = state
                    .rib
                    .attr_sets
                    .extv6_comm
                    .tree
                    .values()
                    .map(ListEntry::RibExtv6Comms);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::ipv6_ext_communities::ipv6_ext_community::ipv6_ext_community::PATH)
        .get_iterate(|_instance, args| {
            let comms = args.parent_list_entry.as_rib_extv6_comms().unwrap();
            let iter = comms.value.0.iter().map(ListEntry::RibExtv6Comm);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let comm = args.list_entry.as_rib_extv6_comm().unwrap();
            Some(comm.to_yang().into())
        })
        .path(bgp::rib::ipv6_ext_communities::ipv6_ext_community::ipv6_ext_community_raw::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::rib::large_communities::large_community::PATH)
        .get_iterate(|instance, _args| {
            if let Some(state) = &instance.state {
                let iter = state
                    .rib
                    .attr_sets
                    .large_comm
                    .tree
                    .values()
                    .map(ListEntry::RibLargeComms);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::large_communities::large_community::large_community::PATH)
        .get_iterate(|_instance, args| {
            let comms = args.parent_list_entry.as_rib_large_comms().unwrap();
            let iter = comms.value.0.iter().map(ListEntry::RibLargeComm);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let comm = args.list_entry.as_rib_large_comm().unwrap();
            Some(comm.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::PATH)
        .get_iterate(|instance, _args| {
            if instance.state.is_some() {
                let iter = [AfiSafi::Ipv4Unicast, AfiSafi::Ipv6Unicast]
                    .into_iter()
                    .map(ListEntry::Rib);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi == AfiSafi::Ipv4Unicast
                && let Some(state) = &instance.state {
                let iter = state.rib.tables.ipv4_unicast.prefixes.iter().filter_map(
                    |(prefix, dest)| {
                        dest.local.as_ref().map(|route| {
                            ListEntry::RibV4LocRoute(prefix, route)
                        })
                    },
                );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_loc_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_loc_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = *args.parent_list_entry.as_rib().unwrap();
            if afi_safi == AfiSafi::Ipv4Unicast {
                let iter = instance
                    .neighbors
                    .values()
                    .filter(|nbr| nbr.state == fsm::State::Established)
                    .map(move |nbr| ListEntry::RibNeighbor(afi_safi, nbr));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv4_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.in_pre.as_ref())
                                .map(|route| {
                                    ListEntry::RibV4AdjInPreRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_pre_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv4_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.in_post.as_ref())
                                .map(|route| {
                                    ListEntry::RibV4AdjInPostRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::best_path::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_adj_in_post_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_in_post_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv4_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.out_pre.as_ref())
                                .map(|route| {
                                    ListEntry::RibV4AdjOutPreRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_pre_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv4_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.out_post.as_ref())
                                .map(|route| {
                                    ListEntry::RibV4AdjOutPostRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v4_adj_out_post_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v4_adj_out_post_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = args.parent_list_entry.as_rib().unwrap();
            if *afi_safi == AfiSafi::Ipv6Unicast
                && let Some(state) = &instance.state {
                let iter = state.rib.tables.ipv6_unicast.prefixes.iter().filter_map(
                    |(prefix, dest)| {
                        dest.local.as_ref().map(|route| {
                            ListEntry::RibV6LocRoute(prefix, route)
                        })
                    },
                );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_loc_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_loc_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let afi_safi = *args.parent_list_entry.as_rib().unwrap();
            if afi_safi == AfiSafi::Ipv6Unicast {
                let iter = instance
                    .neighbors
                    .values()
                    .filter(|nbr| nbr.state == fsm::State::Established)
                    .map(move |nbr| ListEntry::RibNeighbor(afi_safi, nbr));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv6_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.in_pre.as_ref())
                                .map(|route| {
                                    ListEntry::RibV6AdjInPreRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_pre_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv6_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.in_post.as_ref())
                                .map(|route| {
                                    ListEntry::RibV6AdjInPostRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::best_path::PATH)
        .get_element_bool(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_adj_in_post_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_in_post_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv6_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.out_pre.as_ref())
                                .map(|route| {
                                    ListEntry::RibV6AdjOutPreRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_pre_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::PATH)
        .get_iterate(|instance, args| {
            let (_, nbr) = args.parent_list_entry.as_rib_neighbor().unwrap();
            if let Some(state) = &instance.state {
                let iter =
                    state.rib.tables.ipv6_unicast.prefixes.iter().filter_map(
                        |(prefix, dest)| {
                            dest.adj_rib
                                .get(&nbr.remote_addr)
                                .and_then(|adj_rib| adj_rib.out_post.as_ref())
                                .map(|route| {
                                    ListEntry::RibV6AdjOutPostRoute(prefix, route)
                                })
                        },
                    );
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::attr_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            Some(route.attrs.base.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            route.attrs.comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::ext_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            route.attrs.ext_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::large_community_index::PATH)
        .get_element_u64(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            route.attrs.large_comm.as_ref().map(|c| c.index)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::last_modified::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            Some(route.last_modified)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::eligible_route::PATH)
        .get_element_bool(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            Some(route.is_eligible())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::ineligible_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            route.ineligible_reason.as_ref().map(|r| r.to_yang().into())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_rib_v6_adj_out_post_route().unwrap();
            let iter = route.attrs.unknown.iter().map(ListEntry::RouteUnknownAttr);
            Some(Box::new(iter))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::optional::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::OPTIONAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::transitive::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::TRANSITIVE))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::partial::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::PARTIAL))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::extended::PATH)
        .get_element_bool(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.flags.contains(AttrFlags::EXTENDED))
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::attr_len::PATH)
        .get_element_u16(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.length)
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::attr_value::PATH)
        .get_element_binary(|_instance, args| {
            let attr = args.list_entry.as_route_unknown_attr().unwrap();
            Some(attr.value.to_vec())
        })
        .path(bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::reject_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_rib_v6_adj_out_post_route().unwrap();
            route.reject_reason.as_ref().map(|r| r.to_yang().into())
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-bgp:bgp'][name='test']/ietf-bgp:bgp";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::GlobalAfiSafi(afi_safi) => {
                use bgp::global::afi_safis::afi_safi::list_keys;
                let keys = list_keys(afi_safi.to_yang());
                Some(keys)
            }
            ListEntry::Neighbor(nbr) => {
                use bgp::neighbors::neighbor::list_keys;
                let keys = list_keys(nbr.remote_addr);
                Some(keys)
            }
            ListEntry::CapabilityAdv(index, cap) => {
                use bgp::neighbors::neighbor::capabilities::advertised_capabilities::list_keys;
                let keys = list_keys(cap.code() as u8, index);
                Some(keys)
            }
            ListEntry::CapabilityRcvd(index, cap) => {
                use bgp::neighbors::neighbor::capabilities::received_capabilities::list_keys;
                let keys = list_keys(cap.code() as u8, index);
                Some(keys)
            }
            ListEntry::Rib(afi_safi) => {
                use bgp::rib::afi_safis::afi_safi::list_keys;
                let keys = list_keys(afi_safi.to_yang());
                Some(keys)
            }
            ListEntry::RibBaseAttrs(attr_set) => {
                use bgp::rib::attr_sets::attr_set::list_keys;
                let keys = list_keys(attr_set.index);
                Some(keys)
            }
            ListEntry::RibComms(attr_set) => {
                use bgp::rib::communities::community::list_keys;
                let keys = list_keys(attr_set.index);
                Some(keys)
            }
            ListEntry::RibExtComms(attr_set) => {
                use bgp::rib::ext_communities::ext_community::list_keys;
                let keys = list_keys(attr_set.index);
                Some(keys)
            }
            ListEntry::RibExtv6Comms(attr_set) => {
                use bgp::rib::ipv6_ext_communities::ipv6_ext_community::list_keys;
                let keys = list_keys(attr_set.index);
                Some(keys)
            }
            ListEntry::RibLargeComms(attr_set) => {
                use bgp::rib::large_communities::large_community::list_keys;
                let keys = list_keys(attr_set.index);
                Some(keys)
            }
            ListEntry::RibNeighbor(_afi_safi, nbr) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::list_keys;
                let keys = list_keys(nbr.remote_addr);
                Some(keys)
            }
            ListEntry::RibV4LocRoute(prefix, route) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::loc_rib::routes::route::list_keys;
                let keys = list_keys(prefix, route.origin.to_yang(), 0);
                Some(keys)
            }
            ListEntry::RibV6LocRoute(prefix, route) => {
                use bgp::rib::afi_safis::afi_safi::ipv6_unicast::loc_rib::routes::route::list_keys;
                let keys = list_keys(prefix, route.origin.to_yang(), 0);
                Some(keys)
            }
            ListEntry::RibV4AdjInPreRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV6AdjInPreRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_pre::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV4AdjInPostRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV6AdjInPostRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_in_post::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV4AdjOutPreRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV6AdjOutPreRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_pre::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV4AdjOutPostRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RibV6AdjOutPostRoute(prefix, _route) => {
                use bgp::rib::afi_safis::afi_safi::ipv6_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::list_keys;
                let keys = list_keys(prefix, 0);
                Some(keys)
            }
            ListEntry::RouteUnknownAttr(attr) => {
                use bgp::rib::afi_safis::afi_safi::ipv4_unicast::neighbors::neighbor::adj_rib_out_post::routes::route::unknown_attributes::unknown_attribute::list_keys;
                let keys = list_keys(attr.attr_type);
                Some(keys)
            }
            ListEntry::CapabilityNego(_)
            | ListEntry::AddPathTuple(_)
            | ListEntry::RibComm(_)
            | ListEntry::RibExtComm(_)
            | ListEntry::RibExtv6Comm(_)
            | ListEntry::RibLargeComm(_)
            | ListEntry::RibAsPathSegment(_)
            | ListEntry::RibAsPathSegmentMember(_)
            | ListEntry::RibClusterList(_) => {
                // Keyless lists.
                None
            }
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
