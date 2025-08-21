//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock as Lazy;
use std::time::Instant;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::ospf;
use holo_utils::ip::IpAddrKind;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_utils::sr::{IgpAlgoType, Sid};
use holo_yang::{ToYang, ToYangBits};
use num_traits::FromPrimitive;

use crate::area::Area;
use crate::collections::LsdbSingleType;
use crate::instance::Instance;
use crate::interface::{Interface, ism};
use crate::lsdb::{LsaEntry, LsaLogEntry, LsaLogId};
use crate::neighbor::Neighbor;
use crate::packet::lsa::{LsaBodyVersion, LsaHdrVersion};
use crate::packet::tlv::{
    BierEncapSubStlv, BierStlv, GrReason, NodeAdminTagTlv, SidLabelRangeTlv,
    SrLocalBlockTlv, UnknownTlv,
};
use crate::route::{Nexthop, RouteNet};
use crate::spf::SpfLogEntry;
use crate::version::{Ospfv2, Ospfv3, Version};
use crate::{ospfv2, ospfv3};

pub static CALLBACKS_OSPFV2: Lazy<Callbacks<Instance<Ospfv2>>> =
    Lazy::new(load_callbacks_ospfv2);
pub static CALLBACKS_OSPFV3: Lazy<Callbacks<Instance<Ospfv3>>> =
    Lazy::new(load_callbacks_ospfv3);

#[derive(Debug, EnumAsInner)]
pub enum ListEntry<'a, V: Version> {
    None,
    SpfLog(&'a SpfLogEntry<V>),
    SpfTriggerLsa(&'a LsaLogId<V>),
    LsaLog(&'a LsaLogEntry<V>),
    Route(&'a V::IpNetwork, &'a RouteNet<V>),
    Nexthop(&'a Nexthop<V::IpAddr>),
    Hostname(&'a Ipv4Addr, &'a String),
    AsStatsLsaType(&'a LsdbSingleType<V>),
    AsLsaType(&'a LsdbSingleType<V>),
    AsLsa(&'a LsaEntry<V>),
    Area(&'a Area<V>),
    AreaStatsLsaType(&'a LsdbSingleType<V>),
    AreaLsaType(&'a LsdbSingleType<V>),
    AreaLsa(&'a LsaEntry<V>),
    Interface(&'a Interface<V>),
    InterfaceStatsLsaType(&'a LsdbSingleType<V>),
    InterfaceLsaType(&'a LsdbSingleType<V>),
    InterfaceLsa(&'a LsaEntry<V>),
    Neighbor(&'a Interface<V>, &'a Neighbor<V>),
    Msd(u8, u8),
    Srgb(&'a SidLabelRangeTlv),
    Srlb(&'a SrLocalBlockTlv),
    NodeAdminTagTlv(&'a NodeAdminTagTlv),
    NodeAdminTag(&'a u32),
    UnknownTlv(&'a UnknownTlv),
    Flag(&'static str),
    FlagU32(u32),
    // OSPFv2
    Ospfv2RouterLsaLink(&'a ospfv2::packet::lsa::LsaRouterLink),
    Ospfv2ExtPrefixTlv(&'a ospfv2::packet::lsa_opaque::ExtPrefixTlv),
    Ospfv2AdjSid(&'a ospfv2::packet::lsa_opaque::AdjSid),
    Ospfv2PrefixSid(&'a ospfv2::packet::lsa_opaque::PrefixSid),
    // OSPFv3
    Ospfv3RouterLsaLink(&'a ospfv3::packet::lsa::LsaRouterLink),
    Ospfv3LinkLsaPrefix(&'a ospfv3::packet::lsa::LsaLinkPrefix),
    Ospfv3AdjSids(&'a Vec<ospfv3::packet::lsa::AdjSid>),
    Ospfv3AdjSid(&'a ospfv3::packet::lsa::AdjSid),
    Ospfv3IntraAreaLsaPrefix(&'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry),
    Ospfv3PrefixSids(&'a BTreeMap<IgpAlgoType, ospfv3::packet::lsa::PrefixSid>),
    Ospfv3PrefixSid(&'a ospfv3::packet::lsa::PrefixSid),
    Ospfv3LinkLocalAddr(IpAddr),
    Ospfv3Biers(&'a Vec<BierStlv>),
    Ospfv3Bier(&'a BierStlv),
    Ospfv3BierEncaps(&'a Vec<BierEncapSubStlv>),
    Ospfv3BierEncap(&'a BierEncapSubStlv),
}

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(ospf::PATH)
        .get_object(|instance, _args| {
            use ospf::Ospf;
            Box::new(Ospf {
                router_id: instance.state.as_ref().map(|state| Cow::Owned(state.router_id)),
            })
        })
        .path(ospf::spf_control::ietf_spf_delay::PATH)
        .get_object(|instance, _args| {
            use ospf::spf_control::ietf_spf_delay::IetfSpfDelay;
            let mut current_state = None;
            let mut remaining_time_to_learn = None;
            let mut remaining_hold_down = None;
            let mut last_event_received = None;
            let mut next_spf_time = None;
            let mut last_spf_time = None;
            if let Some(state) = &instance.state {
                current_state = Some(state.spf_delay_state.to_yang());
                remaining_time_to_learn = state.spf_learn_timer.as_ref().map(|task| task.remaining());
                remaining_hold_down = state.spf_hold_down_timer.as_ref().map(|task| task.remaining());
                last_event_received = state.spf_last_event_rcvd.as_ref();
                next_spf_time = state.spf_delay_timer.as_ref().map(|timer| Instant::now() + timer.remaining());
                last_spf_time = state.spf_last_time.as_ref();
            }
            Box::new(IetfSpfDelay {
                current_state,
                remaining_time_to_learn: remaining_time_to_learn.map(Cow::Owned).ignore_in_testing(),
                remaining_hold_down: remaining_hold_down.map(Cow::Owned).ignore_in_testing(),
                last_event_received: last_event_received.map(Cow::Borrowed).ignore_in_testing(),
                next_spf_time: next_spf_time.map(Cow::Owned).ignore_in_testing(),
                last_spf_time: last_spf_time.map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(ospf::local_rib::route::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.rib.iter().map(|(destination, route)| ListEntry::Route(destination, route));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::local_rib::route::Route;
            let (prefix, route) = args.list_entry.as_route().unwrap();
            Box::new(Route {
                prefix: Cow::Owned((**prefix).into()),
                metric: Some(route.metric),
                route_type: Some(route.path_type.to_yang()),
                route_tag: route.tag,
            })
        })
        .path(ospf::local_rib::route::next_hops::next_hop::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();
            let iter = route.nexthops.values().map(ListEntry::Nexthop);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use ospf::local_rib::route::next_hops::next_hop::NextHop;
            let nexthop = args.list_entry.as_nexthop().unwrap();
            let iface = &instance.arenas.interfaces[nexthop.iface_idx];
            Box::new(NextHop {
                outgoing_interface: Some(iface.name.as_str().into()),
                next_hop: nexthop.addr.map(std::convert::Into::into).map(Cow::Owned),
            })
        })
        .path(ospf::statistics::PATH)
        .get_object(|instance, _args| {
            use ospf::statistics::Statistics;
            let mut discontinuity_time = None;
            let mut originate_new_lsa_count = None;
            let mut rx_new_lsas_count = None;
            let mut as_scope_lsa_count = None;
            let mut as_scope_lsa_chksum_sum = None;
            if let Some(state) = &instance.state {
                discontinuity_time = Some(Cow::Borrowed(&state.discontinuity_time)).ignore_in_testing();
                originate_new_lsa_count = Some(state.orig_lsa_count).ignore_in_testing();
                rx_new_lsas_count = Some(state.rx_lsa_count).ignore_in_testing();
                as_scope_lsa_count = Some(state.lsdb.lsa_count());
                as_scope_lsa_chksum_sum = Some(state.lsdb.cksum_sum()).ignore_in_testing();
            }
            Box::new(Statistics {
                discontinuity_time,
                originate_new_lsa_count,
                rx_new_lsas_count,
                as_scope_lsa_count,
                as_scope_lsa_chksum_sum,
            })
        })
        .path(ospf::statistics::database::as_scope_lsa_type::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.lsdb.iter_types().map(ListEntry::AsStatsLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::statistics::database::as_scope_lsa_type::AsScopeLsaType;
            let lsdb_type = args.list_entry.as_as_stats_lsa_type().unwrap();
            Box::new(AsScopeLsaType {
                lsa_type: Some(lsdb_type.lsa_type().into()),
                lsa_count: Some(lsdb_type.lsa_count()),
                lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
            })
        })
        .path(ospf::database::as_scope_lsa_type::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.lsdb.iter_types().map(ListEntry::AsLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::AsScopeLsaType;
            let lsdb_type = args.list_entry.as_as_lsa_type().unwrap();
            Box::new(AsScopeLsaType {
                lsa_type: lsdb_type.lsa_type().into(),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            let Some(_instance_state) = &instance.state else { return None };
            let lsdb_type = args.parent_list_entry.as_as_lsa_type().unwrap();
            let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::AsLsa(lse));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::AsScopeLsa;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(AsScopeLsa {
                lsa_id: lsa.hdr.lsa_id().to_string().into(),
                adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
                decode_completed: Some(!lsa.body.is_unknown()),
                raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
            })
        })
        .path(ospf::spf_log::event::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.spf_log.iter().map(ListEntry::SpfLog);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use ospf::spf_log::event::Event;
            let log = args.list_entry.as_spf_log().unwrap();
            Box::new(Event {
                id: log.id,
                spf_type: Some(log.spf_type.to_yang()),
                schedule_timestamp: Some(Cow::Borrowed(&log.schedule_time)),
                start_timestamp: Some(Cow::Borrowed(&log.start_time)),
                end_timestamp: Some(Cow::Borrowed(&log.end_time)),
            })
        })
        .path(ospf::spf_log::event::trigger_lsa::PATH)
        .get_iterate(|_instance, args| {
            let log = args.parent_list_entry.as_spf_log().unwrap();
            let iter = log.trigger_lsas.iter().map(ListEntry::SpfTriggerLsa);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::spf_log::event::trigger_lsa::TriggerLsa;
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            Box::new(TriggerLsa {
                area_id: lsa_id.area_id.map(Cow::Owned),
                r#type: Some(lsa_id.lsa_type.into()),
                lsa_id: Some(lsa_id.lsa_id.to_string().into()),
                adv_router: Some(Cow::Owned(lsa_id.adv_rtr)),
                seq_num: Some(lsa_id.seq_no).ignore_in_testing(),
            })
        })
        .path(ospf::lsa_log::event::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.lsa_log.iter().map(ListEntry::LsaLog);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use ospf::lsa_log::event::Event;
            let log = args.list_entry.as_lsa_log().unwrap();
            Box::new(Event {
                id: log.id,
                received_timestamp: log.rcvd_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                reason: Some(log.reason.to_yang()),
            })
        })
        .path(ospf::lsa_log::event::lsa::PATH)
        .get_object(|_instance, args| {
            use ospf::lsa_log::event::lsa::Lsa;
            let log = args.list_entry.as_lsa_log().unwrap();
            Box::new(Lsa {
                area_id: log.lsa.area_id.map(Cow::Owned),
                r#type: Some(log.lsa.lsa_type.into()),
                lsa_id: Some(log.lsa.lsa_id.to_string().into()),
                adv_router: Some(Cow::Owned(log.lsa.adv_rtr)),
                seq_num: Some(log.lsa.seq_no).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.arenas.areas.iter().map(ListEntry::Area);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::Area;
            let area = args.list_entry.as_area().unwrap();
            Box::new(Area {
                area_id: Cow::Owned(area.area_id),
            })
        })
        .path(ospf::areas::area::statistics::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::statistics::Statistics;
            let area = args.list_entry.as_area().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&area.state.discontinuity_time)).ignore_in_testing(),
                spf_runs_count: Some(area.state.spf_run_count).ignore_in_testing(),
                abr_count: Some(area.abr_count() as _),
                asbr_count: Some(area.asbr_count() as _),
                area_scope_lsa_count: Some(area.state.lsdb.lsa_count()),
                area_scope_lsa_cksum_sum: Some(area.state.lsdb.cksum_sum()).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::statistics::database::area_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area.state.lsdb.iter_types().map(ListEntry::AreaStatsLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::statistics::database::area_scope_lsa_type::AreaScopeLsaType;
            let lsdb_type = args.list_entry.as_area_stats_lsa_type().unwrap();
            Box::new(AreaScopeLsaType {
                lsa_type: Some(lsdb_type.lsa_type().into()),
                lsa_count: Some(lsdb_type.lsa_count()),
                lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area.state.lsdb.iter_types().map(ListEntry::AreaLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::AreaScopeLsaType;
            let lsdb_type = args.list_entry.as_area_lsa_type().unwrap();
            Box::new(AreaScopeLsaType {
                lsa_type: lsdb_type.lsa_type().into(),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            let Some(_instance_state) = &instance.state else { return None };
            let lsdb_type = args.parent_list_entry.as_area_lsa_type().unwrap();
            let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::AreaLsa(lse));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::AreaScopeLsa;
            let lse = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(AreaScopeLsa {
                lsa_id: lsa.hdr.lsa_id().to_string().into(),
                adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
                decode_completed: Some(!lsa.body.is_unknown()),
                raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::PATH)
        .get_iterate(|instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area.interfaces.iter(&instance.arenas.interfaces).map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use ospf::areas::area::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            let mut dr_router_id = None;
            let mut dr_ip_addr = None;
            let mut bdr_router_id = None;
            let mut bdr_ip_addr = None;
            if let Some(instance_state) = &instance.state {
                if iface.state.ism_state == ism::State::Dr {
                    dr_router_id = Some(instance_state.router_id);
                    dr_ip_addr = Some(iface.state.src_addr.unwrap().into());
                } else if let Some(dr_net_id) = iface.state.dr
                    && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
                {
                    dr_router_id = Some(nbr.router_id);
                    dr_ip_addr = Some(nbr.src.into());
                }
                if iface.state.ism_state == ism::State::Backup {
                    bdr_router_id = Some(instance_state.router_id);
                    bdr_ip_addr = Some(iface.state.src_addr.unwrap().into());
                } else if let Some(bdr_net_id) = iface.state.bdr
                    && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
                {
                    bdr_router_id = Some(nbr.router_id);
                    bdr_ip_addr = Some(nbr.src.into());
                }
            }
            Box::new(Interface {
                name: iface.name.as_str().into(),
                state: Some(iface.state.ism_state.to_yang()),
                hello_timer: iface.state.tasks.hello_interval.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                wait_timer: iface.state.tasks.wait_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                dr_router_id: dr_router_id.map(Cow::Owned),
                dr_ip_addr: dr_ip_addr.map(Cow::Owned),
                bdr_router_id: bdr_router_id.map(Cow::Owned),
                bdr_ip_addr: bdr_ip_addr.map(Cow::Owned),
                interface_id: if V::PROTOCOL == Protocol::OSPFV3 { iface.system.ifindex } else { None },
            })
        })
        .path(ospf::areas::area::interfaces::interface::statistics::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::statistics::Statistics;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
                if_event_count: Some(iface.state.event_count).ignore_in_testing(),
                link_scope_lsa_count: Some(iface.state.lsdb.lsa_count()),
                link_scope_lsa_cksum_sum: Some(iface.state.lsdb.cksum_sum()).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceStatsLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::LinkScopeLsaType;
            let lsdb_type = args.list_entry.as_interface_stats_lsa_type().unwrap();
            Box::new(LinkScopeLsaType {
                lsa_type: Some(lsdb_type.lsa_type().into()),
                lsa_count: Some(lsdb_type.lsa_count()),
                lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.state.neighbors.iter(&instance.arenas.neighbors).map(|nbr| ListEntry::Neighbor(iface, nbr));
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use ospf::areas::area::interfaces::interface::neighbors::neighbor::Neighbor;
            let (iface, nbr) = args.list_entry.as_neighbor().unwrap();
            let mut dr_router_id = None;
            let mut dr_ip_addr = None;
            let mut bdr_router_id = None;
            let mut bdr_ip_addr = None;
            if let Some(instance_state) = &instance.state {
                if let Some(dr_net_id) = nbr.dr
                    && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
                {
                    dr_router_id = Some(nbr.router_id);
                    dr_ip_addr = Some(nbr.src.into());
                } else {
                    let iface_src_addr = iface.state.src_addr.unwrap();
                    let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                    if nbr.dr == Some(iface_net_id) {
                        dr_router_id = Some(instance_state.router_id);
                        dr_ip_addr = Some(iface_src_addr.into());
                    }
                }
                if let Some(bdr_net_id) = nbr.bdr
                    && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
                {
                    bdr_router_id = Some(nbr.router_id);
                    bdr_ip_addr = Some(nbr.src.into());
                } else {
                    let iface_src_addr = iface.state.src_addr.unwrap();
                    let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                    if nbr.bdr == Some(iface_net_id) {
                        bdr_router_id = Some(instance_state.router_id);
                        bdr_ip_addr = Some(iface_src_addr.into());
                    }
                }
            }
            Box::new(Neighbor {
                neighbor_router_id: Cow::Owned(nbr.router_id),
                address: Some(Cow::Owned(nbr.src.into())),
                dr_router_id: dr_router_id.map(Cow::Owned),
                dr_ip_addr: dr_ip_addr.map(Cow::Owned),
                bdr_router_id: bdr_router_id.map(Cow::Owned),
                bdr_ip_addr: bdr_ip_addr.map(Cow::Owned),
                state: Some(nbr.state.to_yang()),
                dead_timer: nbr.tasks.inactivity_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::Statistics;
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&nbr.discontinuity_time)).ignore_in_testing(),
                nbr_event_count: Some(nbr.event_count).ignore_in_testing(),
                nbr_retrans_qlen: Some(nbr.lists.ls_rxmt.len() as u32),
            })
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::GracefulRestart;
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            let mut restart_reason = None;
            let mut grace_timer = None;
            if let Some(gr) = &nbr.gr {
                restart_reason = Some(gr.restart_reason.to_yang());
                grace_timer = Some(gr.grace_period.remaining().as_secs().saturating_into());
            }
            Box::new(GracefulRestart {
                restart_reason,
                grace_timer: grace_timer.ignore_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.state.lsdb.iter_types().map(ListEntry::InterfaceLsaType);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::LinkScopeLsaType;
            let lsdb_type = args.list_entry.as_interface_lsa_type().unwrap();
            Box::new(LinkScopeLsaType {
                lsa_type: lsdb_type.lsa_type().into(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            let Some(_instance_state) = &instance.state else { return None };
            let lsdb_type = args.parent_list_entry.as_interface_lsa_type().unwrap();
            let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| ListEntry::InterfaceLsa(lse));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::LinkScopeLsa;
            let lse = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(LinkScopeLsa {
                lsa_id: lsa.hdr.lsa_id().to_string().into(),
                adv_router: Cow::Owned(lsa.hdr.adv_rtr()),
                decode_completed: Some(!lsa.body.is_unknown()),
                raw_data: Some(lsa.raw.as_ref()).ignore_in_testing(),
            })
        })
        .path(ospf::hostnames::hostname::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.hostnames.iter().map(|(router_id, hostname)| ListEntry::Hostname(router_id, hostname));
            Some(Box::new(iter) as _)
        })
        .get_object(|_instance, args| {
            use ospf::hostnames::hostname::Hostname;
            let (router_id, hostname) = args.list_entry.as_hostname().unwrap();
            Box::new(Hostname {
                router_id: Cow::Borrowed(router_id),
                hostname: Some(Cow::Borrowed(hostname)),
            })
        })
        .build()
}

fn load_callbacks_ospfv2() -> Callbacks<Instance<Ospfv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::Header;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
            Box::new(Header {
                lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
                opaque_type,
                opaque_id,
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(LsaOptions {
                lsa_options: Some(Box::new(iter)),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::External;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(External {
                network_mask: lsa.body.as_as_external().map(|lsa_body| lsa_body.mask).map(Cow::Owned),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let _lsa_body = lsa.body.as_as_external()?;
            let iter = std::iter::once(lse).map(ListEntry::AsLsa);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::Topology;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_as_external().unwrap();
            Box::new(Topology {
                mt_id: Some(0),
                flags: Some(lsa_body.flags.to_yang()),
                metric: Some(lsa_body.metric),
                forwarding_address: lsa_body.fwd_addr.map(Cow::Owned),
                external_route_tag: Some(lsa_body.tag),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let mut hostname = None;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_hostname) = &lsa_body.info_hostname {
                    hostname = Some(Cow::Borrowed(info_hostname.get()));
            }
            Box::new(DynamicHostnameTlv {
                hostname,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds
            {
                let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(MsdType {
                msd_type: Some(*msd_type),
                msd_value: Some(*msd_value),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let mut sr_algorithm = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
                sr_algorithm = Some(Box::new(iter) as _);
            }
            Box::new(SrAlgorithmTlv {
                sr_algorithm,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv;
            let srgb = args.list_entry.as_srgb().unwrap();
            let mut stlv = SidRangeTlv::default();
            stlv.range_size = Some(srgb.range);
            match srgb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv;
            let srlb = args.list_entry.as_srlb().unwrap();
            let mut stlv = LocalBlockTlv::default();
            stlv.range_size = Some(srlb.range);
            match srlb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let mut preference = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                preference = lsa_body.srms_pref.as_ref().map(|tlv| tlv.get());
            }
            Box::new(SrmsPreferenceTlv {
                preference,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_ext_prefix()
            {
                let iter = lsa_body.prefixes.values().map(ListEntry::Ospfv2ExtPrefixTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv;
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Box::new(ExtendedPrefixTlv {
                route_type: Some(tlv.route_type.to_yang()),
                prefix: Some(Cow::Owned(tlv.prefix.into())),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags;
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Flags {
                extended_prefix_flags: Some(Box::new(iter)),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv.prefix_sids.values().map(ListEntry::Ospfv2PrefixSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            let mut stlv = PrefixSidSubTlv::default();
            stlv.mt_id = Some(0);
            stlv.algorithm = Some(prefix_sid.algo.to_yang());
            match prefix_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::Header;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
            Box::new(Header {
                lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
                opaque_type,
                opaque_id,
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(LsaOptions {
                lsa_options: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::Router;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(Router {
                num_of_links: lsa.body.as_router().map(|lsa_body| lsa_body.links.len() as u16),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::router_bits::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::router_bits::RouterBits;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut rtr_lsa_bits = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router() {
                let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
                rtr_lsa_bits = Some(Box::new(iter) as _);
            }
            Box::new(RouterBits {
                rtr_lsa_bits,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router() {
                let iter = lsa_body.links.iter().map(ListEntry::Ospfv2RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::Link;
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Box::new(Link {
                link_id: Some(rtr_link.link_id.to_string().into()),
                link_data: Some(rtr_link.link_data.to_string().into()),
                r#type: Some(rtr_link.link_type.to_yang()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let rtr_link = args.parent_list_entry.as_ospfv2_router_lsa_link().unwrap();
            let iter = std::iter::once(*rtr_link).map(ListEntry::Ospfv2RouterLsaLink);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::Topology;
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Box::new(Topology {
                mt_id: Some(0),
                metric: Some(rtr_link.metric),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::Network;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let mut network_mask = None;
            if let Some(lsa_body) = lsa.body.as_network() {
                network_mask = Some(Cow::Owned(lsa_body.mask));
            }
            Box::new(Network {
                network_mask,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::attached_routers::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::attached_routers::AttachedRouters;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut attached_router = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_network() {
                let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
                attached_router = Some(Box::new(iter) as _);
            }
            Box::new(AttachedRouters {
                attached_router,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::Summary;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(Summary {
                network_mask: lsa.body.as_summary().map(|lsa_body| lsa_body.mask).map(Cow::Owned),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(_lsa_body) = lsa.body.as_summary() {
                let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::Topology;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_summary().unwrap();
            Box::new(Topology {
                mt_id: Some(0),
                metric: Some(lsa_body.metric),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.node_tags.iter().map(ListEntry::NodeAdminTagTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::node_tag::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_node_admin_tag_tlv().unwrap();
            let iter = tlv.tags.iter().map(ListEntry::NodeAdminTag);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag;
            let tag = args.list_entry.as_node_admin_tag().unwrap();
            Box::new(NodeTag {
                tag: Some(**tag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let mut hostname = None;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_hostname) = &lsa_body.info_hostname {
                    hostname = Some(Cow::Borrowed(info_hostname.get()));
            }
            Box::new(DynamicHostnameTlv {
                hostname,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds
            {
                let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(MsdType {
                msd_type: Some(*msd_type),
                msd_value: Some(*msd_value),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut sr_algorithm = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
                sr_algorithm = Some(Box::new(iter) as _);
            }
            Box::new(SrAlgorithmTlv {
                sr_algorithm,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv;
            let srgb = args.list_entry.as_srgb().unwrap();
            let mut stlv = SidRangeTlv::default();
            stlv.range_size = Some(srgb.range);
            match srgb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv;
            let srlb = args.list_entry.as_srlb().unwrap();
            let mut stlv = LocalBlockTlv::default();
            stlv.range_size = Some(srlb.range);
            match srlb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut preference = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                preference = lsa_body.srms_pref.as_ref().map(|tlv| tlv.get());
            }
            Box::new(SrmsPreferenceTlv {
                preference,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_prefix()
            {
                let iter = lsa_body.prefixes.values().map(ListEntry::Ospfv2ExtPrefixTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv;
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Box::new(ExtendedPrefixTlv {
                route_type: Some(tlv.route_type.to_yang()),
                prefix: Some(Cow::Owned(tlv.prefix.into())),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags;
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let flags = tlv.flags.to_yang_bits();
            let iter = flags.into_iter().map(|flag| flag.to_string().into());
            Box::new(Flags {
                extended_prefix_flags: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv.prefix_sids.values().map(ListEntry::Ospfv2PrefixSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            let mut stlv = PrefixSidSubTlv::default();
            stlv.mt_id = Some(0);
            stlv.algorithm = Some(prefix_sid.algo.to_yang());
            match prefix_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::ExtendedLinkTlv;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let mut link_id = None;
            let mut link_data = None;
            let mut r#type = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
            {
                link_id = Some(tlv.link_id.to_string().into());
                link_data = Some(tlv.link_data.to_string().into());
                r#type = Some(tlv.link_type.to_yang());
            }
            Box::new(ExtendedLinkTlv {
                link_id,
                link_data,
                r#type,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
                && let Some(msds) = &tlv.msds
            {
                let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::MsdType;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(MsdType {
                msd_type: Some(*msd_type),
                msd_value: Some(*msd_value),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
            {
                let iter = tlv.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
            {
                let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none()).map(ListEntry::Ospfv2AdjSid);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv;
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            let mut stlv = AdjSidSubTlv::default();
            stlv.mt_id = Some(0);
            stlv.weight = Some(adj_sid.weight);
            match adj_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags;
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(AdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
            {
                let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some()).map(ListEntry::Ospfv2AdjSid);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv;
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            let mut stlv = LanAdjSidSubTlv::default();
            stlv.mt_id = Some(0);
            stlv.weight = Some(adj_sid.weight);
            stlv.neighbor_router_id = Some(Cow::Owned(adj_sid.nbr_router_id.unwrap()));
            match adj_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags;
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(LanAdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::Header;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
            Box::new(Header {
                lsa_id: Some(Cow::Owned(lsa.hdr.lsa_id)),
                opaque_type,
                opaque_id,
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            let iter = lsa.hdr.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(LsaOptions {
                lsa_options: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_interface_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds
            {
                let iter = msds.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(MsdType {
                msd_type: Some(*msd_type),
                msd_value: Some(*msd_value),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
            {
                let iter = lsa_body.unknown_tlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::Grace;
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_interface_lsa().unwrap();
            let mut grace_period = None;
            let mut graceful_restart_reason = None;
            let mut ip_interface_address = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_grace()
            {
                if let Some(grace_period_tlv) = &lsa_body.grace_period {
                    grace_period = Some(grace_period_tlv.get());
                }
                if let Some(gr_reason) = &lsa_body.gr_reason
                    && let Some(gr_reason) = GrReason::from_u8(gr_reason.get())
                {
                    graceful_restart_reason = Some(gr_reason.to_yang());
                }
                if let Some(addr) = &lsa_body.addr {
                    ip_interface_address = Some(Cow::Owned(addr.get()));
                }
            }
            Box::new(Grace {
                grace_period,
                graceful_restart_reason,
                ip_interface_address,
            })
        })
        .build()
}

fn load_callbacks_ospfv3() -> Callbacks<Instance<Ospfv3>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::Header;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(Header {
                lsa_id: Some(lsa.hdr.lsa_id.into()),
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::AsExternal;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let mut metric = None;
            let mut flags = None;
            let mut referenced_ls_type = None;
            let mut unknown_referenced_ls_type = None;
            let mut prefix = None;
            let mut forwarding_address = None;
            let mut external_route_tag = None;
            let mut referenced_link_state_id = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_as_external() {
                metric = Some(lsa_body.metric);
                flags = Some(lsa_body.flags.to_yang());
                referenced_ls_type = lsa_body.ref_lsa_type.map(|lsa_type| lsa_type.to_yang());
                unknown_referenced_ls_type = lsa_body.ref_lsa_type.and_then(|ref_lsa_type| if ref_lsa_type.function_code().is_none() { Some(ref_lsa_type.0) } else { None });
                prefix = Some(Cow::Borrowed(&lsa_body.prefix));
                forwarding_address = lsa_body.fwd_addr.map(|addr| {
                    Cow::Owned(match addr {
                        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                        IpAddr::V6(addr) => addr,
                    })
                });
                external_route_tag = lsa_body.tag;
                referenced_link_state_id = lsa_body.ref_lsa_id.map(|lsa_id| lsa_id.into());
            }
            Box::new(AsExternal {
                metric,
                flags,
                referenced_ls_type,
                unknown_referenced_ls_type,
                prefix,
                forwarding_address,
                external_route_tag,
                referenced_link_state_id,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix_options::PrefixOptions;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let mut prefix_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_as_external() {
                let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
                prefix_options = Some(Box::new(iter) as _);
            }
            Box::new(PrefixOptions {
                prefix_options,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let mut hostname = None;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_hostname) = &lsa_body.info_hostname {
                    hostname = Some(Cow::Borrowed(info_hostname.get()));
            }
            Box::new(DynamicHostnameTlv {
                hostname,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let mut sr_algorithm = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
                sr_algorithm = Some(Box::new(iter) as _);
            }
            Box::new(SrAlgorithmTlv {
                sr_algorithm,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv;
            let srgb = args.list_entry.as_srgb().unwrap();
            let mut stlv = SidRangeTlv::default();
            stlv.range_size = Some(srgb.range);
            match srgb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv;
            let srlb = args.list_entry.as_srlb().unwrap();
            let mut stlv = LocalBlockTlv::default();
            stlv.range_size = Some(srlb.range);
            match srlb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(SrmsPreferenceTlv {
                preference: lsa.body.as_router_info().and_then(|lsa_body| lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if lsa.body.as_ext_as_external().is_some() {
                let iter = std::iter::once(lse).map(ListEntry::AsLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::ExternalPrefixTlv;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let mut metric = None;
            let mut prefix = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_as_external() {
                metric = Some(lsa_body.metric);
                prefix = Some(Cow::Borrowed(&lsa_body.prefix));
            }
            Box::new(ExternalPrefixTlv {
                metric,
                prefix,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::flags::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::flags::Flags;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let mut ospfv3_e_external_prefix_bits = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_as_external() {
                let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
                ospfv3_e_external_prefix_bits = Some(Box::new(iter) as _);
            }
            Box::new(Flags {
                ospfv3_e_external_prefix_bits,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_options::PrefixOptions;
            let lse = args.list_entry.as_as_lsa().unwrap();
            let mut prefix_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_as_external() {
                let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
                prefix_options = Some(Box::new(iter) as _);
            }
            Box::new(PrefixOptions {
                prefix_options,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv6_fwd_addr_sub_tlv::PATH)
        .get_object(|_instance, _args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv6_fwd_addr_sub_tlv::Ipv6FwdAddrSubTlv;
            Box::new(Ipv6FwdAddrSubTlv {
                // TODO
                forwarding_address: None,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv4_fwd_addr_sub_tlv::PATH)
        .get_object(|_instance, _args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv4_fwd_addr_sub_tlv::Ipv4FwdAddrSubTlv;
            Box::new(Ipv4FwdAddrSubTlv {
                // TODO
                forwarding_address: None,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::route_tag_sub_tlv::PATH)
        .get_object(|_instance, _args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::route_tag_sub_tlv::RouteTagSubTlv;
            Box::new(RouteTagSubTlv {
                // TODO
                route_tag: None,
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sids = args.parent_list_entry.as_ospfv3_prefix_sids()?;
            let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let mut stlv = PrefixSidSubTlv::default();
            stlv.algorithm = Some(prefix_sid.algo.to_yang());
            match prefix_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Ospfv3PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::Header;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(Header {
                lsa_id: Some(lsa.hdr.lsa_id.into()),
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::router_bits::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::router_bits::RouterBits;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut rtr_lsa_bits = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
                rtr_lsa_bits = Some(Box::new(iter) as _);
            }
            Box::new(RouterBits {
                rtr_lsa_bits,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let iter = lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::Link;
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Box::new(Link {
                interface_id: Some(rtr_link.iface_id),
                neighbor_interface_id: Some(rtr_link.nbr_iface_id),
                neighbor_router_id: Some(Cow::Owned(rtr_link.nbr_router_id)),
                r#type: Some(rtr_link.link_type.to_yang()),
                metric: Some(rtr_link.metric),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_network() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::attached_routers::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::attached_routers::AttachedRouters;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut attached_router = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_network() {
                let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
                attached_router = Some(Box::new(iter) as _);
            }
            Box::new(AttachedRouters {
                attached_router,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::InterAreaPrefix;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut metric = None;
            let mut prefix = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_prefix() {
                metric = Some(lsa_body.metric);
                prefix = Some(Cow::Borrowed(&lsa_body.prefix));
            }
            Box::new(InterAreaPrefix {
                metric,
                prefix,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::PrefixOptions;
            let lse = args.list_entry.as_area_lsa().unwrap();
            let mut prefix_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_prefix() {
                let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
                prefix_options = Some(Box::new(iter) as _);
            }
            Box::new(PrefixOptions {
                prefix_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::InterAreaRouter;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut metric = None;
            let mut destination_router_id = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_router() {
                metric = Some(lsa_body.metric);
                destination_router_id = Some(Cow::Owned(lsa_body.router_id));
            }
            Box::new(InterAreaRouter {
                metric,
                destination_router_id,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_router() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::IntraAreaPrefix;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut referenced_ls_type = None;
            let mut unknown_referenced_ls_type = None;
            let mut referenced_link_state_id = None;
            let mut referenced_adv_router = None;
            let mut num_of_prefixes = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_intra_area_prefix() {
                referenced_ls_type = Some(lsa_body.ref_lsa_type.to_yang());
                unknown_referenced_ls_type = if lsa_body.ref_lsa_type.function_code().is_none() { Some(lsa_body.ref_lsa_type.0) } else { None };
                referenced_link_state_id = Some(lsa_body.ref_lsa_id.into());
                referenced_adv_router = Some(Cow::Owned(lsa_body.ref_adv_rtr));
                num_of_prefixes = Some(lsa_body.prefixes.len() as _);
            }
            Box::new(IntraAreaPrefix {
                referenced_ls_type,
                unknown_referenced_ls_type,
                referenced_link_state_id,
                referenced_adv_router,
                num_of_prefixes,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_intra_area_prefix() {
                let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3IntraAreaLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::Prefix;
            let prefix = args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Box::new(Prefix {
                prefix: Some(Cow::Borrowed(&prefix.value)),
                metric: Some(prefix.metric),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::PrefixOptions;
            let prefix = args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixOptions {
                prefix_options: Some(Box::new(iter) as _),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.node_tags.iter().map(ListEntry::NodeAdminTagTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::node_tag::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_node_admin_tag_tlv().unwrap();
            let iter = tlv.tags.iter().map(ListEntry::NodeAdminTag);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag;
            let tag = args.list_entry.as_node_admin_tag().unwrap();
            Box::new(NodeTag {
                tag: Some(**tag),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let mut hostname = None;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_hostname) = &lsa_body.info_hostname {
                    hostname = Some(Cow::Borrowed(info_hostname.get()));
            }
            Box::new(DynamicHostnameTlv {
                hostname,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut sr_algorithm = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
                sr_algorithm = Some(Box::new(iter) as _);
            }
            Box::new(SrAlgorithmTlv {
                sr_algorithm,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv;
            let srgb = args.list_entry.as_srgb().unwrap();
            let mut stlv = SidRangeTlv::default();
            stlv.range_size = Some(srgb.range);
            match srgb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv;
            let srlb = args.list_entry.as_srlb().unwrap();
            let mut stlv = LocalBlockTlv::default();
            stlv.range_size = Some(srlb.range);
            match srlb.first {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(SrmsPreferenceTlv {
                preference: lsa.body.as_router_info().and_then(|lsa_body| lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::router_bits::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::router_bits::RouterBits;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut rtr_lsa_bits = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let iter = lsa_body.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
                rtr_lsa_bits = Some(Box::new(iter) as _);
            }
            Box::new(RouterBits {
                rtr_lsa_bits,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let iter = lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::LinkTlv;
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Box::new(LinkTlv {
                interface_id: Some(rtr_link.iface_id),
                neighbor_interface_id: Some(rtr_link.nbr_iface_id),
                neighbor_router_id: Some(Cow::Owned(rtr_link.nbr_router_id)),
                r#type: Some(rtr_link.link_type.to_yang()),
                metric: Some(rtr_link.metric),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv3_router_lsa_link().unwrap();
            let iter = tlv.unknown_stlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3AdjSids(&tlv.adj_sids)));
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let adj_sids = args.parent_list_entry.as_ospfv3_adj_sids()?;
            let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none()).map(ListEntry::Ospfv3AdjSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv;
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            let mut stlv = AdjSidSubTlv::default();
            stlv.weight = Some(adj_sid.weight);
            match adj_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags;
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(AdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let adj_sids = args.parent_list_entry.as_ospfv3_adj_sids()?;
            let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some()).map(ListEntry::Ospfv3AdjSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv;
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            let mut stlv = LanAdjSidSubTlv::default();
            stlv.weight = Some(adj_sid.weight);
            stlv.neighbor_router_id = Some(Cow::Owned(adj_sid.nbr_router_id.unwrap()));
            match adj_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags;
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            let iter = adj_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(LanAdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_network() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // Nothing to do.
            None
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::attached_router_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::attached_router_tlv::AttachedRouterTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut adjacent_neighbor_router_id = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_network() {
                let iter = lsa_body.attached_rtrs.iter().map(Cow::Borrowed);
                adjacent_neighbor_router_id = Some(Box::new(iter) as _);
            }
            Box::new(AttachedRouterTlv {
                adjacent_neighbor_router_id,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if lsa.body.as_ext_inter_area_prefix().is_some() {
                let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::InterPrefixTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut metric = None;
            let mut prefix = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_prefix() {
                metric = Some(lsa_body.metric);
                prefix = Some(Cow::Borrowed(&lsa_body.prefix));
            }
            Box::new(InterPrefixTlv {
                metric,
                prefix,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_options::PrefixOptions;
            let lse = args.list_entry.as_area_lsa().unwrap();
            let mut prefix_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_prefix() {
                let iter = lsa_body.prefix_options.to_yang_bits().into_iter().map(Cow::Borrowed);
                prefix_options = Some(Box::new(iter) as _);
            }
            Box::new(PrefixOptions {
                prefix_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_prefix() {
                let iter = lsa_body.unknown_stlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3PrefixSids(&lsa_body.prefix_sids)));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sids = args.parent_list_entry.as_ospfv3_prefix_sids()?;
            let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let mut stlv = PrefixSidSubTlv::default();
            stlv.algorithm = Some(prefix_sid.algo.to_yang());
            match prefix_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Ospfv3PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if lsa.body.as_ext_inter_area_router().is_some() {
                let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::InterRouterTlv;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut metric = None;
            let mut destination_router_id = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                metric = Some(lsa_body.metric);
                destination_router_id = Some(Cow::Owned(lsa_body.router_id));
            }
            Box::new(InterRouterTlv {
                metric,
                destination_router_id,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                let iter = lsa_body.unknown_stlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::EIntraAreaPrefix;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let mut referenced_ls_type = None;
            let mut referenced_link_state_id = None;
            let mut referenced_adv_router = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_intra_area_prefix() {
                referenced_ls_type = Some(lsa_body.ref_lsa_type.into());
                referenced_link_state_id = Some(lsa_body.ref_lsa_id.into());
                referenced_adv_router = Some(Cow::Owned(lsa_body.ref_adv_rtr));
            }
            Box::new(EIntraAreaPrefix {
                referenced_ls_type,
                referenced_link_state_id,
                referenced_adv_router,
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_intra_area_prefix() {
                let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3IntraAreaLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::IntraPrefixTlv;
            let prefix = args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Box::new(IntraPrefixTlv {
                metric: Some(prefix.metric as u32),
                prefix: Some(Cow::Borrowed(&prefix.value)),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions;
            let prefix = args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixOptions {
                prefix_options: Some(Box::new(iter) as _),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let prefix = args.parent_list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            let mut iter: Box<dyn Iterator<Item = ListEntry<'_, _>>>;
            iter = Box::new(prefix.unknown_stlvs.iter().map(ListEntry::UnknownTlv));
            if !prefix.prefix_sids.is_empty() {
                iter = Box::new(iter.chain(std::iter::once(ListEntry::Ospfv3PrefixSids(&prefix.prefix_sids))));
            }
            if !prefix.bier.is_empty() {
                iter = Box::new(iter.chain(std::iter::once(ListEntry::Ospfv3Biers(&prefix.bier))));
            }
            Some(iter)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sids = args.parent_list_entry.as_ospfv3_prefix_sids()?;
            let iter = prefix_sids.values().map(ListEntry::Ospfv3PrefixSid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let mut stlv = PrefixSidSubTlv::default();
            stlv.algorithm = Some(prefix_sid.algo.to_yang());
            match prefix_sid.sid {
                Sid::Index(index) => {
                    stlv.index_value = Some(index);
                },
                Sid::Label(label) => {
                    stlv.label_value = Some(label.get());
                },
            };
            Box::new(stlv)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let biers = args.parent_list_entry.as_ospfv3_biers()?;
            let iter = biers.iter().map(ListEntry::Ospfv3Bier);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::BierInfoSubTlv;
            let bier = args.list_entry.as_ospfv3_bier().unwrap();
            Box::new(BierInfoSubTlv{
                sub_domain_id: Some(bier.sub_domain_id),
                mt_id: Some(bier.mt_id),
                bfr_id: Some(bier.bfr_id),
                bar: Some(bier.bar),
                ipa: Some(bier.ipa),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let bier = args.parent_list_entry.as_ospfv3_bier().unwrap();
            let iter = bier.unknown_sstlvs.iter().map(ListEntry::UnknownTlv).chain(std::iter::once(ListEntry::Ospfv3BierEncaps(&bier.encaps)));
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::bier_encap_sub_sub_tlvs::bier_encap_sub_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let bier_encaps = args.parent_list_entry.as_ospfv3_bier_encaps()?;
            let iter = bier_encaps.iter().map(ListEntry::Ospfv3BierEncap);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::bier_encap_sub_sub_tlvs::bier_encap_sub_sub_tlv::BierEncapSubSubTlv;
            let bier_encap = args.list_entry.as_ospfv3_bier_encap().unwrap();
            Box::new(BierEncapSubSubTlv {
                max_si: Some(bier_encap.max_si),
                id: Some(bier_encap.id.clone().get()),
                bs_len: Some(bier_encap.bs_len)
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags;
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            let iter = prefix_sid.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Ospfv3PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::Header;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(Header {
                lsa_id: Some(lsa.hdr.lsa_id.into()),
                age: Some(lsa.age()).ignore_in_testing(),
                r#type: Some(lsa.hdr.lsa_type.to_yang()),
                adv_router: Some(Cow::Owned(lsa.hdr.adv_rtr)),
                seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
                checksum: Some(lsa.hdr.cksum).ignore_in_testing(),
                length: Some(lsa.hdr.length),
                maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::Link;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let mut rtr_priority = None;
            let mut link_local_interface_address = None;
            let mut num_of_prefixes = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_link() {
                rtr_priority = Some(lsa_body.priority);
                link_local_interface_address = Some(Cow::Owned(match lsa_body.linklocal {
                    IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                    IpAddr::V6(addr) => addr,
                }));
                num_of_prefixes = Some(lsa_body.prefixes.len() as _);
            }
            Box::new(Link {
                rtr_priority,
                link_local_interface_address,
                num_of_prefixes,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_link() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_link() {
                let iter = lsa_body.prefixes.iter().map(ListEntry::Ospfv3LinkLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::Prefix;
            let prefix = args.list_entry.as_ospfv3_link_lsa_prefix().unwrap();
            Box::new(Prefix {
                prefix: Some(Cow::Borrowed(&prefix.value)),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::PrefixOptions;
            let prefix = args.list_entry.as_ospfv3_link_lsa_prefix().unwrap();
            let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixOptions {
                prefix_options: Some(Box::new(iter) as _),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let mut informational_capabilities = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let iter = info_caps.get().to_yang_bits().into_iter().map(Cow::Borrowed);
                informational_capabilities = Some(Box::new(iter) as _);
            }
            Box::new(RouterInformationalCapabilities {
                informational_capabilities,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps
            {
                let info_caps = info_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(InformationalCapabilitiesFlags {
                informational_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps
            {
                let func_caps = func_caps.get().bits();
                let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0).map(ListEntry::FlagU32);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities;
            let flag = args.list_entry.as_flag_u32().unwrap();
            Box::new(FunctionalCapabilities {
                functional_flag: Some(*flag),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::Grace;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let mut grace_period = None;
            let mut graceful_restart_reason = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_grace() {
                if let Some(grace_period_tlv) = &lsa_body.grace_period {
                    grace_period = Some(grace_period_tlv.get());
                }
                if let Some(gr_reason) = &lsa_body.gr_reason
                    && let Some(gr_reason) = GrReason::from_u8(gr_reason.get())
                {
                    graceful_restart_reason = Some(gr_reason.to_yang());
                }
            }
            Box::new(Grace {
                grace_period,
                graceful_restart_reason,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::ELink;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Box::new(ELink {
                rtr_priority: lsa.body.as_ext_link().map(|lsa_body| lsa_body.priority),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::lsa_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::lsa_options::LsaOptions;
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_interface_lsa().unwrap();
            let mut lsa_options = None;
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_link() {
                let iter = lsa_body.options.to_yang_bits().into_iter().map(Cow::Borrowed);
                lsa_options = Some(Box::new(iter) as _);
            }
            Box::new(LsaOptions {
                lsa_options,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_link() {
                let iter_prefixes = lsa_body.prefixes.iter().map(ListEntry::Ospfv3LinkLsaPrefix);
                let iter_linklocal = std::iter::once(lsa_body.linklocal).map(ListEntry::Ospfv3LinkLocalAddr);
                Some(Box::new(iter_prefixes.chain(iter_linklocal)))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::UnknownTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownTlv::default()) };
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::IntraPrefixTlv;
            let mut prefix = None;
            if let Some(lsa_prefix) = args.list_entry.as_ospfv3_link_lsa_prefix() {
                prefix = Some(Cow::Borrowed(&lsa_prefix.value));
            }
            Box::new(IntraPrefixTlv {
                // TODO
                metric: None,
                prefix,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_options::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions;
            let Some(prefix) = args.list_entry.as_ospfv3_link_lsa_prefix() else { return Box::new(PrefixOptions::default()) };
            let iter = prefix.options.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixOptions {
                prefix_options: Some(Box::new(iter) as _),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            if let Some(prefix) = args.parent_list_entry.as_ospfv3_link_lsa_prefix() {
                let iter = prefix.unknown_stlvs.iter().map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, _args| None)
        .get_object(|_instance, _args| unreachable!())
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::PATH)
        .get_object(|_instance, _args| unreachable!())
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::Ipv6LinkLocalAddrTlv;
            Box::new(Ipv6LinkLocalAddrTlv {
                link_local_address: args.list_entry.as_ospfv3_link_local_addr().copied().and_then(Ipv6Addr::get).map(Cow::Owned),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::Ipv4LinkLocalAddrTlv;
            Box::new(Ipv4LinkLocalAddrTlv {
                link_local_address: args.list_entry.as_ospfv3_link_local_addr().copied().and_then(Ipv4Addr::get).map(Cow::Owned),
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::PATH)
        .get_object(|_instance, args| {
            use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv;
            let Some(tlv) = args.list_entry.as_unknown_tlv() else { return Box::new(UnknownSubTlv::default()) };
            Box::new(UnknownSubTlv {
                r#type: Some(tlv.tlv_type),
                length: Some(tlv.length),
                value: Some(tlv.value.as_ref()),
            })
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = ListEntry<'a, V>;

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::state_callbacks()
    }
}

// ===== impl ListEntry =====

impl<V> ListEntryKind for ListEntry<'_, V> where V: Version {}

#[allow(clippy::derivable_impls)]
impl<'a, V> Default for ListEntry<'a, V>
where
    V: Version,
{
    fn default() -> ListEntry<'a, V> {
        ListEntry::None
    }
}

// ===== helper functions =====

fn lsa_hdr_opaque_data(
    lsa_hdr: &ospfv2::packet::lsa::LsaHdr,
) -> (Option<u8>, Option<u32>) {
    let mut opaque_type = None;
    let mut opaque_id = None;
    if lsa_hdr.lsa_type.is_opaque() {
        let mut lsa_id = lsa_hdr.lsa_id.octets();
        lsa_id[0] = 0;
        opaque_type = Some(lsa_hdr.lsa_id.octets()[0]);
        opaque_id = Some(u32::from_be_bytes(lsa_id));
    }
    (opaque_type, opaque_id)
}
