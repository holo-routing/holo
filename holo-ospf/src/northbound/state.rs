//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock as Lazy;
use std::time::Instant;

use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::ospf;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, NodeAttributes, Provider,
};
use holo_utils::sr::IgpAlgoType;
use holo_yang::{ToYang, ToYangBits};
use itertools::Itertools;
use num_traits::{FromPrimitive, ToPrimitive};

use crate::area::Area;
use crate::collections::LsdbSingleType;
use crate::instance::Instance;
use crate::interface::{ism, Interface};
use crate::lsdb::{LsaEntry, LsaLogEntry, LsaLogId};
use crate::neighbor::Neighbor;
use crate::packet::lsa::{LsaBodyVersion, LsaHdrVersion};
use crate::packet::tlv::{
    GrReason, SidLabelRangeTlv, SrLocalBlockTlv, UnknownTlv,
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
    StatsAsLsaType(&'a LsdbSingleType<V>),
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
    NetworkLsaAttachedRtr(Ipv4Addr),
    Msd(u8, u8),
    SrAlgo(&'a IgpAlgoType),
    Srgb(&'a SidLabelRangeTlv),
    Srlb(&'a SrLocalBlockTlv),
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
    Ospfv3AdjSid(&'a ospfv3::packet::lsa::AdjSid),
    Ospfv3IntraAreaLsaPrefix(&'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry),
    Ospfv3PrefixSid(&'a ospfv3::packet::lsa::PrefixSid),
    Ospfv3LinkLocalAddr(&'a IpAddr),
}

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(ospf::spf_control::ietf_spf_delay::current_state::PATH)
        .get_element_string(|instance, _args| {
            instance
                .state
                .as_ref()
                .map(|state| state.spf_delay_state.to_yang())
        })
        .path(ospf::spf_control::ietf_spf_delay::remaining_time_to_learn::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timervalue_secs16(|instance, _args| {
            instance
                .state
                .as_ref()
                .and_then(|state| {
                    state.spf_learn_timer.as_ref().map(|task| task.remaining())
                })
        })
        .path(ospf::spf_control::ietf_spf_delay::remaining_hold_down::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timervalue_secs16(|instance, _args| {
            instance
                .state
                .as_ref()
                .and_then(|state| {
                    state
                        .spf_hold_down_timer
                        .as_ref()
                        .map(|task| task.remaining())
                })
        })
        .path(ospf::spf_control::ietf_spf_delay::last_event_received::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|instance, _args| {
            instance
                .state
                .as_ref()
                .and_then(|state| state.spf_last_event_rcvd)
        })
        .path(ospf::spf_control::ietf_spf_delay::next_spf_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|instance, _args| {
            instance.state.as_ref().and_then(|state| {
                if let Some(spf_delay_timer) = &state.spf_delay_timer {
                    let next_spf_time =
                        Instant::now() + spf_delay_timer.remaining();
                    Some(next_spf_time)
                } else {
                    None
                }
            })
        })
        .path(ospf::spf_control::ietf_spf_delay::last_spf_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|instance, _args| {
            instance
                .state
                .as_ref()
                .and_then(|state| state.spf_last_time)
        })
        .path(ospf::router_id::PATH)
        .get_element_ipv4(|instance, _args| {
            instance.state.as_ref().map(|state| state.router_id)
        })
        .path(ospf::local_rib::route::PATH)
        .get_iterate(|instance, _args| {
            if let Some(instance_state) = &instance.state {
                let iter =
                    instance_state.rib.iter().map(|(destination, route)| {
                        ListEntry::Route(destination, route)
                    });
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::local_rib::route::next_hops::next_hop::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();
            let iter = route.nexthops.values().map(ListEntry::Nexthop);
            Some(Box::new(iter))
        })
        .path(ospf::local_rib::route::next_hops::next_hop::outgoing_interface::PATH)
        .get_element_string(|instance, args| {
            let nexthop = args.list_entry.as_nexthop().unwrap();
            let iface = &instance.arenas.interfaces[nexthop.iface_idx];
            Some(iface.name.clone())
        })
        .path(ospf::local_rib::route::next_hops::next_hop::next_hop::PATH)
        .get_element_ip(|_instance, args| {
            let nexthop = args.list_entry.as_nexthop().unwrap();
            nexthop.addr.map(std::convert::Into::into)
        })
        .path(ospf::local_rib::route::metric::PATH)
        .get_element_u32(|_instance, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            Some(route.metric)
        })
        .path(ospf::local_rib::route::route_type::PATH)
        .get_element_string(|_instance, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            Some(route.path_type.to_yang())
        })
        .path(ospf::local_rib::route::route_tag::PATH)
        .get_element_u32(|_instance, args| {
            let (_, route) = args.list_entry.as_route().unwrap();
            route.tag
        })
        .path(ospf::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|instance, _args| {
            instance
                .state
                .as_ref()
                .map(|state| state.discontinuity_time)
        })
        .path(ospf::statistics::originate_new_lsa_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance.state.as_ref().map(|state| state.orig_lsa_count)
        })
        .path(ospf::statistics::rx_new_lsas_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|instance, _args| {
            instance.state.as_ref().map(|state| state.rx_lsa_count)
        })
        .path(ospf::statistics::as_scope_lsa_count::PATH)
        .get_element_u32(|instance, _args| {
            instance.state.as_ref().map(|state| state.lsdb.lsa_count())
        })
        .path(ospf::statistics::as_scope_lsa_chksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|instance, _args| {
            instance.state.as_ref().map(|state| state.lsdb.cksum_sum())
        })
        .path(ospf::statistics::database::as_scope_lsa_type::PATH)
        .get_iterate(|instance, _args| {
            if let Some(instance_state) = &instance.state {
                let iter = instance_state
                    .lsdb
                    .iter_types()
                    .map(ListEntry::StatsAsLsaType);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::statistics::database::as_scope_lsa_type::lsa_type::PATH)
        .get_element_u16(|_instance, args| {
            let lsdb_type = args.list_entry.as_stats_as_lsa_type().unwrap();
            Some(lsdb_type.lsa_type().into())
        })
        .path(ospf::statistics::database::as_scope_lsa_type::lsa_count::PATH)
        .get_element_u32(|_instance, args| {
            let lsdb_type = args.list_entry.as_stats_as_lsa_type().unwrap();
            Some(lsdb_type.lsa_count())
        })
        .path(ospf::statistics::database::as_scope_lsa_type::lsa_cksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|_instance, args| {
            let lsdb_type = args.list_entry.as_stats_as_lsa_type().unwrap();
            Some(lsdb_type.cksum_sum())
        })
        .path(ospf::database::as_scope_lsa_type::PATH)
        .get_iterate(|instance, _args| {
            if let Some(instance_state) = &instance.state {
                let iter =
                    instance_state.lsdb.iter_types().map(ListEntry::AsLsaType);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            if instance.is_active() {
                let lsdb_type =
                    args.parent_list_entry.as_as_lsa_type().unwrap();
                let iter = lsdb_type
                    .iter(&instance.arenas.lsa_entries)
                    .map(|(_, lse)| ListEntry::AsLsa(lse));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::decode_completed::PATH)
        .get_element_bool(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(!lsa.body.is_unknown())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::raw_data::PATH)
        .attributes(NodeAttributes::LS_RAW)
        .get_element_string(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let bytes =
                lsa.raw.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::spf_log::event::PATH)
        .attributes(NodeAttributes::LOG)
        .get_iterate(|instance, _args| {
            if let Some(instance_state) = &instance.state {
                let iter = instance_state.spf_log.iter().map(ListEntry::SpfLog);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::spf_log::event::spf_type::PATH)
        .get_element_string(|_instance, args| {
            let log = args.list_entry.as_spf_log().unwrap();
            Some(log.spf_type.to_yang())
        })
        .path(ospf::spf_log::event::schedule_timestamp::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let log = args.list_entry.as_spf_log().unwrap();
            Some(log.schedule_time)
        })
        .path(ospf::spf_log::event::start_timestamp::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let log = args.list_entry.as_spf_log().unwrap();
            Some(log.start_time)
        })
        .path(ospf::spf_log::event::end_timestamp::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let log = args.list_entry.as_spf_log().unwrap();
            Some(log.end_time)
        })
        .path(ospf::spf_log::event::trigger_lsa::PATH)
        .get_iterate(|_instance, args| {
            let log = args.parent_list_entry.as_spf_log().unwrap();
            let iter = log.trigger_lsas.iter().map(ListEntry::SpfTriggerLsa);
            Some(Box::new(iter))
        })
        .path(ospf::spf_log::event::trigger_lsa::area_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            lsa_id.area_id
        })
        .path(ospf::spf_log::event::trigger_lsa::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            Some(lsa_id.lsa_type.into())
        })
        .path(ospf::spf_log::event::trigger_lsa::lsa_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            Some(lsa_id.lsa_id)
        })
        .path(ospf::spf_log::event::trigger_lsa::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            Some(lsa_id.adv_rtr)
        })
        .path(ospf::spf_log::event::trigger_lsa::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lsa_id = args.list_entry.as_spf_trigger_lsa().unwrap();
            Some(lsa_id.seq_no)
        })
        .path(ospf::lsa_log::event::PATH)
        .attributes(NodeAttributes::LOG)
        .get_iterate(|instance, _args| {
            if let Some(instance_state) = &instance.state {
                let iter = instance_state.lsa_log.iter().map(ListEntry::LsaLog);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::lsa_log::event::lsa::area_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            log.lsa.area_id
        })
        .path(ospf::lsa_log::event::lsa::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            Some(log.lsa.lsa_type.into())
        })
        .path(ospf::lsa_log::event::lsa::lsa_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            Some(log.lsa.lsa_id)
        })
        .path(ospf::lsa_log::event::lsa::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            Some(log.lsa.adv_rtr)
        })
        .path(ospf::lsa_log::event::lsa::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            Some(log.lsa.seq_no)
        })
        .path(ospf::lsa_log::event::received_timestamp::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            log.rcvd_time
        })
        .path(ospf::lsa_log::event::reason::PATH)
        .get_element_string(|_instance, args| {
            let log = args.list_entry.as_lsa_log().unwrap();
            Some(log.reason.to_yang())
        })
        .path(ospf::areas::area::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.arenas.areas.iter().map(ListEntry::Area);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::ranges::range::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(ospf::areas::area::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.state.discontinuity_time)
        })
        .path(ospf::areas::area::statistics::spf_runs_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.state.spf_run_count)
        })
        .path(ospf::areas::area::statistics::abr_count::PATH)
        .get_element_u32(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.abr_count() as _)
        })
        .path(ospf::areas::area::statistics::asbr_count::PATH)
        .get_element_u32(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.asbr_count() as _)
        })
        .path(ospf::areas::area::statistics::area_scope_lsa_count::PATH)
        .get_element_u32(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.state.lsdb.lsa_count())
        })
        .path(ospf::areas::area::statistics::area_scope_lsa_cksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|_instance, args| {
            let area = args.list_entry.as_area().unwrap();
            Some(area.state.lsdb.cksum_sum())
        })
        .path(ospf::areas::area::statistics::database::area_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area
                .state
                .lsdb
                .iter_types()
                .map(ListEntry::AreaStatsLsaType);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::statistics::database::area_scope_lsa_type::lsa_type::PATH)
        .get_element_u16(|_instance, args| {
            let lsdb_type = args.list_entry.as_area_stats_lsa_type().unwrap();
            Some(lsdb_type.lsa_type().into())
        })
        .path(ospf::areas::area::statistics::database::area_scope_lsa_type::lsa_count::PATH)
        .get_element_u32(|_instance, args| {
            let lsdb_type = args.list_entry.as_area_stats_lsa_type().unwrap();
            Some(lsdb_type.lsa_count())
        })
        .path(ospf::areas::area::statistics::database::area_scope_lsa_type::lsa_cksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|_instance, args| {
            let lsdb_type = args.list_entry.as_area_stats_lsa_type().unwrap();
            Some(lsdb_type.cksum_sum())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area.state.lsdb.iter_types().map(ListEntry::AreaLsaType);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            if instance.is_active() {
                let lsdb_type =
                    args.parent_list_entry.as_area_lsa_type().unwrap();
                let iter = lsdb_type
                    .iter(&instance.arenas.lsa_entries)
                    .map(|(_, lse)| ListEntry::AreaLsa(lse));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::decode_completed::PATH)
        .get_element_bool(|_instance, args| {
            let lse = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(!lsa.body.is_unknown())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::raw_data::PATH)
        .attributes(NodeAttributes::LS_RAW)
        .get_element_string(|_instance, args| {
            let lse = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let bytes =
                lsa.raw.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::PATH)
        .get_iterate(|instance, args| {
            let area = args.parent_list_entry.as_area().unwrap();
            let iter = area
                .interfaces
                .iter(&instance.arenas.interfaces)
                .map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::interfaces::interface::state::PATH)
        .get_element_string(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(iface.state.ism_state.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::hello_timer::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timervalue_secs16(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            iface
                .state
                .tasks
                .hello_interval
                .as_ref()
                .map(|task| task.remaining())
        })
        .path(ospf::areas::area::interfaces::interface::wait_timer::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timervalue_secs16(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            iface
                .state
                .tasks
                .wait_timer
                .as_ref()
                .map(|task| task.remaining())
        })
        .path(ospf::areas::area::interfaces::interface::dr_router_id::PATH)
        .get_element_ipv4(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let iface = args.list_entry.as_interface().unwrap();
                if iface.state.ism_state == ism::State::Dr {
                    Some(instance_state.router_id)
                } else {
                    iface.state.dr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.router_id)
                    })
                }
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::dr_ip_addr::PATH)
        .get_element_ip(|instance, args| {
            if instance.is_active() {
                let iface = args.list_entry.as_interface().unwrap();
                if iface.state.ism_state == ism::State::Dr {
                    Some(iface.state.src_addr.unwrap().into())
                } else {
                    iface.state.dr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.src.into())
                    })
                }
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::bdr_router_id::PATH)
        .get_element_ipv4(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let iface = args.list_entry.as_interface().unwrap();
                if iface.state.ism_state == ism::State::Backup {
                    Some(instance_state.router_id)
                } else {
                    iface.state.bdr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.router_id)
                    })
                }
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::bdr_ip_addr::PATH)
        .get_element_ip(|instance, args| {
            if instance.is_active() {
                let iface = args.list_entry.as_interface().unwrap();
                if iface.state.ism_state == ism::State::Backup {
                    Some(iface.state.src_addr.unwrap().into())
                } else {
                    iface.state.bdr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.src.into())
                    })
                }
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(iface.state.discontinuity_time)
        })
        .path(ospf::areas::area::interfaces::interface::statistics::if_event_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(iface.state.event_count)
        })
        .path(ospf::areas::area::interfaces::interface::statistics::link_scope_lsa_count::PATH)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(iface.state.lsdb.lsa_count())
        })
        .path(ospf::areas::area::interfaces::interface::statistics::link_scope_lsa_cksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            Some(iface.state.lsdb.cksum_sum())
        })
        .path(ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface
                .state
                .lsdb
                .iter_types()
                .map(ListEntry::InterfaceStatsLsaType);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::lsa_type::PATH)
        .get_element_u16(|_instance, args| {
            let lsdb_type =
                args.list_entry.as_interface_stats_lsa_type().unwrap();
            Some(lsdb_type.lsa_type().into())
        })
        .path(ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::lsa_count::PATH)
        .get_element_u32(|_instance, args| {
            let lsdb_type =
                args.list_entry.as_interface_stats_lsa_type().unwrap();
            Some(lsdb_type.lsa_count())
        })
        .path(ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::lsa_cksum_sum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_u32(|_instance, args| {
            let lsdb_type =
                args.list_entry.as_interface_stats_lsa_type().unwrap();
            Some(lsdb_type.cksum_sum())
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::PATH)
        .get_iterate(|instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface
                .state
                .neighbors
                .iter(&instance.arenas.neighbors)
                .map(|nbr| ListEntry::Neighbor(iface, nbr));
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::address::PATH)
        .get_element_ip(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Some(nbr.src.into())
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::dr_router_id::PATH)
        .get_element_ipv4(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let (iface, nbr) = args.list_entry.as_neighbor().unwrap();
                nbr.dr
                    .and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.router_id)
                    })
                    .or_else(|| {
                        let iface_net_id = V::network_id(
                            &iface.state.src_addr.unwrap(),
                            instance_state.router_id,
                        );
                        (nbr.dr == Some(iface_net_id))
                            .then_some(instance_state.router_id)
                    })
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::dr_ip_addr::PATH)
        .get_element_ip(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let (iface, nbr) = args.list_entry.as_neighbor().unwrap();
                nbr.dr
                    .and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.src.into())
                    })
                    .or_else(|| {
                        let iface_src_addr = iface.state.src_addr.unwrap();
                        let iface_net_id = V::network_id(
                            &iface_src_addr,
                            instance_state.router_id,
                        );
                        (nbr.dr == Some(iface_net_id))
                            .then_some(iface_src_addr.into())
                    })
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::bdr_router_id::PATH)
        .get_element_ipv4(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let (iface, nbr) = args.list_entry.as_neighbor().unwrap();
                nbr.bdr
                    .and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.router_id)
                    })
                    .or_else(|| {
                        let iface_net_id = V::network_id(
                            &iface.state.src_addr.unwrap(),
                            instance_state.router_id,
                        );
                        (nbr.bdr == Some(iface_net_id))
                            .then_some(instance_state.router_id)
                    })
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::bdr_ip_addr::PATH)
        .get_element_ip(|instance, args| {
            if let Some(instance_state) = &instance.state {
                let (iface, nbr) = args.list_entry.as_neighbor().unwrap();
                nbr.bdr
                    .and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&instance.arenas.neighbors, net_id)
                            .map(|(_, nbr)| nbr.src.into())
                    })
                    .or_else(|| {
                        let iface_src_addr = iface.state.src_addr.unwrap();
                        let iface_net_id = V::network_id(
                            &iface_src_addr,
                            instance_state.router_id,
                        );
                        (nbr.bdr == Some(iface_net_id))
                            .then_some(iface_src_addr.into())
                    })
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::state::PATH)
        .get_element_string(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Some(nbr.state.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::dead_timer::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timervalue_secs16(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            nbr.tasks
                .inactivity_timer
                .as_ref()
                .map(|task| task.remaining())
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Some(nbr.discontinuity_time)
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::nbr_event_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Some(nbr.event_count)
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::nbr_retrans_qlen::PATH)
        .get_element_u32(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            Some(nbr.lists.ls_rxmt.len() as u32)
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::restart_reason::PATH)
        .get_element_string(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            nbr.gr.as_ref().map(|gr| gr.restart_reason.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::grace_timer::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let (_, nbr) = args.list_entry.as_neighbor().unwrap();
            nbr.gr.as_ref().map(|gr| {
                u16::try_from(gr.grace_period.remaining().as_secs())
                    .unwrap_or(u16::MAX)
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface
                .state
                .lsdb
                .iter_types()
                .map(ListEntry::InterfaceLsaType);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::PATH)
        .get_iterate(|instance, args| {
            if instance.is_active() {
                let lsdb_type =
                    args.parent_list_entry.as_interface_lsa_type().unwrap();
                let iter = lsdb_type
                    .iter(&instance.arenas.lsa_entries)
                    .map(|(_, lse)| ListEntry::InterfaceLsa(lse));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::decode_completed::PATH)
        .get_element_bool(|_instance, args| {
            let lse = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(!lsa.body.is_unknown())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::raw_data::PATH)
        .attributes(NodeAttributes::LS_RAW)
        .get_element_string(|_instance, args| {
            let lse = args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            let bytes =
                lsa.raw.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::PATH)
        .get_iterate(|_instance, _args| None)
        .build()
}

fn load_callbacks_ospfv2() -> Callbacks<Instance<Ospfv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let options = lsa.hdr.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::opaque_type::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr
                .lsa_type
                .is_opaque()
                .then(|| lsa.hdr.lsa_id.octets()[0])
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::opaque_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.lsa_type.is_opaque().then(|| {
                let mut lsa_id = lsa.hdr.lsa_id.octets();
                lsa_id[0] = 0;
                u32::from_be_bytes(lsa_id)
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::num_of_links::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::link_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::link_data::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::router::links::link::topologies::topology::metric::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::network::network_mask::PATH)
        .get_element_ipv4(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::summary::network_mask::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::summary::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::summary::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::summary::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::network_mask::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_as_external().map(|lsa_body| lsa_body.mask)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(_lsa_body) = lsa.body.as_as_external() {
                let iter = std::iter::once(lse).map(ListEntry::AsLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            // TOS-based routing is deprecated.
            Some(0)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::flags::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_as_external().unwrap();
            Some(lsa_body.flags.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_as_external().unwrap();
            Some(lsa_body.metric)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::forwarding_address::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_as_external().unwrap();
            lsa_body.fwd_addr
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::external_route_tag::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_as_external().unwrap();
            Some(lsa_body.tag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds {
                    let iter = msds
                        .get()
                        .iter()
                        .map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, args| {
            let (msd_type, _) = args.list_entry.as_msd().unwrap();
            Some(*msd_type)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, args| {
            let (_, msd_value) = args.list_entry.as_msd().unwrap();
            Some(*msd_value)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.unknown_tlvs
                        .iter()
                        .map(ListEntry::UnknownTlv);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.sr_algo
                        .iter()
                        .flat_map(|tlv| tlv.get().iter())
                        .map(ListEntry::SrAlgo);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srgb
                        .iter()
                        .map(ListEntry::Srgb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srlb
                        .iter()
                        .map(ListEntry::Srlb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_as()
                && let Some(lsa_body) = lsa_body.as_ext_prefix() {
                    let iter = lsa_body
                        .prefixes
                        .values()
                        .map(ListEntry::Ospfv2ExtPrefixTlv);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::route_type::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Some(tlv.route_type.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::extended_prefix_flags::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let flags = tlv.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Some(tlv.prefix.into())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv
                .unknown_tlvs
                .iter()
                .map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_id::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_data::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::r#type::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let options = lsa.hdr.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::opaque_type::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr
                .lsa_type
                .is_opaque()
                .then(|| lsa.hdr.lsa_id.octets()[0])
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::opaque_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.lsa_type.is_opaque().then(|| {
                let mut lsa_id = lsa.hdr.lsa_id.octets();
                lsa_id[0] = 0;
                u32::from_be_bytes(lsa_id)
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router() {
                let flags = lsa_body.flags.to_yang_bits();
                let iter = flags.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::num_of_links::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_router()
                .map(|lsa_body| lsa_body.links.len() as u16)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router() {
                let iter =
                    lsa_body.links.iter().map(ListEntry::Ospfv2RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::link_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Some(rtr_link.link_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::link_data::PATH)
        .get_element_ipv4(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Some(rtr_link.link_data)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Some(rtr_link.link_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let rtr_link =
                args.parent_list_entry.as_ospfv2_router_lsa_link().unwrap();
            let iter =
                std::iter::once(*rtr_link).map(ListEntry::Ospfv2RouterLsaLink);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            // TOS-based routing is deprecated.
            Some(0)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::metric::PATH)
        .get_element_u16(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv2_router_lsa_link().unwrap();
            Some(rtr_link.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::network_mask::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_network().map(|lsa_body| lsa_body.mask)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_network() {
                let iter = lsa_body
                    .attached_rtrs
                    .iter()
                    .copied()
                    .map(ListEntry::NetworkLsaAttachedRtr);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_ipv4(|_instance, args| {
            let attached_rtr =
                args.list_entry.as_network_lsa_attached_rtr().unwrap();
            Some(*attached_rtr)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::network_mask::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_summary().map(|lsa_body| lsa_body.mask)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(_lsa_body) = lsa.body.as_summary() {
                let iter = std::iter::once(lse).map(ListEntry::AreaLsa);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            // TOS-based routing is deprecated.
            Some(0)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            let lsa_body = lsa.body.as_summary().unwrap();
            Some(lsa_body.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::network_mask::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::flags::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::forwarding_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::external::topologies::topology::external_route_tag::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds {
                    let iter = msds
                        .get()
                        .iter()
                        .map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, args| {
            let (msd_type, _) = args.list_entry.as_msd().unwrap();
            Some(*msd_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, args| {
            let (_, msd_value) = args.list_entry.as_msd().unwrap();
            Some(*msd_value)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.unknown_tlvs
                        .iter()
                        .map(ListEntry::UnknownTlv);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.sr_algo
                        .iter()
                        .flat_map(|tlv| tlv.get().iter())
                        .map(ListEntry::SrAlgo);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srgb
                        .iter()
                        .map(ListEntry::Srgb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srlb
                        .iter()
                        .map(ListEntry::Srlb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_prefix() {
                    let iter = lsa_body
                        .prefixes
                        .values()
                        .map(ListEntry::Ospfv2ExtPrefixTlv);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::route_type::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Some(tlv.route_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::extended_prefix_flags::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let flags = tlv.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let tlv = args.list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            Some(tlv.prefix.into())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv
                .unknown_tlvs
                .iter()
                .map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv2_ext_prefix_tlv().unwrap();
            let iter = tlv
                .prefix_sids
                .values()
                .map(ListEntry::Ospfv2PrefixSid);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sid = args.parent_list_entry.as_ospfv2_prefix_sid().unwrap();
            let flags = prefix_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            Some(0)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_string(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            Some(prefix_sid.algo.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv2_prefix_sid().unwrap();
            Some(prefix_sid.sid.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                    Some(tlv.link_id)
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_data::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                    Some(tlv.link_data)
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                    Some(tlv.link_type.to_yang())
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link
                && let Some(msds) = &tlv.msds {
                    let iter = msds
                        .get()
                        .iter()
                        .map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, args| {
            let (msd_type, _) = args.list_entry.as_msd().unwrap();
            Some(*msd_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, args| {
            let (_, msd_value) = args.list_entry.as_msd().unwrap();
            Some(*msd_value)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                let iter = tlv
                    .unknown_tlvs
                    .iter()
                    .map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                let iter = tlv
                    .adj_sids
                    .iter()
                    .filter(|adj_sid| adj_sid.nbr_router_id.is_none())
                    .map(ListEntry::Ospfv2AdjSid);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let adj_sid = args.parent_list_entry.as_ospfv2_adj_sid().unwrap();
            let flags = adj_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            Some(0)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::weight::PATH)
        .get_element_u8(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            Some(adj_sid.weight)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            Some(adj_sid.sid.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_ext_link()
                && let Some(tlv) = &lsa_body.link {
                let iter = tlv
                    .adj_sids
                    .iter()
                    .filter(|adj_sid| adj_sid.nbr_router_id.is_some())
                    .map(ListEntry::Ospfv2AdjSid);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let adj_sid = args.parent_list_entry.as_ospfv2_adj_sid().unwrap();
            let flags = adj_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            Some(0)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::weight::PATH)
        .get_element_u8(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            Some(adj_sid.weight)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::neighbor_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            adj_sid.nbr_router_id
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv2_adj_sid().unwrap();
            Some(adj_sid.sid.value())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            let options = lsa.hdr.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::opaque_type::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr
                .lsa_type
                .is_opaque()
                .then(|| lsa.hdr.lsa_id.octets()[0])
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::opaque_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.lsa_type.is_opaque().then(|| {
                let mut lsa_id = lsa.hdr.lsa_id.octets();
                lsa_id[0] = 0;
                u32::from_be_bytes(lsa_id)
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::num_of_links::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::link_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::link_data::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::router::links::link::topologies::topology::metric::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::network::network_mask::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::summary::network_mask::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::summary::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::summary::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::summary::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::network_mask::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::mt_id::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::flags::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::forwarding_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::external::topologies::topology::external_route_tag::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info()
                && let Some(msds) = &lsa_body.msds {
                    let iter = msds
                        .get()
                        .iter()
                        .map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, args| {
            let (msd_type, _) = args.list_entry.as_msd().unwrap();
            Some(*msd_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, args| {
            let (_, msd_value) = args.list_entry.as_msd().unwrap();
            Some(*msd_value)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_area()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.unknown_tlvs
                        .iter()
                        .map(ListEntry::UnknownTlv);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.sr_algo
                        .iter()
                        .flat_map(|tlv| tlv.get().iter())
                        .map(ListEntry::SrAlgo);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srgb
                        .iter()
                        .map(ListEntry::Srgb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    let iter = lsa_body.srlb
                        .iter()
                        .map(ListEntry::Srlb);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_router_info() {
                    lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::route_type::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::extended_prefix_flags::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::mt_id::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_id::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::link_data::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::r#type::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_type::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::msd_value::PATH)
        .get_element_u8(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, _args| {
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::grace_period::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_grace()
                && let Some(grace_period) = &lsa_body.grace_period {
                    Some(grace_period.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::graceful_restart_reason::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_grace()
                && let Some(gr_reason) = &lsa_body.gr_reason
                && let Some(gr_reason) = GrReason::from_u8(gr_reason.get()) {
                    Some(gr_reason.to_yang())
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::ip_interface_address::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv2> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_opaque_link()
                && let Some(lsa_body) = lsa_body.as_grace()
                && let Some(addr) = &lsa_body.addr {
                    Some(addr.get())
            } else {
                None
            }
        })
        .build()
}

fn load_callbacks_ospfv3() -> Callbacks<Instance<Ospfv3>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::new(core_cbs)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::lsa_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id.into())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::interface_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::neighbor_interface_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::neighbor_router_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router::links::link::metric::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::network::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_prefix::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_router::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::inter_area_router::destination_router_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::flags::PATH)
        .get_element_string(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_as_external()
                .map(|lsa_body| lsa_body.flags.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::referenced_ls_type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().and_then(|lsa_body| {
                lsa_body.ref_lsa_type.map(|lsa_type| lsa_type.to_yang())
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().and_then(|lsa_body| {
                lsa_body.ref_lsa_type.and_then(|ref_lsa_type| {
                    if ref_lsa_type.function_code().is_none() {
                        Some(ref_lsa_type.0)
                    } else {
                        None
                    }
                })
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().map(|lsa_body| lsa_body.prefix)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_as_external() {
                let options = lsa_body.prefix_options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::forwarding_address::PATH)
        .get_element_ipv6(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().and_then(|lsa_body| {
                lsa_body.fwd_addr.map(|addr| match addr {
                    IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                    IpAddr::V6(addr) => addr,
                })
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::external_route_tag::PATH)
        .get_element_u32(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().and_then(|lsa_body| lsa_body.tag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_as_external().and_then(|lsa_body| {
                lsa_body.ref_lsa_id.map(|lsa_id| lsa_id.into())
            })
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::rtr_priority::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::link_local_interface_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::num_of_prefixes::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::prefixes::prefix::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::referenced_ls_type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::referenced_adv_router::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::num_of_prefixes::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body
                    .sr_algo
                    .iter()
                    .flat_map(|tlv| tlv.get().iter())
                    .map(ListEntry::SrAlgo);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_yang())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
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
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::flags::ospfv3_e_external_prefix_bits::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_ext_as_external().map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let lse = args.list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_ext_as_external().map(|lsa_body| lsa_body.prefix)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_as_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_as_external() {
                let options = lsa_body.prefix_options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv6_fwd_addr_sub_tlv::forwarding_address::PATH)
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv4_fwd_addr_sub_tlv::forwarding_address::PATH)
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::route_tag_sub_tlv::route_tag::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::lsa_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id.into())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let flags = lsa_body.flags.to_yang_bits();
                let iter = flags.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_router() {
                let iter =
                    lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::interface_id::PATH)
        .get_element_u32(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.iface_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::neighbor_interface_id::PATH)
        .get_element_u32(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.nbr_iface_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::neighbor_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.nbr_router_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.link_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::metric::PATH)
        .get_element_u16(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_network() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_network() {
                let iter = lsa_body
                    .attached_rtrs
                    .iter()
                    .copied()
                    .map(ListEntry::NetworkLsaAttachedRtr);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_ipv4(|_instance, args| {
            let attached_rtr =
                args.list_entry.as_network_lsa_attached_rtr().unwrap();
            Some(*attached_rtr)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_inter_area_prefix()
                .map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_inter_area_prefix()
                .map(|lsa_body| lsa_body.prefix)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_prefix() {
                let options = lsa_body.prefix_options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_inter_area_router() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_inter_area_router()
                .map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::destination_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_inter_area_router()
                .map(|lsa_body| lsa_body.router_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::flags::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::referenced_ls_type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::forwarding_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::external_route_tag::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::as_external::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::rtr_priority::PATH)
        .get_element_u8(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::link_local_interface_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::num_of_prefixes::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::prefixes::prefix::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::referenced_ls_type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_lsa_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_intra_area_prefix().and_then(|lsa_body| {
                if lsa_body.ref_lsa_type.function_code().is_none() {
                    Some(lsa_body.ref_lsa_type.0)
                } else {
                    None
                }
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_lsa_id.into())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::referenced_adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_adv_rtr)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::num_of_prefixes::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_intra_area_prefix()
                .map(|lsa_body| lsa_body.prefixes.len() as _)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_intra_area_prefix() {
                let iter = lsa_body
                    .prefixes
                    .iter()
                    .map(ListEntry::Ospfv3IntraAreaLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let prefix =
                args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Some(prefix.value)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let prefix = args
                .parent_list_entry
                .as_ospfv3_intra_area_lsa_prefix()
                .unwrap();
            let options = prefix.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::metric::PATH)
        .get_element_u16(|_instance, args| {
            let prefix =
                args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Some(prefix.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body
                    .sr_algo
                    .iter()
                    .flat_map(|tlv| tlv.get().iter())
                    .map(ListEntry::SrAlgo);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let flags = lsa_body.flags.to_yang_bits();
                let iter = flags.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_router() {
                let iter =
                    lsa_body.links.iter().map(ListEntry::Ospfv3RouterLsaLink);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| {
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":")
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::interface_id::PATH)
        .get_element_u32(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.iface_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::neighbor_interface_id::PATH)
        .get_element_u32(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.nbr_iface_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::neighbor_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.nbr_router_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::r#type::PATH)
        .get_element_string(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.link_type.to_yang())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::metric::PATH)
        .get_element_u16(|_instance, args| {
            let rtr_link = args.list_entry.as_ospfv3_router_lsa_link().unwrap();
            Some(rtr_link.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let tlv = args.parent_list_entry.as_ospfv3_router_lsa_link().unwrap();
            let iter = tlv
                .unknown_stlvs
                .iter()
                .map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let rtr_link = args.parent_list_entry.as_ospfv3_router_lsa_link().unwrap();
            let iter = rtr_link
                .adj_sids
                .iter()
                .filter(|adj_sid| adj_sid.nbr_router_id.is_none())
                .map(ListEntry::Ospfv3AdjSid);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let adj_sid = args.parent_list_entry.as_ospfv3_adj_sid().unwrap();
            let flags = adj_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::weight::PATH)
        .get_element_u8(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            Some(adj_sid.weight)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            Some(adj_sid.sid.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let rtr_link = args.parent_list_entry.as_ospfv3_router_lsa_link().unwrap();
            let iter = rtr_link
                .adj_sids
                .iter()
                .filter(|adj_sid| adj_sid.nbr_router_id.is_some())
                .map(ListEntry::Ospfv3AdjSid);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let adj_sid = args.parent_list_entry.as_ospfv3_adj_sid().unwrap();
            let flags = adj_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::weight::PATH)
        .get_element_u8(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            Some(adj_sid.weight)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::neighbor_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            Some(adj_sid.nbr_router_id.unwrap())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let adj_sid = args.list_entry.as_ospfv3_adj_sid().unwrap();
            Some(adj_sid.sid.value())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_network() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // Nothing to do.
            None
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::attached_router_tlv::adjacent_neighbor_router_id::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_network() {
                let iter = lsa_body
                    .attached_rtrs
                    .iter()
                    .copied()
                    .map(ListEntry::NetworkLsaAttachedRtr);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_ipv4(|_instance, args| {
            let attached_rtr =
                args.list_entry.as_network_lsa_attached_rtr().unwrap();
            Some(*attached_rtr)
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
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| {
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":")
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_inter_area_prefix()
                .map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_inter_area_prefix()
                .map(|lsa_body| lsa_body.prefix)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_prefix() {
                let options = lsa_body.prefix_options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                let iter = lsa_body
                    .unknown_stlvs
                    .iter()
                    .map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_prefix() {
                let iter = lsa_body
                    .prefix_sids
                    .values()
                    .map(ListEntry::Ospfv3PrefixSid);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sid = args.parent_list_entry.as_ospfv3_prefix_sid().unwrap();
            let flags = prefix_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            Some(prefix_sid.algo as u8)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            Some(prefix_sid.sid.value())
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
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| {
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":")
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::metric::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_inter_area_router()
                .map(|lsa_body| lsa_body.metric)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::destination_router_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_inter_area_router()
                .map(|lsa_body| lsa_body.router_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_inter_area_router() {
                let iter = lsa_body
                    .unknown_stlvs
                    .iter()
                    .map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::referenced_ls_type::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_lsa_type.into())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_lsa_id.into())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::referenced_adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> = args.list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_ext_intra_area_prefix()
                .map(|lsa_body| lsa_body.ref_lsa_id)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_area_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_intra_area_prefix() {
                let iter = lsa_body
                    .prefixes
                    .iter()
                    .map(ListEntry::Ospfv3IntraAreaLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| {
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":")
            })
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::metric::PATH)
        .get_element_u32(|_instance, args| {
            let prefix =
                args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Some(prefix.metric as u32)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let prefix =
                args.list_entry.as_ospfv3_intra_area_lsa_prefix().unwrap();
            Some(prefix.value)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let prefix = args
                .parent_list_entry
                .as_ospfv3_intra_area_lsa_prefix()
                .unwrap();
            let options = prefix.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let prefix = args
                .parent_list_entry
                .as_ospfv3_intra_area_lsa_prefix()
                .unwrap();
            let iter = prefix
                .unknown_stlvs
                .iter()
                .map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let prefix = args
                .parent_list_entry
                .as_ospfv3_intra_area_lsa_prefix()
                .unwrap();
            let iter = prefix
                .prefix_sids
                .values()
                .map(ListEntry::Ospfv3PrefixSid);
            Some(Box::new(iter))
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, args| {
            let prefix_sid = args.parent_list_entry.as_ospfv3_prefix_sid().unwrap();
            let flags = prefix_sid.flags.to_yang_bits();
            let iter = flags.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            Some(prefix_sid.algo as u8)
        })
        .path(ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let prefix_sid = args.list_entry.as_ospfv3_prefix_sid().unwrap();
            Some(prefix_sid.sid.value())
        })
        .path(ospf::areas::area::interfaces::interface::interface_id::PATH)
        .get_element_u16(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            // NOTE: YANG module needs fixing (s/u16/u32).
            iface.system.ifindex.map(|ifindex| ifindex as _)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::lsa_id::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_id.into())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::age::PATH)
        .attributes(NodeAttributes::LS_AGE)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.age())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::maxage::PATH)
        .attributes(NodeAttributes::DEV)
        .get_element_empty(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.hdr.is_maxage().then_some(())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::r#type::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.lsa_type.to_yang())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::adv_router::PATH)
        .get_element_ipv4(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.adv_rtr)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::seq_num::PATH)
        .attributes(NodeAttributes::LS_SEQNO)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.seq_no)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::checksum::PATH)
        .attributes(NodeAttributes::LS_CKSUM)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(format!("{:#06x}", lsa.hdr.cksum))
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::length::PATH)
        .get_element_u16(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            Some(lsa.hdr.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::router_bits::rtr_lsa_bits::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::interface_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::neighbor_interface_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::neighbor_router_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::r#type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router::links::link::metric::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::network::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::network::attached_routers::attached_router::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_prefix::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_router::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_router::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::inter_area_router::destination_router_id::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::flags::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::referenced_ls_type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::forwarding_address::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::external_route_tag::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::as_external::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::rtr_priority::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_link().map(|lsa_body| lsa_body.priority)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_link() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::link_local_interface_address::PATH)
        .get_element_ipv6(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_std_link().map(|lsa_body| match lsa_body.linklocal {
                IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                IpAddr::V6(addr) => addr,
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::num_of_prefixes::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body
                .as_std_link()
                .map(|lsa_body| lsa_body.prefixes.len() as _)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_std_link() {
                let iter = lsa_body
                    .prefixes
                    .iter()
                    .map(ListEntry::Ospfv3LinkLsaPrefix);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            let prefix = args.list_entry.as_ospfv3_link_lsa_prefix().unwrap();
            Some(prefix.value)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            let prefix =
                args.parent_list_entry.as_ospfv3_link_lsa_prefix().unwrap();
            let options = prefix.options.to_yang_bits();
            let iter = options.into_iter().map(ListEntry::Flag);
            Some(Box::new(iter))
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::referenced_ls_type::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::unknown_referenced_ls_type::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::referenced_link_state_id::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::referenced_adv_router::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::num_of_prefixes::PATH)
        .get_element_u16(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::PATH)
        .get_iterate(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix::PATH)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, _args| None)
        .get_element_string(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::metric::PATH)
        .get_element_u32(|_instance, _args| None)
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::informational_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let iter = info_caps
                        .get()
                        .to_yang_bits()
                        .into_iter()
                        .map(ListEntry::Flag);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(info_caps) = &lsa_body.info_caps {
                    let info_caps = info_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| info_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::informational_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info()
                && let Some(func_caps) = &lsa_body.func_caps {
                    let func_caps = func_caps.get().bits();
                    let iter = (0..31)
                        .map(|flag| 1 << flag)
                        .filter(move |flag| func_caps & flag != 0)
                        .map(ListEntry::FlagU32);
                    Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::functional_flag::PATH)
        .get_element_u32(|_instance, args| {
            let flag = args.list_entry.as_flag_u32().unwrap();
            Some(*flag)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::sr_algorithm::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body
                    .sr_algo
                    .iter()
                    .flat_map(|tlv| tlv.get().iter())
                    .map(ListEntry::SrAlgo);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_u8(|_instance, args| {
            let algo = args.list_entry.as_sr_algo().unwrap();
            Some(algo.to_u8().unwrap())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srgb.iter().map(ListEntry::Srgb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.range)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srgb = args.list_entry.as_srgb().unwrap();
            Some(srgb.first.value())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                let iter = lsa_body.srlb.iter().map(ListEntry::Srlb);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::range_size::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.range)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, args| {
            let srlb = args.list_entry.as_srlb().unwrap();
            Some(srlb.first.value())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::preference::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_router_info() {
                lsa_body.srms_pref.as_ref().map(|tlv| tlv.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::rtr_priority::PATH)
        .get_element_u8(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            lsa.body.as_ext_link().map(|lsa_body| lsa_body.priority)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::lsa_options::lsa_options::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_link() {
                let options = lsa_body.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::PATH)
        .get_iterate(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.parent_list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_ext_link() {
                let iter_prefixes = lsa_body
                    .prefixes
                    .iter()
                    .map(ListEntry::Ospfv3LinkLsaPrefix);
                let iter_linklocal = std::iter::once(&lsa_body.linklocal)
                    .map(ListEntry::Ospfv3LinkLocalAddr);
                Some(Box::new(iter_prefixes.chain(iter_linklocal)))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.tlv_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| tlv.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            args.list_entry.as_unknown_tlv().map(|tlv| {
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":")
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::metric::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix::PATH)
        .get_element_prefix(|_instance, args| {
            args.list_entry.as_ospfv3_link_lsa_prefix()
                .map(|prefix| prefix.value)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_options::prefix_options::PATH)
        .get_iterate(|_instance, args| {
            if let Some(prefix) = args
                .parent_list_entry
                .as_ospfv3_link_lsa_prefix()
            {
                let options = prefix.options.to_yang_bits();
                let iter = options.into_iter().map(ListEntry::Flag);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_element_string(|_instance, args| {
            let flag = args.list_entry.as_flag().unwrap();
            Some(flag.to_string())
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, args| {
            if let Some(prefix) = args
                .parent_list_entry
                .as_ospfv3_link_lsa_prefix()
            {
                let iter = prefix
                    .unknown_stlvs
                    .iter()
                    .map(ListEntry::UnknownTlv);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::bits::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .get_element_string(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::algorithm::PATH)
        .get_element_u8(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::sid::PATH)
        .get_element_u32(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_tlv::link_local_address::PATH)
        .get_element_ipv6(|_instance, args| {
            args.list_entry.as_ospfv3_link_local_addr().and_then(|addr| {
                if let IpAddr::V6(addr) = addr {
                    Some(*addr)
                } else {
                    None
                }
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_tlv::link_local_address::PATH)
        .get_element_ipv4(|_instance, args| {
            args.list_entry.as_ospfv3_link_local_addr().and_then(|addr| {
                if let IpAddr::V4(addr) = addr {
                    Some(*addr)
                } else {
                    None
                }
            })
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_tlv::sub_tlvs::PATH)
        .get_iterate(|_instance, _args| {
            // TODO: implement me!
            None
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_tlv::sub_tlvs::unknown_sub_tlv::r#type::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.tlv_type)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_tlv::sub_tlvs::unknown_sub_tlv::length::PATH)
        .get_element_u16(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Some(tlv.length)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_tlv::sub_tlvs::unknown_sub_tlv::value::PATH)
        .get_element_string(|_instance, args| {
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            let bytes =
                tlv.value.iter().map(|byte| format!("{:02x}", byte)).join(":");
            Some(bytes)
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::grace_period::PATH)
        .get_element_u32(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_grace()
                && let Some(grace_period) = &lsa_body.grace_period {
                    Some(grace_period.get())
            } else {
                None
            }
        })
        .path(ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::graceful_restart_reason::PATH)
        .get_element_string(|_instance, args| {
            let lse: &LsaEntry<Ospfv3> =
                args.list_entry.as_interface_lsa().unwrap();
            let lsa = &lse.data;
            if let Some(lsa_body) = lsa.body.as_grace()
                && let Some(gr_reason) = &lsa_body.gr_reason
                && let Some(gr_reason) = GrReason::from_u8(gr_reason.get()) {
                    Some(gr_reason.to_yang())
            } else {
                None
            }
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    const STATE_PATH: &'static str = V::STATE_PATH;

    type ListEntry<'a> = ListEntry<'a, V>;

    fn callbacks() -> Option<&'static Callbacks<Instance<V>>> {
        V::state_callbacks()
    }
}

// ===== impl ListEntry =====

impl<'a, V> ListEntryKind for ListEntry<'a, V>
where
    V: Version,
{
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::SpfLog(log) => {
                use ospf::spf_log::event::list_keys;
                let keys = list_keys(log.id);
                Some(keys)
            }
            ListEntry::SpfTriggerLsa(_) => {
                // Keyless list.
                None
            }
            ListEntry::LsaLog(log) => {
                use ospf::lsa_log::event::list_keys;
                let keys = list_keys(log.id);
                Some(keys)
            }
            ListEntry::Route(destination, _) => {
                use ospf::local_rib::route::list_keys;
                let keys = list_keys(destination);
                Some(keys)
            }
            ListEntry::Nexthop(_) => {
                // Keyless list.
                None
            }
            ListEntry::StatsAsLsaType(_) => {
                // Keyless list.
                None
            }
            ListEntry::AsLsaType(lsdb_type) => {
                use ospf::database::as_scope_lsa_type::list_keys;
                let keys = list_keys(lsdb_type.lsa_type());
                Some(keys)
            }
            ListEntry::AsLsa(lse) => {
                use ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::list_keys;
                let lsa = &lse.data;
                let keys = list_keys(lsa.hdr.lsa_id(), lsa.hdr.adv_rtr());
                Some(keys)
            }
            ListEntry::Area(area) => {
                use ospf::areas::area::list_keys;
                let keys = list_keys(area.area_id);
                Some(keys)
            }
            ListEntry::AreaStatsLsaType(_) => {
                // Keyless list.
                None
            }
            ListEntry::AreaLsaType(lsdb_type) => {
                use ospf::areas::area::database::area_scope_lsa_type::list_keys;
                let keys = list_keys(lsdb_type.lsa_type());
                Some(keys)
            }
            ListEntry::AreaLsa(lse) => {
                use ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::list_keys;
                let lsa = &lse.data;
                let keys = list_keys(lsa.hdr.lsa_id(), lsa.hdr.adv_rtr());
                Some(keys)
            }
            ListEntry::Interface(iface) => {
                use ospf::areas::area::interfaces::interface::list_keys;
                let keys = list_keys(&iface.name);
                Some(keys)
            }
            ListEntry::InterfaceStatsLsaType(_) => {
                // Keyless list.
                None
            }
            ListEntry::InterfaceLsaType(lsdb_type) => {
                use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::list_keys;
                let keys = list_keys(lsdb_type.lsa_type());
                Some(keys)
            }
            ListEntry::InterfaceLsa(lse) => {
                use ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::list_keys;
                let lsa = &lse.data;
                let keys = list_keys(lsa.hdr.lsa_id(), lsa.hdr.adv_rtr());
                Some(keys)
            }
            ListEntry::Neighbor(_, nbr) => {
                use ospf::areas::area::interfaces::interface::neighbors::neighbor::list_keys;
                let keys = list_keys(nbr.router_id);
                Some(keys)
            }
            ListEntry::Msd(..)
            | ListEntry::SrAlgo(..)
            | ListEntry::Srgb(..)
            | ListEntry::Srlb(..)
            | ListEntry::UnknownTlv(..)
            | ListEntry::Flag(..)
            | ListEntry::FlagU32(..)
            | ListEntry::NetworkLsaAttachedRtr(..)
            | ListEntry::Ospfv2RouterLsaLink(..)
            | ListEntry::Ospfv2ExtPrefixTlv(..)
            | ListEntry::Ospfv2AdjSid(..)
            | ListEntry::Ospfv2PrefixSid(..)
            | ListEntry::Ospfv3RouterLsaLink(..)
            | ListEntry::Ospfv3LinkLsaPrefix(..)
            | ListEntry::Ospfv3AdjSid(..)
            | ListEntry::Ospfv3IntraAreaLsaPrefix(..)
            | ListEntry::Ospfv3PrefixSid(..)
            | ListEntry::Ospfv3LinkLocalAddr(..) => {
                // Keyless lists.
                None
            }
        }
    }
}

impl<'a, V> Default for ListEntry<'a, V>
where
    V: Version,
{
    fn default() -> ListEntry<'a, V> {
        ListEntry::None
    }
}
