//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

#![allow(unreachable_code)]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{LazyLock as Lazy, atomic};
use std::time::Instant;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::isis;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::option::OptionExt;
use holo_utils::sr::Sid;
use holo_yang::{ToYang, ToYangBits};
use ipnetwork::IpNetwork;

use crate::adjacency::{Adjacency, AdjacencySid};
use crate::collections::Lsdb;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::{LspEntry, LspLogEntry, LspLogId};
use crate::packet::subtlvs::capability::LabelBlockEntry;
use crate::packet::subtlvs::neighbor::AdjSidStlv;
use crate::packet::subtlvs::prefix::{PrefixAttrFlags, PrefixSidStlv};
use crate::packet::tlv::{
    AuthenticationTlv, IpReachTlvEntry, Ipv4Reach, Ipv6Reach, IsReach,
    LegacyIpv4Reach, LegacyIsReach, MultiTopologyEntry, RouterCapTlv,
    UnknownTlv,
};
use crate::packet::{LanId, LevelNumber, LevelType, SystemId};
use crate::route::{Nexthop, Route};
use crate::spf::{SpfLogEntry, SpfScheduler};

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    SpfDelay(LevelNumber, &'a SpfScheduler),
    SpfLog(&'a SpfLogEntry),
    SpfTriggerLsp(&'a LspLogId),
    LspLog(&'a LspLogEntry),
    Hostname(&'a SystemId, &'a String),
    Lsdb(LevelNumber, &'a Lsdb),
    LspEntry(&'a LspEntry),
    RouterCap(&'a RouterCapTlv),
    NodeTag(u32),
    LabelBlockEntry(&'a LabelBlockEntry),
    MultiTopologyEntry(&'a MultiTopologyEntry),
    LegacyIsReach(LanId, Vec<&'a LegacyIsReach>),
    LegacyIsReachInstance(u32, &'a LegacyIsReach),
    ExtIsReach(LanId, Vec<&'a IsReach>),
    ExtIsReachInstance(u32, &'a IsReach),
    MtIsReach(u16, LanId, Vec<&'a IsReach>),
    MtIsReachInstance(u32, &'a IsReach),
    IsReachUnreservedBw(usize, &'a f32),
    AdjSidStlv(&'a AdjSidStlv),
    Ipv4Reach(&'a LegacyIpv4Reach),
    ExtIpv4Reach(&'a Ipv4Reach),
    MtIpv4Reach(u16, &'a Ipv4Reach),
    Ipv6Reach(&'a Ipv6Reach),
    MtIpv6Reach(u16, &'a Ipv6Reach),
    PrefixSidStlv(&'a PrefixSidStlv),
    UnknownTlv(&'a UnknownTlv),
    Route(&'a IpNetwork, &'a Route),
    Nexthop(&'a Nexthop),
    SystemCounters(LevelNumber),
    Interface(&'a Interface),
    InterfacePacketCounters(&'a Interface, LevelNumber),
    InterfaceSrmList(&'a Interface, LevelNumber),
    InterfaceSsnList(&'a Interface, LevelNumber),
    Adjacency(&'a Adjacency),
    AdjacencySid(&'a AdjacencySid),
    Msd(u8, u8),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(isis::PATH)
        .get_object(|instance, _args| {
            use isis::Isis;
            Box::new(Isis {
                discontinuity_time: instance.state.as_ref().map(|state| &state.discontinuity_time).map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(isis::spf_control::ietf_spf_delay::level::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance.config.levels().map(|level| ListEntry::SpfDelay(level, instance_state.spf_sched.get(level)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::spf_control::ietf_spf_delay::level::Level;
            let (level, spf_sched) = args.list_entry.as_spf_delay().unwrap();
            Box::new(Level {
                level: *level as u8,
                current_state: Some(spf_sched.delay_state.to_yang()),
                remaining_time_to_learn: spf_sched.learn_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                remaining_hold_down: spf_sched.hold_down_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                last_event_received: spf_sched.last_event_rcvd.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                next_spf_time: spf_sched.delay_timer.as_ref().map(|timer| Instant::now() + timer.remaining()).map(Cow::Owned).ignore_in_testing(),
                last_spf_time: spf_sched.last_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(isis::spf_log::event::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.spf_log.iter().map(ListEntry::SpfLog);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::spf_log::event::Event;
            let log = args.list_entry.as_spf_log().unwrap();
            Box::new(Event {
                id: log.id,
                spf_type: Some(log.spf_type.to_yang()),
                level: Some(log.level as u8),
                schedule_timestamp: log.schedule_time.as_ref().map(Cow::Borrowed),
                start_timestamp: Some(Cow::Borrowed(&log.start_time)),
                end_timestamp: Some(Cow::Borrowed(&log.end_time)),
            })
        })
        .path(isis::spf_log::event::trigger_lsp::PATH)
        .get_iterate(|_instance, args| {
            let log = args.parent_list_entry.as_spf_log().unwrap();
            let iter = log.trigger_lsps.iter().map(ListEntry::SpfTriggerLsp);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::spf_log::event::trigger_lsp::TriggerLsp;
            let lsp = args.list_entry.as_spf_trigger_lsp().unwrap();
            Box::new(TriggerLsp {
                lsp: lsp.lsp_id.to_yang(),
                sequence: Some(lsp.seqno),
            })
        })
        .path(isis::lsp_log::event::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.lsp_log.iter().map(ListEntry::LspLog);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::lsp_log::event::Event;
            let log = args.list_entry.as_lsp_log().unwrap();
            Box::new(Event {
                id: log.id,
                level: Some(log.level as u8),
                received_timestamp: log.rcvd_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                reason: Some(log.reason.to_yang()),
            })
        })
        .path(isis::lsp_log::event::lsp::PATH)
        .get_object(|_instance, args| {
            use isis::lsp_log::event::lsp::Lsp;
            let log = args.list_entry.as_lsp_log().unwrap();
            Box::new(Lsp {
                lsp: Some(log.lsp.lsp_id.to_yang()),
                sequence: Some(log.lsp.seqno),
            })
        })
        .path(isis::hostnames::hostname::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.hostnames.iter().map(|(system_id, hostname)| ListEntry::Hostname(system_id, hostname));
            Some(Box::new(iter) as _)
        })
        .get_object(|_instance, args| {
            use isis::hostnames::hostname::Hostname;
            let (system_id, hostname) = args.list_entry.as_hostname().unwrap();
            Box::new(Hostname {
                system_id: system_id.to_yang(),
                hostname: Some(Cow::Borrowed(hostname)),
            })
        })
        .path(isis::database::levels::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance.config.levels().map(|level| ListEntry::Lsdb(level, instance_state.lsdb.get(level)));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::Levels;
            let (level, _) = args.list_entry.as_lsdb().unwrap();
            Box::new(Levels {
                level: *level as u8,
            })
        })
        .path(isis::database::levels::lsp::PATH)
        .get_iterate(|instance, args| {
            let (_, lsdb) = args.parent_list_entry.as_lsdb().unwrap();
            let iter = lsdb.iter(&instance.arenas.lsp_entries).map(ListEntry::LspEntry);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::Lsp;
            let lse = args.list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let remaining_lifetime = lsp.rem_lifetime();
            let ipv4_addresses = lsp.tlvs.ipv4_addrs().map(Cow::Borrowed);
            let ipv6_addresses = lsp.tlvs.ipv6_addrs().map(Cow::Borrowed);
            let protocol_supported = lsp.tlvs.protocols_supported();
            let area_addresses = lsp.tlvs.area_addrs().map(|area| area.to_yang());
            Box::new(Lsp {
                lsp_id: lsp.lsp_id.to_yang(),
                decoded_completed: None,
                raw_data: Some(lsp.raw.as_ref()).ignore_in_testing(),
                checksum: Some(lsp.cksum).ignore_in_testing(),
                remaining_lifetime: Some(remaining_lifetime).ignore_in_testing_if(remaining_lifetime != 0),
                sequence: Some(lsp.seqno).ignore_in_testing_if(lsp.seqno != 0),
                ipv4_addresses: Some(Box::new(ipv4_addresses)),
                ipv6_addresses: Some(Box::new(ipv6_addresses)),
                ipv4_te_routerid: lsp.tlvs.ipv4_router_id.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                ipv6_te_routerid: lsp.tlvs.ipv6_router_id.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                protocol_supported: Some(Box::new(protocol_supported)),
                dynamic_hostname: lsp.tlvs.hostname().map(Cow::Borrowed),
                area_addresses: Some(Box::new(area_addresses)),
                lsp_buffer_size: lsp.tlvs.lsp_buf_size(),
                received_remaining_lifetime: lsp.rcvd_rem_lifetime.ignore_in_testing_if(lsp.rcvd_rem_lifetime != Some(0)),
            })
        })
        .path(isis::database::levels::lsp::attributes::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::attributes::Attributes;
            let lse = args.list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Attributes {
                lsp_flags: Some(Box::new(iter) as _),
            })
        })
        .path(isis::database::levels::lsp::authentication::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::authentication::Authentication;
            let lse = args.list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let authentication_type =
                lsp.tlvs.auth.as_ref().and_then(|auth| match auth {
                    AuthenticationTlv::ClearText(..) => {
                        Some(CryptoAlgo::ClearText.to_yang())
                    }
                    AuthenticationTlv::HmacMd5(..) => {
                        Some(CryptoAlgo::HmacMd5.to_yang())
                    }
                    AuthenticationTlv::Cryptographic {..} => {
                        // The authentication algorithm is never sent in
                        // cleartext over the wire.
                        None
                    }
                });
            let authentication_key =
                lsp.tlvs.auth.as_ref().and_then(|auth| match auth {
                    AuthenticationTlv::ClearText(..) => None,
                    AuthenticationTlv::HmacMd5(digest) => {
                        Some(Cow::Owned(format_hmac_digest(digest)))
                    }
                    AuthenticationTlv::Cryptographic { digest, .. } => {
                        Some(Cow::Owned(format_hmac_digest(digest)))
                    }
                });
            Box::new(Authentication {
                authentication_type,
                authentication_key,
            })
        })
        .path(isis::database::levels::lsp::mt_entries::topology::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.multi_topology().map(ListEntry::MultiTopologyEntry);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_entries::topology::Topology;
            let mt = args.list_entry.as_multi_topology_entry().unwrap();
            Box::new(Topology {
                mt_id: Some(mt.mt_id),
            })
        })
        .path(isis::database::levels::lsp::mt_entries::topology::attributes::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_entries::topology::attributes::Attributes;
            let mt = args.list_entry.as_multi_topology_entry().unwrap();
            let iter = mt.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Attributes {
                flags: Some(Box::new(iter) as _),
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.router_cap.iter().map(ListEntry::RouterCap);
            Some(Box::new(iter))
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::flags::Flags;
            let router_cap = args.list_entry.as_router_cap().unwrap();
            let iter = router_cap.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(Flags {
                router_capability_flags: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::node_tags::node_tag::PATH)
        .get_iterate(|_instance, args| {
            let router_cap = args.parent_list_entry.as_router_cap().unwrap();
            let iter = router_cap.sub_tlvs.node_tags.iter().flat_map(|stlv| stlv.get().iter().copied()).map(ListEntry::NodeTag);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::node_tags::node_tag::NodeTag;
            let node_tag = args.list_entry.as_node_tag().unwrap();
            Box::new(NodeTag {
                tag: Some(*node_tag),
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let router_cap = args.parent_list_entry.as_router_cap().unwrap();
            let iter = router_cap.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::SrCapability;
            let router_cap = args.list_entry.as_router_cap().unwrap();
            let mut sr_capability_flag = None;
            if let Some(sr_cap) = &router_cap.sub_tlvs.sr_cap {
                let iter = sr_cap.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
                sr_capability_flag = Some(Box::new(iter) as _);
            }
            Box::new(SrCapability {
                sr_capability_flag,
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::global_blocks::global_block::PATH)
        .get_iterate(|_instance, args| {
            let router_cap = args.parent_list_entry.as_router_cap().unwrap();
            if let Some(sr_cap) = &router_cap.sub_tlvs.sr_cap {
                let iter = sr_cap.srgb_entries.iter().map(ListEntry::LabelBlockEntry);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::global_blocks::global_block::GlobalBlock;
            let entry = args.list_entry.as_label_block_entry().unwrap();
            let mut obj = GlobalBlock::default();
            obj.range_size = Some(entry.range);
            match entry.first {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            }
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::sr_algorithms::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::sr_algorithms::SrAlgorithms;
            let router_cap = args.list_entry.as_router_cap().unwrap();
            let mut sr_algorithm = None;
            if let Some(sr_algo) = &router_cap.sub_tlvs.sr_algo {
                let iter = sr_algo.get().iter().map(|algo| algo.to_yang());
                sr_algorithm = Some(Box::new(iter) as _);
            }
            Box::new(SrAlgorithms {
                sr_algorithm,
            })
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::local_blocks::local_block::PATH)
        .get_iterate(|_instance, args| {
            let router_cap = args.parent_list_entry.as_router_cap().unwrap();
            if let Some(srlb) = &router_cap.sub_tlvs.srlb {
                let iter = srlb.entries.iter().map(ListEntry::LabelBlockEntry);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::local_blocks::local_block::LocalBlock;
            let entry = args.list_entry.as_label_block_entry().unwrap();
            let mut obj = LocalBlock::default();
            obj.range_size = Some(entry.range);
            match entry.first {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            }
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::router_capabilities::router_capability::node_msd_tlv::node_msds::PATH)
        .get_iterate(|_instance, args| {
            let router_cap = args.parent_list_entry.as_router_cap().unwrap();
            if let Some(link_msd) = &router_cap.sub_tlvs.node_msd {
                let iter = link_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::router_capabilities::router_capability::node_msd_tlv::node_msds::NodeMsds;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(NodeMsds {
                msd_type: *msd_type,
                msd_value: Some(*msd_value),
            })
        })
        .path(isis::database::levels::lsp::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp
                .tlvs
                .is_reach()
                .fold(BTreeMap::<LanId, Vec<_>>::new(), |mut entries, reach| {
                    let list_key = reach.neighbor;
                    entries.entry(list_key).or_default().push(reach);
                    entries
                })
                .into_iter()
                .map(|(neighbor, entries)| ListEntry::LegacyIsReach(neighbor, entries));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::Neighbor;
            let (neighbor, _) = args.list_entry.as_legacy_is_reach().unwrap();
            Box::new(Neighbor {
                neighbor_id: neighbor.to_yang(),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::PATH)
        .get_iterate(|_instance, args| {
            let (_, entries) = args.parent_list_entry.as_legacy_is_reach().unwrap();
            let iter = entries.iter().enumerate().map(|(id, entry)| ListEntry::LegacyIsReachInstance(id as u32, entry));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::Instance;
            let (id, _) = args.list_entry.as_legacy_is_reach_instance().unwrap();
            Box::new(Instance {
                id: *id,
                i_e: Some(false),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::DefaultMetric;
            let (_, reach) = args.list_entry.as_legacy_is_reach_instance().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::DelayMetric;
            let (_, reach) = args.list_entry.as_legacy_is_reach_instance().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::ExpenseMetric;
            let (_, reach) = args.list_entry.as_legacy_is_reach_instance().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::ErrorMetric;
            let (_, reach) = args.list_entry.as_legacy_is_reach_instance().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp
                .tlvs
                .ext_is_reach()
                .fold(BTreeMap::<LanId, Vec<_>>::new(), |mut entries, reach| {
                    let list_key = reach.neighbor;
                    entries.entry(list_key).or_default().push(reach);
                    entries
                })
                .into_iter()
                .map(|(neighbor, entries)| ListEntry::ExtIsReach(neighbor, entries));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::Neighbor;
            let (neighbor, _) = args.list_entry.as_ext_is_reach().unwrap();
            Box::new(Neighbor {
                neighbor_id: neighbor.to_yang(),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::PATH)
        .get_iterate(|_instance, args| {
            let (_, entries) = args.parent_list_entry.as_ext_is_reach().unwrap();
            let iter = entries.iter().enumerate().map(|(id, entry)| ListEntry::ExtIsReachInstance(id as u32, entry));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::Instance;
            let (id, reach) = args.list_entry.as_ext_is_reach_instance().unwrap();
            Box::new(Instance {
                id: *id,
                metric: Some(reach.metric),
                admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
                te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
                max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
                max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs;
            let (_, reach) = args.list_entry.as_ext_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
            Box::new(LocalIfIpv4Addrs {
                local_if_ipv4_addr: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs;
            let (_, reach) = args.list_entry.as_ext_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
            Box::new(RemoteIfIpv4Addrs {
                remote_if_ipv4_addr: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_ext_is_reach_instance().unwrap();
            if let Some(unreserved_bw) = &reach.sub_tlvs.unreserved_bw {
                let iter = unreserved_bw.iter().map(|(prio, bw)| ListEntry::IsReachUnreservedBw(prio, bw));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth;
            let (priority, unreserved_bandwidth) = args.list_entry.as_is_reach_unreserved_bw().unwrap();
            Box::new(UnreservedBandwidth {
                priority: Some(*priority as u8),
                unreserved_bandwidth: Some(unreserved_bandwidth),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_ext_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_ext_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.adj_sids.iter().map(ListEntry::AdjSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv;
            let stlv = args.list_entry.as_adj_sid_stlv().unwrap();
            let mut obj = AdjSidSubTlv::default();
            obj.weight = Some(stlv.weight);
            obj.neighbor_id = stlv.nbr_system_id.as_ref().map(|system_id| system_id.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags;
            let stlv = args.list_entry.as_adj_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(AdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_ext_is_reach_instance().unwrap();
            if let Some(link_msd) = &reach.sub_tlvs.link_msd {
                let iter = link_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(LinkMsds {
                msd_type: *msd_type,
                msd_value: Some(*msd_value),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ipv4_internal_reach().map(ListEntry::Ipv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(Prefixes {
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                i_e: Some(reach.ie_bit),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::DefaultMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::DelayMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::ExpenseMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::ErrorMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ipv4_external_reach().map(ListEntry::Ipv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(Prefixes {
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                i_e: Some(reach.ie_bit),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::DefaultMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DefaultMetric {
                metric: Some(reach.metric),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::DelayMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(DelayMetric {
                metric: reach.metric_delay,
                supported: Some(reach.metric_delay.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::ExpenseMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ExpenseMetric {
                metric: reach.metric_expense,
                supported: Some(reach.metric_expense.is_some()),
            })
        })
        .path(isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::ErrorMetric;
            let reach = args.list_entry.as_ipv4_reach().unwrap();
            Box::new(ErrorMetric {
                metric: reach.metric_error,
                supported: Some(reach.metric_error.is_some()),
            })
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ext_ipv4_reach().map(ListEntry::ExtIpv4Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ext_ipv4_reach().unwrap();
            Box::new(Prefixes {
                up_down: Some(reach.up_down),
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                metric: Some(reach.metric),
                external_prefix_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::X),
                node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
                readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
                ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            })
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let reach = args.parent_list_entry.as_ext_ipv4_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let reach = args.parent_list_entry.as_ext_ipv4_reach().unwrap();
            let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let mut obj = PrefixSidSubTlv::default();
            obj.algorithm = Some(stlv.algo.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp
                .tlvs
                .mt_is_reach()
                .fold(BTreeMap::<(u16, LanId), Vec<_>>::new(), |mut entries, (mt_id, reach)| {
                    let list_key = (mt_id, reach.neighbor);
                    entries.entry(list_key).or_default().push(reach);
                    entries
                })
                .into_iter()
                .map(|((mt_id, neighbor), entries)| ListEntry::MtIsReach(mt_id, neighbor, entries));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::Neighbor;
            let (mt_id, neighbor, _) = args.list_entry.as_mt_is_reach().unwrap();
            Box::new(Neighbor {
                mt_id: Some(*mt_id),
                neighbor_id: Some(neighbor.to_yang()),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::PATH)
        .get_iterate(|_instance, args| {
            let (_, _, entries) = args.parent_list_entry.as_mt_is_reach().unwrap();
            let iter = entries.iter().enumerate().map(|(id, entry)| ListEntry::MtIsReachInstance(id as u32, entry));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::Instance;
            let (id, reach) = args.list_entry.as_mt_is_reach_instance().unwrap();
            Box::new(Instance {
                id: *id,
                metric: Some(reach.metric),
                admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
                te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
                max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
                max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs;
            let (_, reach) = args.list_entry.as_mt_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
            Box::new(LocalIfIpv4Addrs {
                local_if_ipv4_addr: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs;
            let (_, reach) = args.list_entry.as_mt_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
            Box::new(RemoteIfIpv4Addrs {
                remote_if_ipv4_addr: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_is_reach_instance().unwrap();
            if let Some(unreserved_bw) = &reach.sub_tlvs.unreserved_bw {
                let iter = unreserved_bw.iter().map(|(prio, bw)| ListEntry::IsReachUnreservedBw(prio, bw));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth;
            let (priority, unreserved_bandwidth) = args.list_entry.as_is_reach_unreserved_bw().unwrap();
            Box::new(UnreservedBandwidth {
                priority: Some(*priority as u8),
                unreserved_bandwidth: Some(unreserved_bandwidth),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_is_reach_instance().unwrap();
            let iter = reach.sub_tlvs.adj_sids.iter().map(ListEntry::AdjSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv;
            let stlv = args.list_entry.as_adj_sid_stlv().unwrap();
            let mut obj = AdjSidSubTlv::default();
            obj.weight = Some(stlv.weight);
            obj.neighbor_id = stlv.nbr_system_id.as_ref().map(|system_id| system_id.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags;
            let stlv = args.list_entry.as_adj_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(AdjSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_is_reach_instance().unwrap();
            if let Some(link_msd) = &reach.sub_tlvs.link_msd {
                let iter = link_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds;
            let (msd_type, msd_value) = args.list_entry.as_msd().unwrap();
            Box::new(LinkMsds {
                msd_type: *msd_type,
                msd_value: Some(*msd_value),
            })
        })
        .path(isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.mt_ipv4_reach().map(|(mt_id, entry)| ListEntry::MtIpv4Reach(mt_id, entry));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::Prefixes;
            let (mt_id, reach) = args.list_entry.as_mt_ipv4_reach().unwrap();
            Box::new(Prefixes {
                mt_id: Some(*mt_id),
                up_down: Some(reach.up_down),
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                metric: Some(reach.metric),
                external_prefix_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::X),
                node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
                readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
                ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            })
        })
        .path(isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_ipv4_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_ipv4_reach().unwrap();
            let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let mut obj = PrefixSidSubTlv::default();
            obj.algorithm = Some(stlv.algo.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::mt_ipv6_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.mt_ipv6_reach().map(|(mt_id, entry)| ListEntry::MtIpv6Reach(mt_id, entry));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_ipv6_reachability::prefixes::Prefixes;
            let (mt_id, reach) = args.list_entry.as_mt_ipv6_reach().unwrap();
            Box::new(Prefixes {
                mt_id: Some(*mt_id),
                up_down: Some(reach.up_down),
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                metric: Some(reach.metric),
                external_prefix_flag: Some(reach.external),
                node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
                readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
                ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            })
        })
        .path(isis::database::levels::lsp::mt_ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_ipv6_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let (_, reach) = args.parent_list_entry.as_mt_ipv6_reach().unwrap();
            let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let mut obj = PrefixSidSubTlv::default();
            obj.algorithm = Some(stlv.algo.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::PATH)
        .get_iterate(|_instance, args| {
            let lse = args.parent_list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            let iter = lsp.tlvs.ipv6_reach().map(ListEntry::Ipv6Reach);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::Prefixes;
            let reach = args.list_entry.as_ipv6_reach().unwrap();
            Box::new(Prefixes {
                up_down: Some(reach.up_down),
                ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
                prefix_len: Some(reach.prefix.prefix()),
                metric: Some(reach.metric),
                external_prefix_flag: Some(reach.external),
                node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
                readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
                ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
                ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            })
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::PATH)
        .get_iterate(|_instance, args| {
            let reach = args.parent_list_entry.as_ipv6_reach().unwrap();
            let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv;
            let tlv = args.list_entry.as_unknown_tlv().unwrap();
            Box::new(UnknownTlv {
                r#type: Some(tlv.tlv_type as u16),
                length: Some(tlv.length as u16),
                value: Some(tlv.value.as_ref()),
            })
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PATH)
        .get_iterate(|_instance, args| {
            let reach = args.parent_list_entry.as_ipv6_reach().unwrap();
            let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let mut obj = PrefixSidSubTlv::default();
            obj.algorithm = Some(stlv.algo.to_yang());
            match stlv.sid {
                Sid::Index(index) => {
                    obj.index_value = Some(index);
                },
                Sid::Label(label) => {
                    obj.label_value = Some(label.get());
                },
            };
            Box::new(obj)
        })
        .path(isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags;
            let stlv = args.list_entry.as_prefix_sid_stlv().unwrap();
            let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
            Box::new(PrefixSidFlags {
                flag: Some(Box::new(iter)),
            })
        })
        .path(isis::database::levels::lsp::purge_originator_identification::PATH)
        .get_object(|_instance, args| {
            use isis::database::levels::lsp::purge_originator_identification::PurgeOriginatorIdentification;
            let lse = args.list_entry.as_lsp_entry().unwrap();
            let lsp = &lse.data;
            Box::new(PurgeOriginatorIdentification {
                originator: lsp.tlvs.purge_originator_id.as_ref().map(|tlv| tlv.system_id.to_yang()),
                received_from: lsp.tlvs.purge_originator_id.as_ref().and_then(|tlv| tlv.system_id_rcvd.map(|system_id| system_id.to_yang())),
            })
        })
        .path(isis::local_rib::route::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let rib = instance_state.rib(instance.config.level_type);
            let iter = rib.iter().map(|(destination, route)| ListEntry::Route(destination, route));
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::local_rib::route::Route;
            let (prefix, route) = args.list_entry.as_route().unwrap();
            Box::new(Route {
                prefix: Cow::Borrowed(prefix),
                metric: Some(route.metric),
                level: Some(route.level as u8),
                route_tag: route.tag,
            })
        })
        .path(isis::local_rib::route::next_hops::next_hop::PATH)
        .get_iterate(|_instance, args| {
            let (_, route) = args.parent_list_entry.as_route().unwrap();
            let iter = route.nexthops.values().map(ListEntry::Nexthop);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use isis::local_rib::route::next_hops::next_hop::NextHop;
            let nexthop = args.list_entry.as_nexthop().unwrap();
            let iface = &instance.arenas.interfaces[nexthop.iface_idx];
            Box::new(NextHop {
                next_hop: Cow::Borrowed(&nexthop.addr),
                outgoing_interface: Some(Cow::Borrowed(iface.name.as_str())),
            })
        })
        .path(isis::system_counters::level::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.config.levels().map(ListEntry::SystemCounters);
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|instance, args| {
            use isis::system_counters::level::Level;
            let level = args.list_entry.as_system_counters().unwrap();
            let mut corrupted_lsps = None;
            let mut authentication_type_fails = None;
            let mut authentication_fails = None;
            let mut database_overload = None;
            let mut own_lsp_purge = None;
            let mut manual_address_drop_from_area = None;
            let mut max_sequence = None;
            let mut sequence_number_skipped = None;
            let mut id_len_mismatch = None;
            let mut partition_changes = None;
            let mut lsp_errors = None;
            let mut spf_runs = None;
            if let Some(state) = &instance.state {
                let counters = state.counters.get(*level);
                corrupted_lsps = Some(counters.corrupted_lsps);
                authentication_type_fails = Some(counters.auth_type_fails);
                authentication_fails = Some(counters.auth_fails);
                database_overload = Some(counters.database_overload);
                own_lsp_purge = Some(counters.own_lsp_purge);
                manual_address_drop_from_area = Some(counters.manual_addr_drop_from_area);
                max_sequence = Some(counters.max_sequence);
                sequence_number_skipped = Some(counters.seqno_skipped);
                id_len_mismatch = Some(counters.id_len_mismatch);
                partition_changes = Some(counters.partition_changes);
                lsp_errors = Some(counters.lsp_errors);
                spf_runs = Some(counters.spf_runs);
            }
            Box::new(Level {
                level: *level as u8,
                corrupted_lsps,
                authentication_type_fails,
                authentication_fails,
                database_overload,
                own_lsp_purge,
                manual_address_drop_from_area,
                max_sequence,
                sequence_number_skipped,
                id_len_mismatch,
                partition_changes,
                lsp_errors,
                spf_runs,
            })
        })
        .path(isis::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            let iter = instance.arenas.interfaces.iter().map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            let state = if iface.state.active { "up" } else { "down" };
            Box::new(Interface {
                name: Cow::Borrowed(&iface.name),
                discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
                state: Some(state.into()),
                circuit_id: Some(iface.state.circuit_id),
            })
        })
        .path(isis::interfaces::interface::adjacencies::adjacency::PATH)
        .get_iterate(|instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.adjacencies(&instance.arenas.adjacencies).map(ListEntry::Adjacency);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::adjacencies::adjacency::Adjacency;
            let adj = args.list_entry.as_adjacency().unwrap();
            let area_addresses = adj.area_addrs.iter().map(|area| area.to_yang());
            let ipv4_addresses = adj.ipv4_addrs.iter().map(Cow::Borrowed);
            let ipv6_addresses = adj.ipv6_addrs.iter().map(Cow::Borrowed);
            let protocol_supported = adj.protocols_supported.iter().copied();
            let topologies = adj.topologies.iter().copied();
            Box::new(Adjacency {
                neighbor_sys_type: Some(adj.level_capability.to_yang()),
                neighbor_sysid: Some(adj.system_id.to_yang()),
                neighbor_extended_circuit_id: None,
                neighbor_snpa: Some(Cow::Owned(adj.snpa.to_string())).ignore_in_testing(),
                usage: Some(adj.level_usage.to_yang()),
                hold_timer: adj.holdtimer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
                neighbor_priority: adj.priority,
                lastuptime: adj.last_uptime.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                state: Some(adj.state.to_yang()),
                area_addresses: Some(Box::new(area_addresses)),
                ipv4_addresses: Some(Box::new(ipv4_addresses)),
                ipv6_addresses: Some(Box::new(ipv6_addresses)),
                protocol_supported: Some(Box::new(protocol_supported)),
                topologies: Some(Box::new(topologies)),
            })
        })
        .path(isis::interfaces::interface::adjacencies::adjacency::adjacency_sid::PATH)
        .get_iterate(|_instance, args| {
            let adj = args.parent_list_entry.as_adjacency().unwrap();
            let iter = adj.adj_sids.iter().map(ListEntry::AdjacencySid);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::adjacencies::adjacency::adjacency_sid::AdjacencySid;
            let adj_sid = args.list_entry.as_adjacency_sid().unwrap();
            Box::new(AdjacencySid {
                value: Some(adj_sid.label.get()),
                address_family: Some(adj_sid.af.to_yang()),
                weight: Some(0),
                protection_requested: Some(false),
            })
        })
        .path(isis::interfaces::interface::event_counters::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::event_counters::EventCounters;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(EventCounters {
                adjacency_changes: Some(iface.state.event_counters.adjacency_changes).ignore_in_testing(),
                adjacency_number: Some(iface.state.event_counters.adjacency_number).ignore_in_testing(),
                init_fails: Some(iface.state.event_counters.init_fails).ignore_in_testing(),
                adjacency_rejects: Some(iface.state.event_counters.adjacency_rejects).ignore_in_testing(),
                id_len_mismatch: Some(iface.state.event_counters.id_len_mismatch).ignore_in_testing(),
                max_area_addresses_mismatch: Some(iface.state.event_counters.max_area_addr_mismatch).ignore_in_testing(),
                authentication_type_fails: Some(iface.state.event_counters.auth_type_fails).ignore_in_testing(),
                authentication_fails: Some(iface.state.event_counters.auth_fails).ignore_in_testing(),
                lan_dis_changes: Some(iface.state.event_counters.lan_dis_changes).ignore_in_testing(),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = iface.config.levels().map(|level| ListEntry::InterfacePacketCounters(iface, level));
            Some(Box::new(iter) as _).ignore_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::Level;
            let (_, level) = args.list_entry.as_interface_packet_counters().unwrap();
            Box::new(Level {
                level: *level as u8,
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::iih::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::iih::Iih;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Iih {
                r#in: Some(packet_counters.iih_in),
                out: Some(packet_counters.iih_out.load(atomic::Ordering::Relaxed)),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::lsp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::lsp::Lsp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Lsp {
                r#in: Some(packet_counters.lsp_in),
                out: Some(packet_counters.lsp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::psnp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::psnp::Psnp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Psnp {
                r#in: Some(packet_counters.psnp_in),
                out: Some(packet_counters.psnp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::csnp::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::csnp::Csnp;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Csnp {
                r#in: Some(packet_counters.csnp_in),
                out: Some(packet_counters.csnp_out),
            })
        })
        .path(isis::interfaces::interface::packet_counters::level::unknown::PATH)
        .get_object(|_instance, args| {
            use isis::interfaces::interface::packet_counters::level::unknown::Unknown;
            let (iface, level) = args.list_entry.as_interface_packet_counters().unwrap();
            let packet_counters = iface.state.packet_counters.get(*level);
            Box::new(Unknown {
                r#in: Some(packet_counters.unknown_in),
            })
        })
        .path(isis::interfaces::interface::srm::level::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = LevelType::All.into_iter().filter(|level| !iface.state.srm_list.get(*level).is_empty()).map(|level| ListEntry::InterfaceSrmList(iface, level));
            Some(Box::new(iter) as _).only_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::srm::level::Level;
            let (iface, level) = args.list_entry.as_interface_srm_list().unwrap();
            Box::new(Level {
                level: *level as u8,
                lsp_id: Some(Box::new(iface.state.srm_list.get(*level).keys().map(|lsp_id| lsp_id.to_yang()))),
            })
        })
        .path(isis::interfaces::interface::ssn::level::PATH)
        .get_iterate(|_instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = LevelType::All.into_iter().filter(|level| !iface.state.ssn_list.get(*level).is_empty()).map(|level| ListEntry::InterfaceSsnList(iface, level));
            Some(Box::new(iter) as _).only_in_testing()
        })
        .get_object(|_instance, args| {
            use isis::interfaces::interface::ssn::level::Level;
            let (iface, level) = args.list_entry.as_interface_ssn_list().unwrap();
            Box::new(Level {
                level: *level as u8,
                lsp_id: Some(Box::new(iface.state.ssn_list.get(*level).keys().map(|lsp_id| lsp_id.to_yang()))),
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

fn format_hmac_digest(digest: &[u8]) -> String {
    digest.iter().fold(
        String::with_capacity(digest.len() * 2),
        |mut output, &byte| {
            write!(&mut output, "{byte:02x}").unwrap();
            output
        },
    )
}
