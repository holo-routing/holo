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
use std::sync::atomic;
use std::time::Instant;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::mac_addr::MacAddr;
use holo_utils::option::OptionExt;
use holo_yang::{ToYang, ToYangBits};
use ipnetwork::IpNetwork;

use crate::adjacency::{Adjacency, AdjacencySid};
use crate::collections::Lsdb;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::{LspEntry, LspLogEntry, LspLogId};
use crate::northbound::yang_gen::{self, isis};
use crate::packet::subtlvs::capability::LabelBlockEntry;
use crate::packet::subtlvs::neighbor::AdjSidStlv;
use crate::packet::subtlvs::prefix::{PrefixAttrFlags, PrefixSidStlv};
use crate::packet::subtlvs::spb::{IsidEntry, IsidFlags, SpbmSiStlv};
use crate::packet::tlv::{AuthenticationTlv, IpReachTlvEntry, Ipv4Reach, Ipv6Reach, IsReach, LegacyIpv4Reach, LegacyIsReach, MtCapabilityTlv, MultiTopologyEntry, RouterCapTlv, UnknownTlv};
use crate::packet::{LanId, LevelNumber, LevelType, SystemId};
use crate::route::{Nexthop, Route};
use crate::spf::{SpfLogEntry, SpfScheduler};

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

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
    MtCap(&'a MtCapabilityTlv),
    SpbmService(&'a SpbmSiStlv),
    SpbmIsid(&'a IsidEntry),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for isis::Isis<'a> {
    fn new(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        Some(Self {
            discontinuity_time: instance.state.as_ref().map(|state| &state.discontinuity_time).map(Cow::Borrowed).ignore_in_testing(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_control::ietf_spf_delay::level::Level<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let spf_sched = &instance.state.as_ref()?.spf_sched;
        let iter = instance.config.levels().map(|level| ListEntry::SpfDelay(level, spf_sched.get(level)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (level, spf_sched) = list_entry.as_spf_delay().unwrap();
        Self {
            level: *level as u8,
            current_state: Some(spf_sched.delay_state.to_yang()),
            remaining_time_to_learn: spf_sched.learn_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            remaining_hold_down: spf_sched.hold_down_timer.as_ref().map(|task| task.remaining()).map(Cow::Owned).ignore_in_testing(),
            last_event_received: spf_sched.last_event_rcvd.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            next_spf_time: spf_sched.delay_timer.as_ref().map(|timer| Instant::now() + timer.remaining()).map(Cow::Owned).ignore_in_testing(),
            last_spf_time: spf_sched.last_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_log::event::Event<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let spf_log = &instance.state.as_ref()?.spf_log;
        let iter = spf_log.iter().map(ListEntry::SpfLog);
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let log = list_entry.as_spf_log().unwrap();
        Self {
            id: log.id,
            spf_type: Some(log.spf_type.to_yang()),
            level: Some(log.level as u8),
            schedule_timestamp: log.schedule_time.as_ref().map(Cow::Borrowed),
            start_timestamp: Some(Cow::Borrowed(&log.start_time)),
            end_timestamp: Some(Cow::Borrowed(&log.end_time)),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_log::event::trigger_lsp::TriggerLsp<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let log = list_entry.as_spf_log().unwrap();
        let iter = log.trigger_lsps.iter().map(ListEntry::SpfTriggerLsp);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let lsp = list_entry.as_spf_trigger_lsp().unwrap();
        Self {
            lsp: lsp.lsp_id.to_yang(),
            sequence: Some(lsp.seqno),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::lsp_log::event::Event<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lsp_log = &instance.state.as_ref()?.lsp_log;
        let iter = lsp_log.iter().map(ListEntry::LspLog);
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let log = list_entry.as_lsp_log().unwrap();
        Self {
            id: log.id,
            level: Some(log.level as u8),
            received_timestamp: log.rcvd_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            reason: Some(log.reason.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::lsp_log::event::lsp::Lsp<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let log = list_entry.as_lsp_log().unwrap();
        Some(Self {
            lsp: Some(log.lsp.lsp_id.to_yang()),
            sequence: Some(log.lsp.seqno),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::hostnames::hostname::Hostname<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let hostnames = &instance.state.as_ref()?.hostnames;
        let iter = hostnames.iter().map(|(system_id, hostname)| ListEntry::Hostname(system_id, hostname));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (system_id, hostname) = list_entry.as_hostname().unwrap();
        Self {
            system_id: system_id.to_yang(),
            hostname: Some(Cow::Borrowed(hostname)),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::Levels {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = instance.config.levels().map(|level| ListEntry::Lsdb(level, lsdb.get(level)));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (level, lsdb) = list_entry.as_lsdb().unwrap();
        Self {
            level: *level as u8,
            lsp_count: Some(lsdb.lsp_count()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::Lsp<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, lsdb) = list_entry.as_lsdb().unwrap();
        let iter = lsdb.iter(&instance.arenas.lsp_entries).map(ListEntry::LspEntry);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let remaining_lifetime = lsp.rem_lifetime();
        let ipv4_addresses = lsp.tlvs.ipv4_addrs().map(Cow::Borrowed);
        let ipv6_addresses = lsp.tlvs.ipv6_addrs().map(Cow::Borrowed);
        let protocol_supported = lsp.tlvs.protocols_supported();
        let area_addresses = lsp.tlvs.area_addrs().map(|area| area.to_yang());
        Self {
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
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::attributes::Attributes<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            lsp_flags: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::authentication::Authentication<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let auth_tlv = lsp.tlvs.auth.as_ref()?;
        let authentication_type = match auth_tlv {
            AuthenticationTlv::ClearText(..) => Some(CryptoAlgo::ClearText.to_yang()),
            AuthenticationTlv::HmacMd5(..) => Some(CryptoAlgo::HmacMd5.to_yang()),
            AuthenticationTlv::Cryptographic {
                ..
            } => {
                // The authentication algorithm is never sent in cleartext over the wire.
                None
            }
        };
        let authentication_key = match auth_tlv {
            AuthenticationTlv::ClearText(..) => {
                // Clear-text password omitted for security reasons.
                None
            }
            AuthenticationTlv::HmacMd5(digest) => Some(Cow::Owned(format_hmac_digest(digest))),
            AuthenticationTlv::Cryptographic {
                digest, ..
            } => Some(Cow::Owned(format_hmac_digest(digest))),
        };
        Some(Self {
            authentication_type,
            authentication_key,
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_entries::topology::Topology {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.multi_topology().map(ListEntry::MultiTopologyEntry);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let mt = list_entry.as_multi_topology_entry().unwrap();
        Self {
            mt_id: Some(mt.mt_id),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_entries::topology::attributes::Attributes<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let mt = list_entry.as_multi_topology_entry().unwrap();
        let iter = mt.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flags: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::RouterCapability {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.router_cap.iter().map(ListEntry::RouterCap);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let router_cap = list_entry.as_router_cap().unwrap();
        Self {
            flooding_algorithm: router_cap.sub_tlvs.flooding_algo.as_ref().map(|stlv| stlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::flags::Flags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let iter = router_cap.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            router_capability_flags: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::node_tags::node_tag::NodeTag {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let iter = router_cap.sub_tlvs.node_tags.iter().flat_map(|stlv| stlv.get().iter().copied()).map(ListEntry::NodeTag);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let node_tag = list_entry.as_node_tag().unwrap();
        Self {
            tag: Some(*node_tag),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let iter = router_cap.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::node_msd_tlv::node_msds::NodeMsds {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let node_msd = router_cap.sub_tlvs.node_msd.as_ref()?;
        let iter = node_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::SrCapability<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let sr_cap = &router_cap.sub_tlvs.sr_cap.as_ref()?;
        let iter = sr_cap.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            sr_capability_flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::global_blocks::global_block::GlobalBlock {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let sr_cap = &router_cap.sub_tlvs.sr_cap.as_ref()?;
        let iter = sr_cap.srgb_entries.iter().map(ListEntry::LabelBlockEntry);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let label_block = list_entry.as_label_block_entry().unwrap();
        Self {
            range_size: Some(label_block.range),
            label_value: label_block.first.as_label().map(|label| label.get()),
            index_value: label_block.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_algorithms::SrAlgorithms<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let sr_algo = &router_cap.sub_tlvs.sr_algo.as_ref()?;
        let iter = sr_algo.get().iter().map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::local_blocks::local_block::LocalBlock {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let router_cap = list_entry.as_router_cap().unwrap();
        let srlb = router_cap.sub_tlvs.srlb.as_ref()?;
        let iter = srlb.entries.iter().map(ListEntry::LabelBlockEntry);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let label_block = list_entry.as_label_block_entry().unwrap();
        Self {
            range_size: Some(label_block.range),
            label_value: label_block.first.as_label().map(|label| label.get()),
            index_value: label_block.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::Neighbor<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
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
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (neighbor, _) = list_entry.as_legacy_is_reach().unwrap();
        Self {
            neighbor_id: neighbor.to_yang(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::Instance {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, entries) = list_entry.as_legacy_is_reach().unwrap();
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| ListEntry::LegacyIsReachInstance(id as u32, entry));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (id, _) = list_entry.as_legacy_is_reach_instance().unwrap();
        Self {
            id: *id,
            i_e: Some(false),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::DefaultMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_legacy_is_reach_instance().unwrap();
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::DelayMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_legacy_is_reach_instance().unwrap();
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::ExpenseMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_legacy_is_reach_instance().unwrap();
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::ErrorMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_legacy_is_reach_instance().unwrap();
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::Neighbor<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
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
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (neighbor, _) = list_entry.as_ext_is_reach().unwrap();
        Self {
            neighbor_id: neighbor.to_yang(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::Instance<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, entries) = list_entry.as_ext_is_reach().unwrap();
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| ListEntry::ExtIsReachInstance(id as u32, entry));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (id, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        Self {
            id: *id,
            metric: Some(reach.metric),
            admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
            te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
        Some(Self {
            local_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
        Some(Self {
            remote_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let unreserved_bw = reach.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter().map(|(prio, bw)| ListEntry::IsReachUnreservedBw(prio, bw));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (priority, unreserved_bandwidth) = list_entry.as_is_reach_unreserved_bw().unwrap();
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(unreserved_bandwidth),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let link_msd = &reach.sub_tlvs.link_msd.as_ref()?;
        let iter = link_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_ext_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.adj_sids.iter().map(ListEntry::AdjSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_adj_sid_stlv().unwrap();
        Self {
            weight: Some(stlv.weight),
            neighbor_id: stlv.nbr_system_id.as_ref().map(|system_id| system_id.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_adj_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv4_internal_reach().map(ListEntry::Ipv4Reach);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Self {
            ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
            prefix_len: Some(reach.prefix.prefix()),
            i_e: Some(reach.ie_bit),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::DefaultMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::DelayMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::ExpenseMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::ErrorMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv4_external_reach().map(ListEntry::Ipv4Reach);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Self {
            ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
            prefix_len: Some(reach.prefix.prefix()),
            i_e: Some(reach.ie_bit),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::DefaultMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::DelayMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::ExpenseMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::ErrorMetric {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let reach = list_entry.as_ipv4_reach().unwrap();
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.ext_ipv4_reach().map(ListEntry::ExtIpv4Reach);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let reach = list_entry.as_ext_ipv4_reach().unwrap();
        Self {
            up_down: Some(reach.up_down),
            ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::X),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let reach = list_entry.as_ext_ipv4_reach().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let reach = list_entry.as_ext_ipv4_reach().unwrap();
        let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::Neighbor<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
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
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (mt_id, neighbor, _) = list_entry.as_mt_is_reach().unwrap();
        Self {
            mt_id: Some(*mt_id),
            neighbor_id: Some(neighbor.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::Instance<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, _, entries) = list_entry.as_mt_is_reach().unwrap();
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| ListEntry::MtIsReachInstance(id as u32, entry));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (id, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        Self {
            id: *id,
            metric: Some(reach.metric),
            admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
            te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
        Some(Self {
            local_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get()).map(Cow::Borrowed);
        Some(Self {
            remote_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let unreserved_bw = reach.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter().map(|(prio, bw)| ListEntry::IsReachUnreservedBw(prio, bw));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (priority, unreserved_bandwidth) = list_entry.as_is_reach_unreserved_bw().unwrap();
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(unreserved_bandwidth),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let link_msd = reach.sub_tlvs.link_msd.as_ref()?;
        let iter = link_msd.get().iter().map(|(msd_type, msd_value)| ListEntry::Msd(*msd_type, *msd_value));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (msd_type, msd_value) = list_entry.as_msd().unwrap();
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_is_reach_instance().unwrap();
        let iter = reach.sub_tlvs.adj_sids.iter().map(ListEntry::AdjSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_adj_sid_stlv().unwrap();
        Self {
            weight: Some(stlv.weight),
            neighbor_id: stlv.nbr_system_id.as_ref().map(|system_id| system_id.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_adj_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_ipv4_reach().map(|(mt_id, entry)| ListEntry::MtIpv4Reach(mt_id, entry));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (mt_id, reach) = list_entry.as_mt_ipv4_reach().unwrap();
        Self {
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
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_ipv4_reach().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_ipv4_reach().unwrap();
        let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_ipv6_reach().map(|(mt_id, entry)| ListEntry::MtIpv6Reach(mt_id, entry));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (mt_id, reach) = list_entry.as_mt_ipv6_reach().unwrap();
        Self {
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
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_ipv6_reach().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, reach) = list_entry.as_mt_ipv6_reach().unwrap();
        let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::Prefixes<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv6_reach().map(ListEntry::Ipv6Reach);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let reach = list_entry.as_ipv6_reach().unwrap();
        Self {
            up_down: Some(reach.up_down),
            ip_prefix: Some(Cow::Owned(reach.prefix.ip())),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: Some(reach.external),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| Cow::Borrowed(tlv.get())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let reach = list_entry.as_ipv6_reach().unwrap();
        let iter = reach.sub_tlvs.unknown.iter().map(ListEntry::UnknownTlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let tlv = list_entry.as_unknown_tlv().unwrap();
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(tlv.value.as_ref()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let reach = list_entry.as_ipv6_reach().unwrap();
        let iter = reach.sub_tlvs.prefix_sids.values().map(ListEntry::PrefixSidStlv);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let stlv = list_entry.as_prefix_sid_stlv().unwrap();
        let iter = stlv.flags.to_yang_bits().into_iter().map(Cow::Borrowed);
        Some(Self {
            flag: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::purge_originator_identification::PurgeOriginatorIdentification<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        Some(Self {
            originator: lsp.tlvs.purge_originator_id.as_ref().map(|tlv| tlv.system_id.to_yang()),
            received_from: lsp.tlvs.purge_originator_id.as_ref().and_then(|tlv| tlv.system_id_rcvd.map(|system_id| system_id.to_yang())),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::MtCapability {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let lse = list_entry.as_lsp_entry().unwrap();
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_cap.iter().map(ListEntry::MtCap);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let mt_cap = list_entry.as_mt_cap().unwrap();
        Self {
            mt_id: Some(mt_cap.mt_id),
            overload: Some(mt_cap.overload),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::spbm_service::SpbmService<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let mt_cap = list_entry.as_mt_cap().unwrap();
        let iter = mt_cap.sub_tlvs.spbm_si.iter().map(ListEntry::SpbmService);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let spbm_si = list_entry.as_spbm_service().unwrap();
        Self {
            bmac: Some(Cow::Owned(MacAddr::from(spbm_si.bmac).to_string())),
            base_vid: Some(spbm_si.base_vid),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::spbm_service::isid::Isid {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let spbm_si = list_entry.as_spbm_service().unwrap();
        let iter = spbm_si.isid_entries.iter().map(ListEntry::SpbmIsid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let isid = list_entry.as_spbm_isid().unwrap();
        Self {
            value: Some(isid.isid),
            transmit: Some(isid.flags.contains(IsidFlags::T)),
            receive: Some(isid.flags.contains(IsidFlags::R)),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::fingerprint::Fingerprint {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (_, lsdb) = list_entry.as_lsdb().unwrap();
        Some(Self {
            value: Some(lsdb.fingerprint()),
            last_update: lsdb.fingerprint_last_update().map(|time| time.elapsed().as_secs() as u32),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance> for isis::local_rib::route::Route<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let rib = instance.state.as_ref()?.rib(instance.config.level_type);
        let iter = rib.iter().map(|(destination, route)| ListEntry::Route(destination, route));
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (prefix, route) = list_entry.as_route().unwrap();
        Self {
            prefix: Cow::Borrowed(prefix),
            metric: Some(route.metric),
            level: Some(route.level as u8),
            route_tag: route.tag,
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::local_rib::route::next_hops::next_hop::NextHop<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let (_, route) = list_entry.as_route().unwrap();
        let iter = route.nexthops.values().map(ListEntry::Nexthop);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let nexthop = list_entry.as_nexthop().unwrap();
        let iface = &instance.arenas.interfaces[nexthop.iface_idx];
        Self {
            next_hop: Cow::Borrowed(&nexthop.addr),
            outgoing_interface: Some(Cow::Borrowed(iface.name.as_str())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::system_counters::level::Level {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = instance.config.levels().map(ListEntry::SystemCounters);
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let level = list_entry.as_system_counters().unwrap();
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
        Self {
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
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::Interface<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = instance.arenas.interfaces.iter().map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        let state = if iface.state.active { "up" } else { "down" };
        Self {
            name: Cow::Borrowed(&iface.name),
            discontinuity_time: Some(Cow::Borrowed(&iface.state.discontinuity_time)).ignore_in_testing(),
            state: Some(Cow::Borrowed(state)),
            circuit_id: Some(iface.state.circuit_id).ignore_in_testing(),
            extended_circuit_id: iface.system.ifindex.ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::adjacencies::adjacency::Adjacency<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.adjacencies(&instance.arenas.adjacencies).map(ListEntry::Adjacency);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let adj = list_entry.as_adjacency().unwrap();
        let area_addresses = adj.area_addrs.iter().map(|area| area.to_yang());
        let ipv4_addresses = adj.ipv4_addrs.iter().map(Cow::Borrowed);
        let ipv6_addresses = adj.ipv6_addrs.iter().map(Cow::Borrowed);
        let protocol_supported = adj.protocols_supported.iter().copied();
        let topologies = adj.topologies.iter().copied();
        Self {
            neighbor_sys_type: Some(adj.level_capability.to_yang()),
            neighbor_sysid: Some(adj.system_id.to_yang()),
            neighbor_extended_circuit_id: adj.ext_circuit_id.ignore_in_testing(),
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
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::adjacencies::adjacency::adjacency_sid::AdjacencySid<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let adj = list_entry.as_adjacency().unwrap();
        let iter = adj.adj_sids.iter().map(ListEntry::AdjacencySid);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let adj_sid = list_entry.as_adjacency_sid().unwrap();
        Self {
            value: Some(adj_sid.label.get()),
            address_family: Some(adj_sid.af.to_yang()),
            weight: Some(0),
            protection_requested: Some(false),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::event_counters::EventCounters {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        Some(Self {
            adjacency_changes: Some(iface.state.event_counters.adjacency_changes),
            adjacency_number: Some(iface.state.event_counters.adjacency_number),
            init_fails: Some(iface.state.event_counters.init_fails),
            adjacency_rejects: Some(iface.state.event_counters.adjacency_rejects),
            id_len_mismatch: Some(iface.state.event_counters.id_len_mismatch),
            max_area_addresses_mismatch: Some(iface.state.event_counters.max_area_addr_mismatch),
            authentication_type_fails: Some(iface.state.event_counters.auth_type_fails),
            authentication_fails: Some(iface.state.event_counters.auth_fails),
            lan_dis_changes: Some(iface.state.event_counters.lan_dis_changes),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::packet_counters::level::Level {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = iface.config.levels().map(|level| ListEntry::InterfacePacketCounters(iface, level));
        Some(Box::new(iter) as _).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (_, level) = list_entry.as_interface_packet_counters().unwrap();
        Self {
            level: *level as u8,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::iih::Iih {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (iface, level) = list_entry.as_interface_packet_counters().unwrap();
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.iih_in),
            out: Some(packet_counters.iih_out.load(atomic::Ordering::Relaxed)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::lsp::Lsp {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (iface, level) = list_entry.as_interface_packet_counters().unwrap();
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.lsp_in),
            out: Some(packet_counters.lsp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::psnp::Psnp {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (iface, level) = list_entry.as_interface_packet_counters().unwrap();
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.psnp_in),
            out: Some(packet_counters.psnp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::csnp::Csnp {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (iface, level) = list_entry.as_interface_packet_counters().unwrap();
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.csnp_in),
            out: Some(packet_counters.csnp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::unknown::Unknown {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let (iface, level) = list_entry.as_interface_packet_counters().unwrap();
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.unknown_in),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::srm::level::Level<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = LevelType::All.into_iter().filter(|level| !iface.state.srm_list.get(*level).is_empty()).map(|level| ListEntry::InterfaceSrmList(iface, level));
        Some(Box::new(iter) as _).only_in_testing()
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (iface, level) = list_entry.as_interface_srm_list().unwrap();
        Self {
            level: *level as u8,
            lsp_id: Some(Box::new(iface.state.srm_list.get(*level).keys().map(|lsp_id| lsp_id.to_yang()))),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::ssn::level::Level<'a> {
    fn iter(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = LevelType::All.into_iter().filter(|level| !iface.state.ssn_list.get(*level).is_empty()).map(|level| ListEntry::InterfaceSsnList(iface, level));
        Some(Box::new(iter) as _).only_in_testing()
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let (iface, level) = list_entry.as_interface_ssn_list().unwrap();
        Self {
            level: *level as u8,
            lsp_id: Some(Box::new(iface.state.ssn_list.get(*level).keys().map(|lsp_id| lsp_id.to_yang()))),
        }
    }
}

// ===== helper functions =====

fn format_hmac_digest(digest: &[u8]) -> String {
    digest.iter().fold(String::with_capacity(digest.len() * 2), |mut output, &byte| {
        write!(&mut output, "{byte:02x}").unwrap();
        output
    })
}
