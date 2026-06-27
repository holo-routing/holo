//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic;
use std::time::Instant;

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::mac_addr::MacAddr;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_yang::types::{HexStr, HexString, TimerValueMillis, TimerValueSecs16, Timeticks};
use holo_yang::{ToYang, ToYangFlags};
use ipnetwork::IpNetwork;
use num_traits::FromPrimitive;

use crate::adjacency::{Adjacency, AdjacencySid};
use crate::collections::Lsdb;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::lsdb::{LspEntry, LspLogEntry, LspLogId};
use crate::northbound::yang_gen::{self, isis};
use crate::packet::iana::{IgpAlgoType, IgpMetricType};
use crate::packet::subtlvs::capability::{FadStlv, FapmStlv, LabelBlockEntry};
use crate::packet::subtlvs::neighbor::{AdjSidStlv, AslaStlv};
use crate::packet::subtlvs::prefix::{PrefixAttrFlags, PrefixSidStlv};
use crate::packet::subtlvs::spb::{IsidEntry, IsidFlags, SpbmSiStlv};
use crate::packet::tlv::{AuthenticationTlv, IpReachTlvEntry, Ipv4Reach, Ipv6Reach, IsReach, LegacyIpv4Reach, LegacyIsReach, MtCapabilityTlv, MultiTopologyEntry, RouterCapTlv, UnknownTlv};
use crate::packet::{LanId, LevelNumber, LevelType, SystemId};
use crate::route::{Nexthop, Route};
use crate::spf::{SpfLogEntry, SpfScheduler};

impl Provider for Instance {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!("/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-isis:isis", Protocol::ISIS.to_yang(), self.name)
    }
}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for isis::Isis {
    type ParentListEntry = ();

    fn new(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: instance.state.as_ref().map(|state| state.discontinuity_time).ignore_in_testing(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_control::ietf_spf_delay::level::Level<'a> {
    type ParentListEntry = ();
    type ListEntry = (LevelNumber, &'a SpfScheduler);

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let spf_sched = &instance.state.as_ref()?.spf_sched;
        let iter = instance.config.levels().map(|level| (level, spf_sched.get(level)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (level, spf_sched): &Self::ListEntry) -> Self {
        Self {
            level: *level as u8,
            current_state: Some(spf_sched.delay_state.to_yang()),
            remaining_time_to_learn: spf_sched.learn_timer.as_ref().map(|task| TimerValueMillis(task.remaining())).ignore_in_testing(),
            remaining_hold_down: spf_sched.hold_down_timer.as_ref().map(|task| TimerValueMillis(task.remaining())).ignore_in_testing(),
            last_event_received: spf_sched.last_event_rcvd.map(Timeticks).ignore_in_testing(),
            next_spf_time: spf_sched.delay_timer.as_ref().map(|timer| Timeticks(Instant::now() + timer.remaining())).ignore_in_testing(),
            last_spf_time: spf_sched.last_time.map(Timeticks).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_log::event::Event<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a SpfLogEntry;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let spf_log = &instance.state.as_ref()?.spf_log;
        let iter = spf_log.iter();
        Some(iter).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, log: &Self::ListEntry) -> Self {
        Self {
            id: log.id,
            spf_type: Some(log.spf_type.to_yang()),
            level: Some(log.level as u8),
            schedule_timestamp: log.schedule_time.map(Timeticks),
            start_timestamp: Some(Timeticks(log.start_time)),
            end_timestamp: Some(Timeticks(log.end_time)),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::spf_log::event::trigger_lsp::TriggerLsp {
    type ParentListEntry = &'a SpfLogEntry;
    type ListEntry = &'a LspLogId;

    fn iter(_instance: &'a Instance, log: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = log.trigger_lsps.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, lsp: &Self::ListEntry) -> Self {
        Self {
            lsp: lsp.lsp_id,
            sequence: Some(lsp.seqno),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::lsp_log::event::Event<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a LspLogEntry;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp_log = &instance.state.as_ref()?.lsp_log;
        let iter = lsp_log.iter();
        Some(iter).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, log: &Self::ListEntry) -> Self {
        Self {
            id: log.id,
            level: Some(log.level as u8),
            received_timestamp: log.rcvd_time.map(Timeticks).ignore_in_testing(),
            reason: Some(log.reason.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::lsp_log::event::lsp::Lsp {
    type ParentListEntry = &'a LspLogEntry;

    fn new(_instance: &'a Instance, log: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            lsp: Some(log.lsp.lsp_id),
            sequence: Some(log.lsp.seqno),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::hostnames::hostname::Hostname<'a> {
    type ParentListEntry = ();
    type ListEntry = (SystemId, &'a String);

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let hostnames = &instance.state.as_ref()?.hostnames;
        let iter = hostnames.iter().map(|(system_id, hostname)| (*system_id, hostname));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (system_id, hostname): &Self::ListEntry) -> Self {
        Self {
            system_id: *system_id,
            hostname: Some(Cow::Borrowed(hostname)),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::Levels {
    type ParentListEntry = ();
    type ListEntry = (LevelNumber, &'a Lsdb);

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = instance.config.levels().map(|level| (level, lsdb.get(level)));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (level, lsdb): &Self::ListEntry) -> Self {
        Self {
            level: *level as u8,
            lsp_count: Some(lsdb.lsp_count()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::Lsp<'a> {
    type ParentListEntry = (LevelNumber, &'a Lsdb);
    type ListEntry = &'a LspEntry;

    fn iter(instance: &'a Instance, (_, lsdb): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = lsdb.iter(&instance.arenas.lsp_entries);
        Some(iter)
    }

    fn new(_instance: &'a Instance, lse: &Self::ListEntry) -> Self {
        let lsp = &lse.data;
        let remaining_lifetime = lsp.rem_lifetime();
        let ipv4_addresses = lsp.tlvs.ipv4_addrs().copied();
        let ipv6_addresses = lsp.tlvs.ipv6_addrs().copied();
        let protocol_supported = lsp.tlvs.protocols_supported();
        let area_addresses = lsp.tlvs.area_addrs().map(Cow::Borrowed);
        Self {
            lsp_id: lsp.lsp_id,
            decoded_completed: None,
            raw_data: Some(HexStr(lsp.raw.as_ref())).ignore_in_testing(),
            checksum: Some(lsp.cksum).ignore_in_testing(),
            remaining_lifetime: Some(remaining_lifetime).ignore_in_testing_if(remaining_lifetime != 0),
            sequence: Some(lsp.seqno).ignore_in_testing_if(lsp.seqno != 0),
            ipv4_addresses: Some(Box::new(ipv4_addresses)),
            ipv6_addresses: Some(Box::new(ipv6_addresses)),
            ipv4_te_routerid: lsp.tlvs.ipv4_router_id.as_ref().map(|tlv| tlv.get()),
            ipv6_te_routerid: lsp.tlvs.ipv6_router_id.as_ref().map(|tlv| tlv.get()),
            protocol_supported: Some(Box::new(protocol_supported)),
            dynamic_hostname: lsp.tlvs.hostname().map(Cow::Borrowed),
            area_addresses: Some(Box::new(area_addresses)),
            lsp_buffer_size: lsp.tlvs.lsp_buf_size(),
            received_remaining_lifetime: lsp.rcvd_rem_lifetime.ignore_in_testing_if(lsp.rcvd_rem_lifetime != Some(0)),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::attributes::Attributes<'a> {
    type ParentListEntry = &'a LspEntry;

    fn new(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsp = &lse.data;
        Some(Self {
            lsp_flags: lsp.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::authentication::Authentication<'a> {
    type ParentListEntry = &'a LspEntry;

    fn new(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a MultiTopologyEntry;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.multi_topology();
        Some(iter)
    }

    fn new(_instance: &'a Instance, mt: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(mt.mt_id),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_entries::topology::attributes::Attributes<'a> {
    type ParentListEntry = &'a MultiTopologyEntry;

    fn new(_instance: &'a Instance, mt: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flags: mt.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::RouterCapability {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a RouterCapTlv;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.router_cap.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, router_cap: &Self::ListEntry) -> Self {
        Self {
            flooding_algorithm: router_cap.sub_tlvs.flooding_algo.as_ref().map(|stlv| stlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::flags::Flags<'a> {
    type ParentListEntry = &'a RouterCapTlv;

    fn new(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            router_capability_flags: router_cap.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::node_tags::node_tag::NodeTag {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = router_cap.sub_tlvs.node_tags.iter().flat_map(|stlv| stlv.get().iter().copied());
        Some(iter)
    }

    fn new(_instance: &'a Instance, node_tag: &Self::ListEntry) -> Self {
        Self {
            tag: Some(*node_tag),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = router_cap.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::node_msd_tlv::node_msds::NodeMsds {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let node_msd = router_cap.sub_tlvs.node_msd.as_ref()?;
        let iter = node_msd.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::SrCapability<'a> {
    type ParentListEntry = &'a RouterCapTlv;

    fn new(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<Self> {
        let sr_cap = &router_cap.sub_tlvs.sr_cap.as_ref()?;
        Some(Self {
            sr_capability_flag: sr_cap.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_capability::global_blocks::global_block::GlobalBlock {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = &'a LabelBlockEntry;

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let sr_cap = &router_cap.sub_tlvs.sr_cap.as_ref()?;
        let iter = sr_cap.srgb_entries.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, label_block: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(label_block.range),
            label_value: label_block.first.as_label().map(|label| label.get()),
            index_value: label_block.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::sr_algorithms::SrAlgorithms<'a> {
    type ParentListEntry = &'a RouterCapTlv;

    fn new(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<Self> {
        let sr_algo = &router_cap.sub_tlvs.sr_algo.as_ref()?;
        let iter = sr_algo.get().iter().map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::local_blocks::local_block::LocalBlock {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = &'a LabelBlockEntry;

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let srlb = router_cap.sub_tlvs.srlb.as_ref()?;
        let iter = srlb.entries.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, label_block: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(label_block.range),
            label_value: label_block.first.as_label().map(|label| label.get()),
            index_value: label_block.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::FadTlv<'a> {
    type ParentListEntry = &'a RouterCapTlv;
    type ListEntry = &'a FadStlv;

    fn iter(_instance: &'a Instance, router_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = router_cap.sub_tlvs.fad.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, fad: &Self::ListEntry) -> Self {
        Self {
            algo_number: Some(fad.flex_algo),
            metric_type: IgpMetricType::from_u8(fad.metric_type).map(|t| t.to_yang()),
            calc_type: IgpAlgoType::from_u8(fad.calc_type).map(|t| t.to_yang()),
            priority: Some(fad.priority),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::fa_ex_ag_sub_tlv::FaExAgSubTlv<'a> {
    type ParentListEntry = &'a FadStlv;

    fn new(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<Self> {
        let stlv = fad.sub_tlvs.exclude_admin_group.as_ref()?;
        let iter = stlv.get().chunks(4).map(HexStr);
        Some(Self {
            extended_admin_group: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::fa_in_any_ag_sub_tlv::FaInAnyAgSubTlv<'a> {
    type ParentListEntry = &'a FadStlv;

    fn new(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<Self> {
        let stlv = fad.sub_tlvs.include_any_admin_group.as_ref()?;
        let iter = stlv.get().chunks(4).map(HexStr);
        Some(Self {
            extended_admin_group: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::fa_in_all_ag_sub_tlv::FaInAllAgSubTlv<'a> {
    type ParentListEntry = &'a FadStlv;

    fn new(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<Self> {
        let stlv = fad.sub_tlvs.include_all_admin_group.as_ref()?;
        let iter = stlv.get().chunks(4).map(HexStr);
        Some(Self {
            extended_admin_group: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::fad_flags_sub_tlv::FadFlagsSubTlv<'a> {
    type ParentListEntry = &'a FadStlv;

    fn new(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<Self> {
        let stlv = fad.sub_tlvs.flags.as_ref()?;
        Some(Self {
            fad_flags: stlv.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::fa_ex_srlg_sub_tlv::FaExSrlgSubTlv<'a> {
    type ParentListEntry = &'a FadStlv;

    fn new(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<Self> {
        let stlv = fad.sub_tlvs.exclude_srlgs.as_ref()?;
        let iter = stlv.get().iter().copied();
        Some(Self {
            srlgs: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::router_capabilities::router_capability::fad_tlvs::fad_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a FadStlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, fad: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = fad.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::Neighbor {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = (LanId, Vec<&'a LegacyIsReach>);

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp
            .tlvs
            .is_reach()
            .fold(BTreeMap::<LanId, Vec<_>>::new(), |mut entries, reach| {
                let list_key = reach.neighbor;
                entries.entry(list_key).or_default().push(reach);
                entries
            })
            .into_iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (neighbor, _): &Self::ListEntry) -> Self {
        Self {
            neighbor_id: *neighbor,
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::Instance {
    type ParentListEntry = (LanId, Vec<&'a LegacyIsReach>);
    type ListEntry = (u32, &'a LegacyIsReach);

    fn iter(_instance: &'a Instance, (_, entries): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| (id as u32, entry));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (id, _): &Self::ListEntry) -> Self {
        Self {
            id: *id,
            i_e: Some(false),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::default_metric::DefaultMetric {
    type ParentListEntry = (u32, &'a LegacyIsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::delay_metric::DelayMetric {
    type ParentListEntry = (u32, &'a LegacyIsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::expense_metric::ExpenseMetric {
    type ParentListEntry = (u32, &'a LegacyIsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::is_neighbor::neighbor::instances::instance::error_metric::ErrorMetric {
    type ParentListEntry = (u32, &'a LegacyIsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::Neighbor {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = (LanId, Vec<&'a IsReach>);

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp
            .tlvs
            .ext_is_reach()
            .fold(BTreeMap::<LanId, Vec<_>>::new(), |mut entries, reach| {
                let list_key = reach.neighbor;
                entries.entry(list_key).or_default().push(reach);
                entries
            })
            .into_iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (neighbor, _): &Self::ListEntry) -> Self {
        Self {
            neighbor_id: *neighbor,
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::Instance<'a> {
    type ParentListEntry = (LanId, Vec<&'a IsReach>);
    type ListEntry = (u32, &'a IsReach);

    fn iter(_instance: &'a Instance, (_, entries): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| (id as u32, entry));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (id, reach): &Self::ListEntry) -> Self {
        Self {
            id: *id,
            metric: Some(reach.metric),
            admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
            extended_admin_group: reach.sub_tlvs.ext_admin_group.as_ref().map(|tlv| HexStr(tlv.get())),
            te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get());
        Some(Self {
            local_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get());
        Some(Self {
            remote_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = (usize, f32);

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unreserved_bw = reach.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (priority, unreserved_bandwidth): &Self::ListEntry) -> Self {
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(*unreserved_bandwidth),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_delay::UnidirectionalLinkDelay {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            value: Some(stlv.delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::min_max_unidirectional_link_delay::MinMaxUnidirectionalLinkDelay {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_value: Some(stlv.min_delay),
            max_value: Some(stlv.max_delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::min_max_unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_max_unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_delay_variation::UnidirectionalLinkDelayVariation {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_delay_variation.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_loss::UnidirectionalLinkLoss {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            value: Some(stlv.loss),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_loss::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            unidirectional_link_loss_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_residual_bandwidth::UnidirectionalLinkResidualBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_resid_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_available_bandwidth::UnidirectionalLinkAvailableBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_avail_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unidirectional_link_utilized_bandwidth::UnidirectionalLinkUtilizedBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_util_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::AslaSubTlv<'a> {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a AslaStlv;

    fn iter(_provider: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.asla.iter();
        Some(iter)
    }

    fn new(_provider: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            l_flag: Some(stlv.l_flag),
            te_metric: stlv.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            admin_group: stlv.sub_tlvs.admin_group.as_ref().map(|tlv| HexString(tlv.get().to_be_bytes().to_vec())),
            extended_admin_group: stlv.sub_tlvs.ext_admin_group.as_ref().map(|tlv| HexStr(tlv.get())),
            max_bandwidth: stlv.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: stlv.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::sabm::Sabm<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_provider: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            sabm_bit: stlv.sabm.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth {
    type ParentListEntry = &'a AslaStlv;
    type ListEntry = (usize, f32);

    fn iter(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unreserved_bw = stlv.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (priority, unreserved_bandwidth): &Self::ListEntry) -> Self {
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(*unreserved_bandwidth),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay::UnidirectionalLinkDelay {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            value: Some(stlv.delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::min_max_unidirectional_link_delay::MinMaxUnidirectionalLinkDelay {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_value: Some(stlv.min_delay),
            max_value: Some(stlv.max_delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::min_max_unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_max_unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay_variation::UnidirectionalLinkDelayVariation {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_delay_variation.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_loss::UnidirectionalLinkLoss {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            value: Some(stlv.loss),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_loss::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            unidirectional_link_loss_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_residual_bandwidth::UnidirectionalLinkResidualBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_resid_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_available_bandwidth::UnidirectionalLinkAvailableBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_avail_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_utilized_bandwidth::UnidirectionalLinkUtilizedBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_util_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a AslaStlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_provider: &'a Instance, stlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = stlv.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_provider: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let link_msd = &reach.sub_tlvs.link_msd.as_ref()?;
        let iter = link_msd.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a AdjSidStlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.adj_sids.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            weight: Some(stlv.weight),
            neighbor_id: stlv.nbr_system_id,
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a> {
    type ParentListEntry = &'a AdjSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a LegacyIpv4Reach;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv4_internal_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, reach: &Self::ListEntry) -> Self {
        Self {
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            i_e: Some(reach.ie_bit),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::default_metric::DefaultMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::delay_metric::DelayMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::expense_metric::ExpenseMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_internal_reachability::prefixes::error_metric::ErrorMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a LegacyIpv4Reach;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv4_external_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, reach: &Self::ListEntry) -> Self {
        Self {
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            i_e: Some(reach.ie_bit),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::default_metric::DefaultMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: Some(reach.metric),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::delay_metric::DelayMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_delay,
            supported: Some(reach.metric_delay.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::expense_metric::ExpenseMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_expense,
            supported: Some(reach.metric_expense.is_some()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv4_external_reachability::prefixes::error_metric::ErrorMetric {
    type ParentListEntry = &'a LegacyIpv4Reach;

    fn new(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: reach.metric_error,
            supported: Some(reach.metric_error.is_some()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a Ipv4Reach;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.ext_ipv4_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, reach: &Self::ListEntry) -> Self {
        Self {
            up_down: Some(reach.up_down),
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::X),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| tlv.get()),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a Ipv4Reach;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    type ParentListEntry = &'a Ipv4Reach;
    type ListEntry = &'a PrefixSidStlv;

    fn iter(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    type ParentListEntry = &'a PrefixSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::extended_ipv4_reachability::prefixes::fapm_sub_tlvs::fapm_sub_tlv::FapmSubTlv {
    type ParentListEntry = &'a Ipv4Reach;
    type ListEntry = &'a FapmStlv;

    fn iter(_instance: &'a Instance, prefix: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = prefix.sub_tlvs.fapm.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, fapm: &Self::ListEntry) -> Self {
        Self {
            algo_number: Some(fapm.flex_algo),
            metric: Some(fapm.metric),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::Neighbor {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = (u16, LanId, Vec<&'a IsReach>);

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
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
            .map(|((mt_id, neighbor), entries)| (mt_id, neighbor, entries));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (mt_id, neighbor, _): &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(*mt_id),
            neighbor_id: Some(*neighbor),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::Instance<'a> {
    type ParentListEntry = (u16, LanId, Vec<&'a IsReach>);
    type ListEntry = (u32, &'a IsReach);

    fn iter(_instance: &'a Instance, (_, _, entries): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = entries.clone().into_iter().enumerate().map(|(id, entry)| (id as u32, entry));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (id, reach): &Self::ListEntry) -> Self {
        Self {
            id: *id,
            metric: Some(reach.metric),
            admin_group: reach.sub_tlvs.admin_group.as_ref().map(|tlv| tlv.get()),
            extended_admin_group: reach.sub_tlvs.ext_admin_group.as_ref().map(|tlv| HexStr(tlv.get())),
            te_metric: reach.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            max_bandwidth: reach.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: reach.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::local_if_ipv4_addrs::LocalIfIpv4Addrs<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let iter = reach.sub_tlvs.ipv4_interface_addr.iter().map(|tlv| tlv.get());
        Some(Self {
            local_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::remote_if_ipv4_addrs::RemoteIfIpv4Addrs<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let iter = reach.sub_tlvs.ipv4_neighbor_addr.iter().map(|tlv| tlv.get());
        Some(Self {
            remote_if_ipv4_addr: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = (usize, f32);

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unreserved_bw = reach.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (priority, unreserved_bandwidth): &Self::ListEntry) -> Self {
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(*unreserved_bandwidth),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_delay::UnidirectionalLinkDelay {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            value: Some(stlv.delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::min_max_unidirectional_link_delay::MinMaxUnidirectionalLinkDelay {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_value: Some(stlv.min_delay),
            max_value: Some(stlv.max_delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::min_max_unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_max_unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_delay_variation::UnidirectionalLinkDelayVariation {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_delay_variation.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_loss::UnidirectionalLinkLoss {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            value: Some(stlv.loss),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_loss::flags::Flags<'a> {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            unidirectional_link_loss_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_residual_bandwidth::UnidirectionalLinkResidualBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_resid_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_available_bandwidth::UnidirectionalLinkAvailableBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_avail_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unidirectional_link_utilized_bandwidth::UnidirectionalLinkUtilizedBandwidth {
    type ParentListEntry = (u32, &'a IsReach);

    fn new(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<Self> {
        let stlv = reach.sub_tlvs.uni_util_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::AslaSubTlv<'a> {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a AslaStlv;

    fn iter(_provider: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.asla.iter();
        Some(iter)
    }

    fn new(_provider: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            l_flag: Some(stlv.l_flag),
            te_metric: stlv.sub_tlvs.te_default_metric.as_ref().map(|tlv| tlv.get()),
            admin_group: stlv.sub_tlvs.admin_group.as_ref().map(|tlv| HexString(tlv.get().to_be_bytes().to_vec())),
            extended_admin_group: stlv.sub_tlvs.ext_admin_group.as_ref().map(|tlv| HexStr(tlv.get())),
            max_bandwidth: stlv.sub_tlvs.max_link_bw.as_ref().map(|tlv| tlv.get()),
            max_reservable_bandwidth: stlv.sub_tlvs.max_resv_link_bw.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::sabm::Sabm<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_provider: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            sabm_bit: stlv.sabm.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unreserved_bandwidths::unreserved_bandwidth::UnreservedBandwidth {
    type ParentListEntry = &'a AslaStlv;
    type ListEntry = (usize, f32);

    fn iter(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let unreserved_bw = stlv.sub_tlvs.unreserved_bw.as_ref()?;
        let iter = unreserved_bw.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (priority, unreserved_bandwidth): &Self::ListEntry) -> Self {
        Self {
            priority: Some(*priority as u8),
            unreserved_bandwidth: Some(*unreserved_bandwidth),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay::UnidirectionalLinkDelay {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            value: Some(stlv.delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_delay.as_ref()?;
        Some(Self {
            unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::min_max_unidirectional_link_delay::MinMaxUnidirectionalLinkDelay {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_value: Some(stlv.min_delay),
            max_value: Some(stlv.max_delay),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::min_max_unidirectional_link_delay::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.min_max_uni_link_delay.as_ref()?;
        Some(Self {
            min_max_unidirectional_link_delay_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_delay_variation::UnidirectionalLinkDelayVariation {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_delay_variation.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_loss::UnidirectionalLinkLoss {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            value: Some(stlv.loss),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_loss::flags::Flags<'a> {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_link_loss.as_ref()?;
        Some(Self {
            unidirectional_link_loss_subtlv_flags: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_residual_bandwidth::UnidirectionalLinkResidualBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_resid_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_available_bandwidth::UnidirectionalLinkAvailableBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_avail_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unidirectional_link_utilized_bandwidth::UnidirectionalLinkUtilizedBandwidth {
    type ParentListEntry = &'a AslaStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        let stlv = stlv.sub_tlvs.uni_util_bw.as_ref()?;
        Some(Self {
            value: Some(stlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::asla_sub_tlvs::asla_sub_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a AslaStlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_provider: &'a Instance, stlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = stlv.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_provider: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::link_msd_sub_tlv::link_msds::LinkMsds {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let link_msd = reach.sub_tlvs.link_msd.as_ref()?;
        let iter = link_msd.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: *msd_type,
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    type ParentListEntry = (u32, &'a IsReach);
    type ListEntry = &'a AdjSidStlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.adj_sids.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            weight: Some(stlv.weight),
            neighbor_id: stlv.nbr_system_id,
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_is_neighbor::neighbor::instances::instance::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a> {
    type ParentListEntry = &'a AdjSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = (u16, &'a Ipv4Reach);

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_ipv4_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (mt_id, reach): &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(*mt_id),
            up_down: Some(reach.up_down),
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::X),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| tlv.get()),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = (u16, &'a Ipv4Reach);
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    type ParentListEntry = (u16, &'a Ipv4Reach);
    type ListEntry = &'a PrefixSidStlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    type ParentListEntry = &'a PrefixSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_extended_ipv4_reachability::prefixes::fapm_sub_tlvs::fapm_sub_tlv::FapmSubTlv {
    type ParentListEntry = (u16, &'a Ipv4Reach);
    type ListEntry = &'a FapmStlv;

    fn iter(_instance: &'a Instance, (_mt_id, prefix): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = prefix.sub_tlvs.fapm.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, fapm: &Self::ListEntry) -> Self {
        Self {
            algo_number: Some(fapm.flex_algo),
            metric: Some(fapm.metric),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = (u16, &'a Ipv6Reach);

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_ipv6_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, (mt_id, reach): &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(*mt_id),
            up_down: Some(reach.up_down),
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: Some(reach.external),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| tlv.get()),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = (u16, &'a Ipv6Reach);
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    type ParentListEntry = (u16, &'a Ipv6Reach);
    type ListEntry = &'a PrefixSidStlv;

    fn iter(_instance: &'a Instance, (_, reach): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    type ParentListEntry = &'a PrefixSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_ipv6_reachability::prefixes::fapm_sub_tlvs::fapm_sub_tlv::FapmSubTlv {
    type ParentListEntry = (u16, &'a Ipv6Reach);
    type ListEntry = &'a FapmStlv;

    fn iter(_instance: &'a Instance, (_mt_id, prefix): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = prefix.sub_tlvs.fapm.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, fapm: &Self::ListEntry) -> Self {
        Self {
            algo_number: Some(fapm.flex_algo),
            metric: Some(fapm.metric),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::Prefixes {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a Ipv6Reach;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.ipv6_reach();
        Some(iter)
    }

    fn new(_instance: &'a Instance, reach: &Self::ListEntry) -> Self {
        Self {
            up_down: Some(reach.up_down),
            ip_prefix: Some(reach.prefix.ip()),
            prefix_len: Some(reach.prefix.prefix()),
            metric: Some(reach.metric),
            external_prefix_flag: Some(reach.external),
            node_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::N),
            readvertisement_flag: reach.prefix_attr_flags_get(PrefixAttrFlags::R),
            ipv4_source_router_id: reach.sub_tlvs.ipv4_source_rid.as_ref().map(|tlv| tlv.get()),
            ipv6_source_router_id: reach.sub_tlvs.ipv6_source_rid.as_ref().map(|tlv| tlv.get()),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a Ipv6Reach;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.unknown.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type as u16),
            length: Some(tlv.length as u16),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    type ParentListEntry = &'a Ipv6Reach;
    type ListEntry = &'a PrefixSidStlv;

    fn iter(_instance: &'a Instance, reach: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = reach.sub_tlvs.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a> {
    type ParentListEntry = &'a PrefixSidStlv;

    fn new(_instance: &'a Instance, stlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: stlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::ipv6_reachability::prefixes::fapm_sub_tlvs::fapm_sub_tlv::FapmSubTlv {
    type ParentListEntry = &'a Ipv6Reach;
    type ListEntry = &'a FapmStlv;

    fn iter(_instance: &'a Instance, prefix: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = prefix.sub_tlvs.fapm.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance, fapm: &Self::ListEntry) -> Self {
        Self {
            algo_number: Some(fapm.flex_algo),
            metric: Some(fapm.metric),
        }
    }
}
impl<'a> YangContainer<'a, Instance> for isis::database::levels::lsp::purge_originator_identification::PurgeOriginatorIdentification {
    type ParentListEntry = &'a LspEntry;

    fn new(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsp = &lse.data;
        Some(Self {
            originator: lsp.tlvs.purge_originator_id.as_ref().map(|tlv| tlv.system_id),
            received_from: lsp.tlvs.purge_originator_id.as_ref().and_then(|tlv| tlv.system_id_rcvd),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::MtCapability {
    type ParentListEntry = &'a LspEntry;
    type ListEntry = &'a MtCapabilityTlv;

    fn iter(_instance: &'a Instance, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsp = &lse.data;
        let iter = lsp.tlvs.mt_cap.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, mt_cap: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(mt_cap.mt_id),
            overload: Some(mt_cap.overload),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::spbm_service::SpbmService<'a> {
    type ParentListEntry = &'a MtCapabilityTlv;
    type ListEntry = &'a SpbmSiStlv;

    fn iter(_instance: &'a Instance, mt_cap: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = mt_cap.sub_tlvs.spbm_si.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, spbm_si: &Self::ListEntry) -> Self {
        Self {
            bmac: Some(Cow::Owned(MacAddr::from(spbm_si.bmac).to_string())),
            base_vid: Some(spbm_si.base_vid),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::database::levels::lsp::mt_capability::spbm_service::isid::Isid {
    type ParentListEntry = &'a SpbmSiStlv;
    type ListEntry = &'a IsidEntry;

    fn iter(_instance: &'a Instance, spbm_si: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = spbm_si.isid_entries.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, isid: &Self::ListEntry) -> Self {
        Self {
            value: Some(isid.isid),
            transmit: Some(isid.flags.contains(IsidFlags::T)),
            receive: Some(isid.flags.contains(IsidFlags::R)),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::database::levels::fingerprint::Fingerprint {
    type ParentListEntry = (LevelNumber, &'a Lsdb);

    fn new(_instance: &'a Instance, (_, lsdb): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            value: Some(lsdb.fingerprint()),
            last_update: lsdb.fingerprint_last_update().map(|time| time.elapsed().as_secs() as u32),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangList<'a, Instance> for isis::local_rib::route::Route {
    type ParentListEntry = ();
    type ListEntry = (IpNetwork, &'a Route);

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = instance.state.as_ref()?.rib(instance.config.level_type);
        let iter = rib.iter().map(|(destination, route)| (*destination, route));
        Some(iter)
    }

    fn new(_instance: &'a Instance, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: *prefix,
            metric: Some(route.metric),
            level: Some(route.level as u8),
            route_tag: route.tag,
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::local_rib::route::next_hops::next_hop::NextHop<'a> {
    type ParentListEntry = (IpNetwork, &'a Route);
    type ListEntry = &'a Nexthop;

    fn iter(_instance: &'a Instance, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = route.nexthops.values();
        Some(iter)
    }

    fn new(instance: &'a Instance, nexthop: &Self::ListEntry) -> Self {
        let iface = &instance.arenas.interfaces[nexthop.iface_idx];
        Self {
            next_hop: nexthop.addr,
            outgoing_interface: Some(Cow::Borrowed(iface.name.as_str())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::system_counters::level::Level {
    type ParentListEntry = ();
    type ListEntry = LevelNumber;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.config.levels();
        Some(iter).ignore_in_testing()
    }

    fn new(instance: &'a Instance, level: &Self::ListEntry) -> Self {
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
    type ParentListEntry = ();
    type ListEntry = &'a Interface;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.arenas.interfaces.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, iface: &Self::ListEntry) -> Self {
        let state = if iface.state.active { "up" } else { "down" };
        Self {
            name: Cow::Borrowed(&iface.name),
            discontinuity_time: Some(iface.state.discontinuity_time).ignore_in_testing(),
            state: Some(Cow::Borrowed(state)),
            circuit_id: Some(iface.state.circuit_id).ignore_in_testing(),
            extended_circuit_id: iface.system.ifindex.ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::adjacencies::adjacency::Adjacency<'a> {
    type ParentListEntry = &'a Interface;
    type ListEntry = &'a Adjacency;

    fn iter(instance: &'a Instance, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.adjacencies(&instance.arenas.adjacencies);
        Some(iter)
    }

    fn new(_instance: &'a Instance, adj: &Self::ListEntry) -> Self {
        let area_addresses = adj.area_addrs.iter().map(Cow::Borrowed);
        let ipv4_addresses = adj.ipv4_addrs.iter().copied();
        let ipv6_addresses = adj.ipv6_addrs.iter().copied();
        let protocol_supported = adj.protocols_supported.iter().copied();
        let topologies = adj.topologies.iter().copied();
        Self {
            neighbor_sys_type: Some(adj.level_capability),
            neighbor_sysid: Some(adj.system_id),
            neighbor_extended_circuit_id: adj.ext_circuit_id.ignore_in_testing(),
            neighbor_snpa: Some(Cow::Owned(adj.snpa.to_string())).ignore_in_testing(),
            usage: Some(adj.level_usage),
            hold_timer: adj.holdtimer.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
            neighbor_priority: adj.priority,
            lastuptime: adj.last_uptime.map(Timeticks).ignore_in_testing(),
            state: Some(adj.state),
            area_addresses: Some(Box::new(area_addresses)),
            ipv4_addresses: Some(Box::new(ipv4_addresses)),
            ipv6_addresses: Some(Box::new(ipv6_addresses)),
            protocol_supported: Some(Box::new(protocol_supported)),
            topologies: Some(Box::new(topologies)),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::adjacencies::adjacency::adjacency_sid::AdjacencySid<'a> {
    type ParentListEntry = &'a Adjacency;
    type ListEntry = &'a AdjacencySid;

    fn iter(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = adj.adj_sids.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, adj_sid: &Self::ListEntry) -> Self {
        Self {
            value: Some(adj_sid.label.get()),
            address_family: Some(adj_sid.af.to_yang()),
            weight: Some(0),
            protection_requested: Some(false),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::event_counters::EventCounters {
    type ParentListEntry = &'a Interface;

    fn new(_instance: &'a Instance, iface: &Self::ParentListEntry) -> Option<Self> {
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
    type ParentListEntry = &'a Interface;
    type ListEntry = (&'a Interface, LevelNumber);

    fn iter(_instance: &'a Instance, &iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.config.levels().map(move |level| (iface, level));
        Some(iter).ignore_in_testing()
    }

    fn new(_instance: &'a Instance, (_, level): &Self::ListEntry) -> Self {
        Self {
            level: *level as u8,
        }
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::iih::Iih {
    type ParentListEntry = (&'a Interface, LevelNumber);

    fn new(_instance: &'a Instance, (iface, level): &Self::ParentListEntry) -> Option<Self> {
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.iih_in),
            out: Some(packet_counters.iih_out.load(atomic::Ordering::Relaxed)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::lsp::Lsp {
    type ParentListEntry = (&'a Interface, LevelNumber);

    fn new(_instance: &'a Instance, (iface, level): &Self::ParentListEntry) -> Option<Self> {
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.lsp_in),
            out: Some(packet_counters.lsp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::psnp::Psnp {
    type ParentListEntry = (&'a Interface, LevelNumber);

    fn new(_instance: &'a Instance, (iface, level): &Self::ParentListEntry) -> Option<Self> {
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.psnp_in),
            out: Some(packet_counters.psnp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::csnp::Csnp {
    type ParentListEntry = (&'a Interface, LevelNumber);

    fn new(_instance: &'a Instance, (iface, level): &Self::ParentListEntry) -> Option<Self> {
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.csnp_in),
            out: Some(packet_counters.csnp_out),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for isis::interfaces::interface::packet_counters::level::unknown::Unknown {
    type ParentListEntry = (&'a Interface, LevelNumber);

    fn new(_instance: &'a Instance, (iface, level): &Self::ParentListEntry) -> Option<Self> {
        let packet_counters = iface.state.packet_counters.get(*level);
        Some(Self {
            r#in: Some(packet_counters.unknown_in),
        })
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::srm::level::Level<'a> {
    type ParentListEntry = &'a Interface;
    type ListEntry = (&'a Interface, LevelNumber);

    fn iter(_instance: &'a Instance, &iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = LevelType::All.into_iter().filter(|level| !iface.state.srm_list.get(*level).is_empty()).map(move |level| (iface, level));
        Some(iter).only_in_testing()
    }

    fn new(_instance: &'a Instance, (iface, level): &Self::ListEntry) -> Self {
        Self {
            level: *level as u8,
            lsp_id: Some(Box::new(iface.state.srm_list.get(*level).keys().copied())),
        }
    }
}

impl<'a> YangList<'a, Instance> for isis::interfaces::interface::ssn::level::Level<'a> {
    type ParentListEntry = &'a Interface;
    type ListEntry = (&'a Interface, LevelNumber);

    fn iter(_instance: &'a Instance, &iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = LevelType::All.into_iter().filter(|level| !iface.state.ssn_list.get(*level).is_empty()).map(move |level| (iface, level));
        Some(iter).only_in_testing()
    }

    fn new(_instance: &'a Instance, (iface, level): &Self::ListEntry) -> Self {
        Self {
            level: *level as u8,
            lsp_id: Some(Box::new(iface.state.ssn_list.get(*level).keys().copied())),
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
