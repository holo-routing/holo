//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use bitflags::bitflags;
use derive_new::new;
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt, Ipv6NetworkExt};
use holo_utils::task::TimeoutTask;
use holo_utils::UnboundedSender;

use crate::adjacency::AdjacencyState;
use crate::collections::{Arena, LspEntryId};
use crate::debug::{Debug, LspPurgeReason};
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType};
use crate::northbound::notification;
use crate::packet::consts::LspFlags;
use crate::packet::pdu::{Lsp, LspTlvs};
use crate::packet::tlv::{
    ExtIpv4Reach, ExtIsReach, Ipv4Reach, Ipv6Reach, IsReach, Nlpid,
    MAX_NARROW_METRIC,
};
use crate::packet::{LanId, LevelNumber, LspId};
use crate::spf::SpfType;
use crate::tasks::messages::input::LspPurgeMsg;
use crate::{spf, tasks};

// LSP ZeroAge lifetime.
pub const LSP_ZERO_AGE_LIFETIME: u64 = 60;
// Minimum time interval between generation of LSPs.
pub const LSP_MIN_GEN_INTERVAL: u64 = 5;
// LSP initial sequence number.
const LSP_INIT_SEQNO: u32 = 0x00000001;
// Maximum size of the LSP log record.
const LSP_LOG_MAX_SIZE: usize = 64;

// LSP database entry.
#[derive(Debug)]
pub struct LspEntry {
    // LSP entry ID.
    pub id: LspEntryId,
    // LSP data.
    pub data: Lsp,
    // Timer triggered when the LSP's remaining lifetime reaches zero.
    pub expiry_timer: Option<TimeoutTask>,
    // Timer triggered when the LSP's ZeroAge timeout expires.
    pub delete_timer: Option<TimeoutTask>,
    // Timer for the periodic LSP refresh interval.
    pub refresh_timer: Option<TimeoutTask>,
    // LSP entry flags.
    pub flags: LspEntryFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct LspEntryFlags: u8 {
        const RECEIVED = 0x01;
        const PURGED = 0x02;
    }
}

#[derive(Debug)]
#[derive(new)]
pub struct LspLogEntry {
    pub id: u32,
    pub level: LevelNumber,
    pub lsp: LspLogId,
    pub rcvd_time: Option<Instant>,
    pub reason: LspLogReason,
}

#[derive(Clone, Debug)]
#[derive(new)]
pub struct LspLogId {
    pub lsp_id: LspId,
    pub seqno: u32,
}

#[derive(Debug)]
pub enum LspLogReason {
    Refresh,
    ContentChange,
}

// ===== impl LspEntry =====

impl LspEntry {
    // Creates new LSP database entry.
    pub(crate) fn new(
        level: LevelNumber,
        id: LspEntryId,
        data: Lsp,
        lsp_purgep: &UnboundedSender<LspPurgeMsg>,
    ) -> LspEntry {
        let expiry_timer = (data.rem_lifetime != 0)
            .then_some(tasks::lsp_expiry_timer(level, id, &data, lsp_purgep));

        LspEntry {
            id,
            data,
            expiry_timer,
            delete_timer: None,
            refresh_timer: None,
            flags: Default::default(),
        }
    }
}

// ===== helper functions =====

fn lsp_build(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
) -> Vec<Lsp> {
    let mut lsps = vec![];

    // Build main LSP.
    let tlvs = lsp_build_tlvs(instance, arenas, level);
    let fragments = lsp_build_fragments(instance, arenas, level, 0, tlvs);
    lsps.extend(fragments);

    // Build pseudonode LSPs.
    for iface in arenas
        .interfaces
        .iter()
        .filter(|iface| iface.state.active)
        .filter(|iface| iface.config.interface_type == InterfaceType::Broadcast)
        .filter(|iface| iface.is_dis(level))
    {
        let circuit_id = iface.state.circuit_id;
        let tlvs = lsp_build_tlvs_pseudo(instance, arenas, level, iface);
        let fragments =
            lsp_build_fragments(instance, arenas, level, circuit_id, tlvs);
        lsps.extend(fragments);
    }

    lsps
}

fn lsp_build_flags(
    instance: &mut InstanceUpView<'_>,
    lsp_id: LspId,
) -> LspFlags {
    let mut lsp_flags = LspFlags::default();
    if instance.config.level_type.intersects(LevelNumber::L1) {
        lsp_flags.insert(LspFlags::IS_TYPE1);
    }
    if instance.config.level_type.intersects(LevelNumber::L2) {
        lsp_flags.insert(LspFlags::IS_TYPE2);
    }
    if instance.config.overload_status
        && lsp_id.pseudonode == 0
        && lsp_id.fragment == 0
    {
        lsp_flags.insert(LspFlags::OL);
    }
    lsp_flags
}

fn lsp_build_tlvs(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
) -> LspTlvs {
    let metric_type = instance.config.metric_type.get(level);
    let mut protocols_supported = vec![];
    let mut is_reach = vec![];
    let mut ext_is_reach = vec![];
    let mut ipv4_addrs = BTreeSet::new();
    let mut ipv4_internal_reach = BTreeMap::new();
    let mut ext_ipv4_reach = BTreeMap::new();
    let mut ipv6_addrs = BTreeSet::new();
    let mut ipv6_reach = BTreeMap::new();

    // Add supported protocols.
    if instance.config.is_af_enabled(AddressFamily::Ipv4) {
        protocols_supported.push(Nlpid::Ipv4 as u8);
    }
    if instance.config.is_af_enabled(AddressFamily::Ipv6) {
        protocols_supported.push(Nlpid::Ipv6 as u8);
    }

    // Iterate over all active interfaces.
    for iface in arenas.interfaces.iter().filter(|iface| iface.state.active) {
        let metric = iface.config.metric.get(level);

        // Add IS reachability information.
        match iface.config.interface_type {
            InterfaceType::Broadcast => {
                if let Some(dis) = iface.state.dis.get(level) {
                    if metric_type.is_standard_enabled() {
                        is_reach.push(IsReach {
                            metric: std::cmp::min(metric, MAX_NARROW_METRIC)
                                as u8,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            neighbor: dis.lan_id,
                        });
                    }
                    if metric_type.is_wide_enabled() {
                        ext_is_reach.push(ExtIsReach {
                            neighbor: dis.lan_id,
                            metric,
                            sub_tlvs: Default::default(),
                        });
                    }
                }
            }
            InterfaceType::PointToPoint => {
                if let Some(adj) = iface
                    .state
                    .p2p_adjacency
                    .as_ref()
                    .filter(|adj| adj.level_usage.intersects(level))
                    .filter(|adj| adj.state == AdjacencyState::Up)
                {
                    let neighbor = LanId::from((adj.system_id, 0));
                    if metric_type.is_standard_enabled() {
                        is_reach.push(IsReach {
                            metric: std::cmp::min(metric, MAX_NARROW_METRIC)
                                as u8,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            neighbor,
                        });
                    }
                    if metric_type.is_wide_enabled() {
                        ext_is_reach.push(ExtIsReach {
                            neighbor,
                            metric,
                            sub_tlvs: Default::default(),
                        });
                    }
                }
            }
        }

        // Add IPv4 information.
        if instance.config.is_af_enabled(AddressFamily::Ipv4) {
            for addr in iface.system.ipv4_addr_list.iter() {
                ipv4_addrs.insert(addr.ip());

                let prefix = addr.apply_mask();
                if metric_type.is_standard_enabled() {
                    ipv4_internal_reach.insert(
                        prefix,
                        Ipv4Reach {
                            ie_bit: false,
                            metric: std::cmp::min(metric, MAX_NARROW_METRIC)
                                as u8,
                            metric_delay: None,
                            metric_expense: None,
                            metric_error: None,
                            prefix,
                        },
                    );
                }
                if metric_type.is_wide_enabled() {
                    ext_ipv4_reach.insert(
                        prefix,
                        ExtIpv4Reach {
                            metric,
                            up_down: false,
                            prefix,
                            sub_tlvs: Default::default(),
                        },
                    );
                }
            }
        }

        // Add IPv6 information.
        if instance.config.is_af_enabled(AddressFamily::Ipv6) {
            for addr in iface
                .system
                .ipv6_addr_list
                .iter()
                .filter(|addr| !addr.ip().is_unicast_link_local())
            {
                ipv6_addrs.insert(addr.ip());

                let prefix = addr.apply_mask();
                ipv6_reach.insert(
                    prefix,
                    Ipv6Reach {
                        metric,
                        up_down: false,
                        external: false,
                        prefix,
                        sub_tlvs: Default::default(),
                    },
                );
            }
        }
    }
    LspTlvs::new(
        protocols_supported,
        instance.config.area_addrs.clone(),
        Some(instance.config.lsp_mtu),
        is_reach,
        ext_is_reach,
        ipv4_addrs,
        ipv4_internal_reach.into_values(),
        [],
        ext_ipv4_reach.into_values(),
        ipv6_addrs,
        ipv6_reach.into_values(),
    )
}

fn lsp_build_tlvs_pseudo(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
    iface: &Interface,
) -> LspTlvs {
    let system_id = instance.config.system_id.unwrap();
    let metric_type = instance.config.metric_type.get(level);
    let mut is_reach = vec![];
    let mut ext_is_reach = vec![];

    // Add IS reachability information.
    for neighbor in iface
        .state
        .lan_adjacencies
        .get(level)
        .iter(&arenas.adjacencies)
        // Add adjacencies in the Up state.
        .filter(|adj| adj.state == AdjacencyState::Up)
        .map(|adj| LanId::from((adj.system_id, 0)))
        // Add ourselves.
        .chain(std::iter::once(LanId::from((system_id, 0))))
    {
        if metric_type.is_standard_enabled() {
            is_reach.push(IsReach {
                metric: 0,
                metric_delay: None,
                metric_expense: None,
                metric_error: None,
                neighbor,
            });
        }
        if metric_type.is_wide_enabled() {
            ext_is_reach.push(ExtIsReach {
                neighbor,
                metric: 0,
                sub_tlvs: Default::default(),
            });
        }
    }

    LspTlvs::new([], [], None, is_reach, ext_is_reach, [], [], [], [], [], [])
}

fn lsp_build_fragments(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
    pseudonode_id: u8,
    mut tlvs: LspTlvs,
) -> Vec<Lsp> {
    let system_id = instance.config.system_id.unwrap();
    let mut fragments = vec![];
    for frag_id in 0..=255 {
        let Some(tlvs) = tlvs.next_chunk(
            instance.config.lsp_mtu as usize - Lsp::HEADER_LEN as usize,
        ) else {
            break;
        };

        let lsp_id = LspId::from((system_id, pseudonode_id, frag_id));
        let seqno = instance
            .state
            .lsdb
            .get(level)
            .get_by_lspid(&arenas.lsp_entries, &lsp_id)
            .map(|(_, lse)| lse.data.seqno + 1)
            .unwrap_or(LSP_INIT_SEQNO);
        let lsp_flags = lsp_build_flags(instance, lsp_id);
        let fragment = Lsp::new(
            level,
            instance.config.lsp_lifetime,
            lsp_id,
            seqno,
            lsp_flags,
            tlvs,
        );
        fragments.push(fragment);
    }
    fragments
}

// Adds log entry for the newly installed LSP.
fn log_lsp(
    instance: &mut InstanceUpView<'_>,
    level: LevelNumber,
    lsp: LspLogId,
    rcvd_time: Option<Instant>,
    reason: LspLogReason,
) {
    // Get next log ID.
    let log_id = &mut instance.state.lsp_log_next_id;
    *log_id += 1;

    // Add new log entry.
    let log_entry = LspLogEntry::new(*log_id, level, lsp, rcvd_time, reason);
    instance.state.lsp_log.push_front(log_entry);

    // Remove old entries if necessary.
    instance.state.lsp_log.truncate(LSP_LOG_MAX_SIZE);
}

// ===== global functions =====

// Compares which LSP is more recent.
pub(crate) fn lsp_compare(
    lsp_db: &Lsp,
    lsp_rx_seqno: u32,
    lsp_rx_rem_lifetime: u16,
) -> Ordering {
    let cmp = lsp_db.seqno.cmp(&lsp_rx_seqno);
    if cmp != Ordering::Equal {
        return cmp;
    }

    // ISO 10589 - Section 7.3.16.3:
    // If the sequence numbers are the same, prefer the LSP in the database if
    // it has expired (Remaining Lifetime = 0) and the received LSP has a
    // non-zero Remaining Lifetime.
    if lsp_db.rem_lifetime == 0 && lsp_rx_rem_lifetime != 0 {
        return Ordering::Greater;
    }

    // ISO 10589 - Section 7.3.16.4.b.1:
    // If the sequence numbers are the same, prefer the received LSP if it has
    // expired (Remaining Lifetime = 0) and the LSP in the database has a
    // non-zero Remaining Lifetime.
    if lsp_db.rem_lifetime != 0 && lsp_rx_rem_lifetime == 0 {
        return Ordering::Less;
    }

    Ordering::Equal
}

// Installs the provided LSP to the LSDB.
pub(crate) fn install<'a>(
    instance: &mut InstanceUpView<'_>,
    lsp_entries: &'a mut Arena<LspEntry>,
    level: LevelNumber,
    lsp: Lsp,
) -> &'a mut LspEntry {
    Debug::LspInstall(level, &lsp).log();

    // Remove old instance of the LSP.
    let lsdb = instance.state.lsdb.get_mut(level);
    let mut old_lsp = None;
    if let Some((lse_idx, _)) = lsdb.get_by_lspid(lsp_entries, &lsp.lsp_id) {
        let old_lse = lsdb.delete(lsp_entries, lse_idx);
        old_lsp = Some(old_lse.data);
    }

    // Check if the LSP content has changed.
    let mut content_change = true;
    let mut topology_change = true;
    if let Some(old_lsp) = old_lsp
        && lsp.flags == old_lsp.flags
    {
        if old_lsp.tlvs == lsp.tlvs {
            content_change = false;
            topology_change = false;
        } else if old_lsp.tlvs.is_reach().eq(lsp.tlvs.is_reach())
            && old_lsp.tlvs.ext_is_reach().eq(lsp.tlvs.ext_is_reach())
        {
            topology_change = false;
        }
    }

    // Add LSP entry to LSDB.
    let (_, lse) = instance.state.lsdb.get_mut(level).insert(
        lsp_entries,
        level,
        lsp,
        &instance.tx.protocol_input.lsp_purge,
    );

    // Add entry to LSP log.
    let lsp = &lse.data;
    let lsp_log_id = LspLogId::new(lsp.lsp_id, lsp.seqno);
    let reason = if content_change {
        LspLogReason::ContentChange
    } else {
        LspLogReason::Refresh
    };
    log_lsp(instance, level, lsp_log_id.clone(), None, reason);

    // Schedule SPF run if necessary.
    if content_change && lsp.seqno != 0 {
        let spf_sched = instance.state.spf_sched.get_mut(level);
        spf_sched.trigger_lsps.push(lsp_log_id);
        spf_sched.schedule_time.get_or_insert_with(Instant::now);
        if topology_change {
            spf_sched.spf_type = SpfType::Full;
        }

        instance
            .tx
            .protocol_input
            .spf_delay_event(level, spf::fsm::Event::Igp);
    }

    lse
}

pub(crate) fn lsp_originate_all(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    level: LevelNumber,
) {
    let system_id = instance.config.system_id.unwrap();
    let before: HashSet<_> = instance
        .state
        .lsdb
        .get(level)
        .iter_for_system_id(&arenas.lsp_entries, system_id)
        .map(|lse| lse.data.lsp_id)
        .collect();
    let mut after = HashSet::new();

    // Build updated local LSP.
    for lsp in lsp_build(instance, arenas, level) {
        after.insert(lsp.lsp_id);

        // Get the current instance of this LSP (if any) from the LSDB.
        let old_lsp = instance
            .state
            .lsdb
            .get(level)
            .get_by_lspid(&arenas.lsp_entries, &lsp.lsp_id)
            .map(|(_, lse)| &lse.data);

        // Skip origination if the LSP content hasn't changed.
        if let Some(old_lsp) = old_lsp
            && old_lsp.flags == lsp.flags
            && old_lsp.tlvs == lsp.tlvs
        {
            continue;
        }

        // Log LSP origination.
        Debug::LspOriginate(level, &lsp).log();

        // Send YANG notification.
        notification::lsp_generation(instance, &lsp);

        // Originate new LSP version.
        lsp_originate(instance, arenas, level, lsp);
    }

    // Purge any LSP fragments that are no longer in use.
    for (_, lse) in before.difference(&after).filter_map(|lsp_id| {
        instance
            .state
            .lsdb
            .get(level)
            .get_by_lspid(&arenas.lsp_entries, lsp_id)
    }) {
        let reason = LspPurgeReason::Removed;
        instance.tx.protocol_input.lsp_purge(level, lse.id, reason);
    }

    // Update time of last LSP origination.
    instance.state.lsp_orig_last = Some(Instant::now());
}

pub(crate) fn lsp_originate(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    level: LevelNumber,
    lsp: Lsp,
) {
    // Install LSP into the LSDB.
    let lse = install(instance, &mut arenas.lsp_entries, level, lsp);

    // Flood LSP over all interfaces.
    for iface in arenas.interfaces.iter_mut() {
        iface.srm_list_add(instance, level, lse.data.clone());
    }

    // Schedule LSP refreshing.
    let refresh_timer = tasks::lsp_refresh_timer(
        level,
        lse.id,
        instance.config.lsp_refresh,
        &instance.tx.protocol_input.lsp_refresh,
    );
    lse.refresh_timer = Some(refresh_timer);
}
