//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet, btree_map};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use bitflags::bitflags;
use derive_new::new;
use holo_utils::bier::{
    BierEncapId, BierEncapsulationType, BierInBiftId, BiftId,
    UnderlayProtocolType,
};
use holo_utils::ip::{
    AddressFamily, Ipv4NetworkExt, Ipv6NetworkExt, JointPrefixMapExt,
    JointPrefixSetExt,
};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid, SidLastHopBehavior, SrCfgPrefixSid};
use holo_utils::task::TimeoutTask;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;
use tokio::sync::mpsc::UnboundedSender;

use crate::adjacency::{Adjacency, AdjacencyState};
use crate::collections::{Arena, LspEntryId};
use crate::debug::{Debug, LspPurgeReason};
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType};
use crate::northbound::configuration::MetricType;
use crate::northbound::notification;
use crate::packet::consts::{MtId, Nlpid};
use crate::packet::pdu::{Lsp, LspFlags, LspTlvs, Pdu};
use crate::packet::subtlvs::MsdStlv;
use crate::packet::subtlvs::capability::{
    LabelBlockEntry, NodeAdminTagStlv, SrAlgoStlv, SrCapabilitiesFlags,
    SrCapabilitiesStlv, SrLocalBlockStlv,
};
use crate::packet::subtlvs::prefix::{
    BierEncapSubStlv, BierInfoStlv, BierSubStlv, Ipv4SourceRidStlv,
    Ipv6SourceRidStlv, PrefixAttrFlags, PrefixAttrFlagsStlv, PrefixSidFlags,
    PrefixSidStlv,
};
use crate::packet::tlv::{
    IpReachTlvEntry, Ipv4Reach, Ipv4ReachStlvs, Ipv6Reach, Ipv6ReachStlvs,
    IsReach, IsReachStlvs, LegacyIpv4Reach, LegacyIsReach, MAX_NARROW_METRIC,
    MtFlags, MultiTopologyEntry, RouterCapFlags, RouterCapTlv,
};
use crate::packet::{LanId, LevelNumber, LevelType, LspId};
use crate::spf::{SpfType, VertexId};
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

// Builds the local LSP.
//
// This function builds all required TLVs based on the local configuration,
// interface state, and other relevant data. The TLVs are then split into
// as many fragments as needed.
//
// Whenever a change occurs, all fragments are rebuilt from scratch. This is a
// simple and reliable strategy that yields consistent results. However, when
// multiple fragments exist, even a minor change may require multiple fragments
// to be rebuilt, which can cause unnecessary churn in the network due to LSP
// flooding.
//
// A more efficient strategy would be to manage LSP fragments independently
// so that small changes, such as adding or removing an IS adjacency, affect
// only a single fragment. This, however, would come at the cost of increased
// code complexity.
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
    arenas: &InstanceArenas,
    level: LevelNumber,
    lsp_id: LspId,
) -> LspFlags {
    let mut lsp_flags = LspFlags::default();

    // Per ISO 10589 - Section 9.9, the "Level 1 Intermediate System"
    // bit must always be set, even in L2-only systems.
    lsp_flags.insert(LspFlags::IS_TYPE1);
    if instance.config.level_type.intersects(LevelNumber::L2) {
        lsp_flags.insert(LspFlags::IS_TYPE2);
    }
    if !instance.config.att_suppress
        && instance.config.level_type == LevelType::All
        && level == LevelNumber::L1
        && lsp_id.pseudonode == 0
        && lsp_id.fragment == 0
        && instance.is_l2_attached_to_backbone(
            MtId::Standard,
            &arenas.interfaces,
            &arenas.adjacencies,
        )
    {
        lsp_flags.insert(LspFlags::ATT);
    }
    if instance.config.overload_status
        && lsp_id.pseudonode == 0
        && lsp_id.fragment == 0
    {
        lsp_flags.insert(LspFlags::OL);
    }
    lsp_flags
}

fn lsp_build_mt_flags(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
    mt_id: u16,
) -> MtFlags {
    let mut mt_flags = MtFlags::default();

    if !instance.config.att_suppress
        && instance.config.level_type == LevelType::All
        && level == LevelNumber::L1
        && instance.is_l2_attached_to_backbone(
            mt_id,
            &arenas.interfaces,
            &arenas.adjacencies,
        )
    {
        mt_flags.insert(MtFlags::ATT);
    }
    if instance.config.overload_status {
        mt_flags.insert(MtFlags::OL);
    }

    mt_flags
}

fn lsp_build_tlvs(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
) -> LspTlvs {
    let metric_type = instance.config.metric_type.get(level);
    let mut protocols_supported = vec![];
    let mut router_cap = vec![];
    let mut is_reach = vec![];
    let mut ext_is_reach = vec![];
    let mut mt_is_reach = vec![];
    let mut ipv4_addrs = BTreeSet::new();
    let mut ipv4_internal_reach = BTreeMap::new();
    let mut ipv4_external_reach = BTreeMap::new();
    let mut ext_ipv4_reach = BTreeMap::new();
    let mut ipv6_addrs = BTreeSet::new();
    let mut ipv6_reach = BTreeMap::new();
    let mut mt_ipv6_reach = BTreeMap::new();

    // Add supported protocols.
    if instance.config.is_af_enabled(AddressFamily::Ipv4) {
        protocols_supported.push(Nlpid::Ipv4 as u8);
    }
    if instance.config.is_af_enabled(AddressFamily::Ipv6) {
        protocols_supported.push(Nlpid::Ipv6 as u8);
    }

    // Add router capabilities.
    lsp_build_tlvs_router_cap(instance, &mut router_cap);

    // Add topologies.
    let mut multi_topology = vec![];
    let topologies = instance.config.topologies();
    if topologies != [MtId::Standard].into() {
        multi_topology = topologies
            .into_iter()
            .map(|mt_id| MultiTopologyEntry {
                // Flags will be set later.
                flags: MtFlags::empty(),
                mt_id: mt_id as u16,
            })
            .collect::<Vec<_>>();
    }

    // Iterate over all active interfaces.
    for iface in arenas.interfaces.iter().filter(|iface| iface.state.active) {
        // Add IS reachability information.
        lsp_build_tlvs_is_reach(
            instance,
            iface,
            level,
            metric_type,
            &mut is_reach,
            &mut ext_is_reach,
            &mut mt_is_reach,
            &arenas.adjacencies,
        );

        // Add IP addresses and IP reachability information.
        lsp_build_tlvs_ip_local(
            instance,
            iface,
            level,
            &mut ipv4_addrs,
            &mut ipv4_internal_reach,
            &mut ext_ipv4_reach,
            &mut ipv6_addrs,
            &mut ipv6_reach,
        );
    }

    // Add redistributed routes.
    lsp_build_tlvs_ip_redistributed(
        instance,
        level,
        &mut ipv4_external_reach,
        &mut ext_ipv4_reach,
        &mut ipv6_reach,
    );

    // In an L1/L2 router, propagate L1 IP reachability to L2 for inter-area
    // routing.
    if level == LevelNumber::L2 && instance.config.level_type == LevelType::All
    {
        lsp_propagate_l1_to_l2(
            instance,
            arenas,
            &mut router_cap,
            &mut ipv4_internal_reach,
            &mut ipv4_external_reach,
            &mut ext_ipv4_reach,
            &mut ipv6_reach,
        );
    }

    // Swap the IPv6 reachability entries to use MT TLVs if the IPv6 unicast
    // topology is enabled.
    if instance.config.is_topology_enabled(MtId::Ipv6Unicast) {
        std::mem::swap(&mut ipv6_reach, &mut mt_ipv6_reach);
    }

    LspTlvs::new(
        protocols_supported,
        router_cap,
        instance.config.area_addrs.clone(),
        multi_topology,
        instance.shared.hostname.clone(),
        Some(instance.config.lsp_mtu),
        is_reach,
        ext_is_reach,
        mt_is_reach,
        ipv4_addrs,
        ipv4_internal_reach.into_values(),
        ipv4_external_reach.into_values(),
        ext_ipv4_reach.into_values(),
        [],
        instance.config.ipv4_router_id,
        ipv6_addrs,
        ipv6_reach.into_values(),
        mt_ipv6_reach.into_values(),
        instance.config.ipv6_router_id,
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
            is_reach.push(LegacyIsReach {
                metric: 0,
                metric_delay: None,
                metric_expense: None,
                metric_error: None,
                neighbor,
            });
        }
        if metric_type.is_wide_enabled() {
            ext_is_reach.push(IsReach {
                neighbor,
                metric: 0,
                sub_tlvs: Default::default(),
            });
        }
    }

    LspTlvs::new(
        [],
        [].into(),
        [],
        [],
        None,
        None,
        is_reach,
        ext_is_reach,
        [],
        [],
        [],
        [],
        [],
        [],
        None,
        [],
        [],
        [],
        None,
    )
}

fn lsp_build_tlvs_router_cap(
    instance: &mut InstanceUpView<'_>,
    router_cap: &mut Vec<RouterCapTlv>,
) {
    let mut cap = RouterCapTlv::default();
    cap.router_id =
        instance.config.ipv4_router_id.or(instance.system.router_id);

    // Add SR Sub-TLVs.
    let sr_config = &instance.shared.sr_config;
    if instance.config.sr.enabled && !sr_config.srgb.is_empty() {
        // Add SR-Capabilities Sub-TLV.
        let mut sr_cap_flags = SrCapabilitiesFlags::empty();
        if instance.config.is_af_enabled(AddressFamily::Ipv4) {
            sr_cap_flags.insert(SrCapabilitiesFlags::I);
        }
        if instance.config.is_af_enabled(AddressFamily::Ipv6) {
            sr_cap_flags.insert(SrCapabilitiesFlags::V);
        }
        let mut srgb = vec![];
        for range in &sr_config.srgb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srgb.push(LabelBlockEntry::new(range, first));
        }
        cap.sub_tlvs.sr_cap = Some(SrCapabilitiesStlv::new(sr_cap_flags, srgb));

        // Add SR-Algorithm Sub-TLV.
        cap.sub_tlvs.sr_algo = Some(SrAlgoStlv::new([IgpAlgoType::Spf].into()));

        // Add SR Local Block Sub-TLV.
        let mut srlb = vec![];
        for range in &sr_config.srlb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srlb.push(LabelBlockEntry::new(range, first));
        }
        if !srlb.is_empty() {
            cap.sub_tlvs.srlb = Some(SrLocalBlockStlv::new(srlb));
        }
    }

    // Add Node MSD Sub-TLV.
    if !instance.system.node_msd.is_empty() {
        cap.sub_tlvs.node_msd = Some(MsdStlv::from(&instance.system.node_msd));
    }

    // Add Node-Admin-Tag Sub-TLVs.
    if !instance.config.node_tags.is_empty() {
        let node_tags = instance.config.node_tags.clone();
        cap.sub_tlvs.node_tags = node_tags
            .into_iter()
            .chunks(NodeAdminTagStlv::MAX_ENTRIES)
            .into_iter()
            .map(|chunk| NodeAdminTagStlv::new(chunk.collect()))
            .collect();
    }

    if cap.sub_tlvs.sr_cap.is_some()
        || cap.sub_tlvs.node_msd.is_some()
        || !cap.sub_tlvs.node_tags.is_empty()
    {
        router_cap.push(cap);
    }
}

fn lsp_build_tlvs_is_reach(
    instance: &mut InstanceUpView<'_>,
    iface: &Interface,
    level: LevelNumber,
    metric_type: MetricType,
    is_reach: &mut Vec<LegacyIsReach>,
    ext_is_reach: &mut Vec<IsReach>,
    mt_is_reach: &mut Vec<IsReach>,
    adjacencies: &Arena<Adjacency>,
) {
    let metric = iface.config.metric.get(level);

    match iface.config.interface_type {
        InterfaceType::Broadcast => {
            if let Some(dis) = iface.state.dis.get(level) {
                // Add legacy IS reachability.
                if metric_type.is_standard_enabled() {
                    is_reach.push(LegacyIsReach {
                        metric: std::cmp::min(metric, MAX_NARROW_METRIC) as u8,
                        metric_delay: None,
                        metric_expense: None,
                        metric_error: None,
                        neighbor: dis.lan_id,
                    });
                }

                // Add extended IS reachability.
                if metric_type.is_wide_enabled() {
                    let af = if instance
                        .config
                        .is_topology_enabled(MtId::Ipv6Unicast)
                    {
                        Some(AddressFamily::Ipv4)
                    } else {
                        None
                    };
                    let sub_tlvs = lsp_build_is_reach_lan_stlvs(
                        instance,
                        iface,
                        level,
                        af,
                        adjacencies,
                    );
                    ext_is_reach.push(IsReach {
                        neighbor: dis.lan_id,
                        metric,
                        sub_tlvs,
                    });
                }

                // Add IPv6 MT IS reachability.
                let mt_id = MtId::Ipv6Unicast;
                if instance.config.is_topology_enabled(mt_id)
                    && iface.config.is_topology_enabled(mt_id)
                    && iface
                        .state
                        .lan_adjacencies
                        .get(level)
                        .iter(adjacencies)
                        .any(|adj| adj.topologies.contains(&(mt_id as u16)))
                {
                    let sub_tlvs = lsp_build_is_reach_lan_stlvs(
                        instance,
                        iface,
                        level,
                        Some(AddressFamily::Ipv6),
                        adjacencies,
                    );
                    mt_is_reach.push(IsReach {
                        neighbor: dis.lan_id,
                        metric: iface.config.topology_metric(mt_id, level),
                        sub_tlvs,
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

                // Add legacy IS reachability.
                if metric_type.is_standard_enabled()
                    && adj.bfd.ipv4.as_ref().is_none_or(|bfd| bfd.is_up())
                    && adj.bfd.ipv6.as_ref().is_none_or(|bfd| bfd.is_up())
                {
                    is_reach.push(LegacyIsReach {
                        metric: std::cmp::min(metric, MAX_NARROW_METRIC) as u8,
                        metric_delay: None,
                        metric_expense: None,
                        metric_error: None,
                        neighbor,
                    });
                }

                // Add extended IS reachability.
                if metric_type.is_wide_enabled()
                    && adj.bfd.ipv4.as_ref().is_none_or(|bfd| bfd.is_up())
                    && adj.bfd.ipv6.as_ref().is_none_or(|bfd| bfd.is_up())
                {
                    let af = if instance
                        .config
                        .is_topology_enabled(MtId::Ipv6Unicast)
                    {
                        Some(AddressFamily::Ipv4)
                    } else {
                        None
                    };
                    let sub_tlvs =
                        lsp_build_is_reach_p2p_stlvs(instance, iface, adj, af);
                    ext_is_reach.push(IsReach {
                        neighbor,
                        metric,
                        sub_tlvs,
                    });
                }

                // Add IPv6 MT IS reachability.
                let mt_id = MtId::Ipv6Unicast;
                if instance.config.is_topology_enabled(mt_id)
                    && iface.config.is_topology_enabled(mt_id)
                    && adj.topologies.contains(&(mt_id as u16))
                    && adj.bfd.ipv6.as_ref().is_none_or(|bfd| bfd.is_up())
                {
                    let sub_tlvs = lsp_build_is_reach_p2p_stlvs(
                        instance,
                        iface,
                        adj,
                        Some(AddressFamily::Ipv6),
                    );
                    mt_is_reach.push(IsReach {
                        neighbor,
                        metric: iface.config.topology_metric(mt_id, level),
                        sub_tlvs,
                    });
                }
            }
        }
    }
}

fn lsp_build_tlvs_ip_local(
    instance: &mut InstanceUpView<'_>,
    iface: &Interface,
    level: LevelNumber,
    ipv4_addrs: &mut BTreeSet<Ipv4Addr>,
    ipv4_internal_reach: &mut BTreeMap<Ipv4Network, LegacyIpv4Reach>,
    ext_ipv4_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    ipv6_addrs: &mut BTreeSet<Ipv6Addr>,
    ipv6_reach: &mut BTreeMap<Ipv6Network, Ipv6Reach>,
) {
    let metric = iface.config.metric.get(level);

    // Add IPv4 information.
    if iface
        .config
        .is_af_enabled(AddressFamily::Ipv4, instance.config)
    {
        let metric_type = instance.config.metric_type.get(level);
        for addr in iface.system.addr_list.ipv4().iter() {
            ipv4_addrs.insert(addr.ip());

            let prefix = addr.apply_mask();
            if metric_type.is_standard_enabled() {
                ipv4_internal_reach.insert(
                    prefix,
                    LegacyIpv4Reach {
                        up_down: false,
                        ie_bit: false,
                        metric: std::cmp::min(metric, MAX_NARROW_METRIC) as u8,
                        metric_delay: None,
                        metric_expense: None,
                        metric_error: None,
                        prefix,
                    },
                );
            }
            if metric_type.is_wide_enabled() {
                let mut prefix_attr_flags = PrefixAttrFlags::empty();
                if iface.config.node_flag
                    && iface.is_loopback()
                    && prefix.is_host_prefix()
                {
                    prefix_attr_flags.insert(PrefixAttrFlags::N);
                }
                let sub_tlvs = lsp_build_ipv4_reach_stlvs(
                    instance,
                    prefix,
                    prefix_attr_flags,
                    true,
                );
                ext_ipv4_reach.insert(
                    prefix,
                    Ipv4Reach {
                        metric,
                        up_down: false,
                        prefix,
                        sub_tlvs,
                    },
                );
            }
        }
    }

    // Add IPv6 information.
    if iface
        .config
        .is_af_enabled(AddressFamily::Ipv6, instance.config)
        && (!instance.config.is_topology_enabled(MtId::Ipv6Unicast)
            || iface.config.is_topology_enabled(MtId::Ipv6Unicast))
    {
        for addr in iface
            .system
            .addr_list
            .ipv6()
            .iter()
            .filter(|addr| !addr.ip().is_unicast_link_local())
        {
            ipv6_addrs.insert(addr.ip());

            let prefix = addr.apply_mask();
            let mut prefix_attr_flags = PrefixAttrFlags::empty();
            if iface.config.node_flag
                && iface.is_loopback()
                && prefix.is_host_prefix()
            {
                prefix_attr_flags.insert(PrefixAttrFlags::N);
            }
            let sub_tlvs = lsp_build_ipv6_reach_stlvs(
                instance,
                prefix,
                prefix_attr_flags,
                true,
            );
            ipv6_reach.insert(
                prefix,
                Ipv6Reach {
                    metric,
                    up_down: false,
                    external: false,
                    prefix,
                    sub_tlvs,
                },
            );
        }
    }
}

fn lsp_build_tlvs_ip_redistributed(
    instance: &mut InstanceUpView<'_>,
    level: LevelNumber,
    ipv4_external_reach: &mut BTreeMap<Ipv4Network, LegacyIpv4Reach>,
    ext_ipv4_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    ipv6_reach: &mut BTreeMap<Ipv6Network, Ipv6Reach>,
) {
    if instance.config.is_af_enabled(AddressFamily::Ipv4) {
        let metric_type = instance.config.metric_type.get(level);
        for (prefix, route) in instance.system.routes.get(level).ipv4() {
            let prefix = prefix.apply_mask();
            if metric_type.is_standard_enabled() {
                ipv4_external_reach.insert(
                    prefix,
                    LegacyIpv4Reach {
                        up_down: false,
                        ie_bit: false,
                        metric: std::cmp::min(route.metric, MAX_NARROW_METRIC)
                            as u8,
                        metric_delay: None,
                        metric_expense: None,
                        metric_error: None,
                        prefix,
                    },
                );
            }
            if metric_type.is_wide_enabled() {
                let prefix_attr_flags = PrefixAttrFlags::X;
                let sub_tlvs = lsp_build_ipv4_reach_stlvs(
                    instance,
                    prefix,
                    prefix_attr_flags,
                    false,
                );
                ext_ipv4_reach.insert(
                    prefix,
                    Ipv4Reach {
                        metric: route.metric,
                        up_down: false,
                        prefix,
                        sub_tlvs,
                    },
                );
            }
        }
    }
    if instance.config.is_af_enabled(AddressFamily::Ipv6) {
        for (prefix, route) in instance.system.routes.get(level).ipv6() {
            let prefix = prefix.apply_mask();
            let prefix_attr_flags = PrefixAttrFlags::empty();
            let sub_tlvs = lsp_build_ipv6_reach_stlvs(
                instance,
                prefix,
                prefix_attr_flags,
                false,
            );
            ipv6_reach.insert(
                prefix,
                Ipv6Reach {
                    metric: route.metric,
                    up_down: false,
                    external: true,
                    prefix,
                    sub_tlvs,
                },
            );
        }
    }
}

fn lsp_build_is_reach_lan_stlvs(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    level: LevelNumber,
    af: Option<AddressFamily>,
    adjacencies: &Arena<Adjacency>,
) -> IsReachStlvs {
    let mut sub_tlvs = IsReachStlvs::default();

    // Add Adj-SID Sub-TLV(s).
    if instance.config.sr.enabled {
        sub_tlvs.adj_sids = iface
            .state
            .lan_adjacencies
            .get(level)
            .iter(adjacencies)
            .flat_map(|adj| adj.adj_sids.iter())
            .filter(|adj_sid| af.is_none_or(|af| af == adj_sid.af))
            .map(|adj_sid| adj_sid.to_stlv())
            .collect();
    }

    // Add Link MSD Sub-TLV.
    if !iface.system.msd.is_empty() {
        sub_tlvs.link_msd = Some(MsdStlv::from(&iface.system.msd));
    }

    sub_tlvs
}

fn lsp_build_is_reach_p2p_stlvs(
    instance: &InstanceUpView<'_>,
    iface: &Interface,
    adj: &Adjacency,
    af: Option<AddressFamily>,
) -> IsReachStlvs {
    let mut sub_tlvs = IsReachStlvs::default();

    // Add Adj-SID Sub-TLV(s).
    if instance.config.sr.enabled {
        sub_tlvs.adj_sids = adj
            .adj_sids
            .iter()
            .filter(|adj_sid| af.is_none_or(|af| af == adj_sid.af))
            .map(|adj_sid| adj_sid.to_stlv())
            .collect();
    }

    // Add Link MSD Sub-TLV.
    if !iface.system.msd.is_empty() {
        sub_tlvs.link_msd = Some(MsdStlv::from(&iface.system.msd));
    }

    sub_tlvs
}

fn lsp_build_ipv4_reach_stlvs(
    instance: &InstanceUpView<'_>,
    prefix: Ipv4Network,
    prefix_attr_flags: PrefixAttrFlags,
    add_prefix_sid: bool,
) -> Ipv4ReachStlvs {
    let mut sub_tlvs = Ipv4ReachStlvs::default();

    // Add IPv4 Extended Reachability Attribute Flags.
    if !prefix_attr_flags.is_empty() {
        sub_tlvs.prefix_attr_flags =
            Some(PrefixAttrFlagsStlv::new(prefix_attr_flags));
    }

    // Add Source Router ID Sub-TLV(s).
    if let Some(router_id) = instance.config.ipv4_router_id {
        sub_tlvs.ipv4_source_rid = Some(Ipv4SourceRidStlv::new(router_id));
    }
    if let Some(router_id) = instance.config.ipv6_router_id {
        sub_tlvs.ipv6_source_rid = Some(Ipv6SourceRidStlv::new(router_id));
    }

    // Add Prefix-SID Sub-TLV(s).
    if add_prefix_sid && instance.config.sr.enabled {
        let algo = IgpAlgoType::Spf;
        if let Some(prefix_sid_cfg) = instance
            .shared
            .sr_config
            .prefix_sids
            .get(&(prefix.into(), algo))
        {
            let prefix_sid = lsp_build_prefix_sid_stlv(prefix_sid_cfg);
            sub_tlvs.prefix_sids.insert(algo, prefix_sid);
        }
    }

    sub_tlvs
}

fn lsp_build_ipv6_reach_stlvs(
    instance: &InstanceUpView<'_>,
    prefix: Ipv6Network,
    prefix_attr_flags: PrefixAttrFlags,
    add_prefix_sid: bool,
) -> Ipv6ReachStlvs {
    let bier_config = &instance.shared.bier_config;
    let mut sub_tlvs = Ipv6ReachStlvs::default();

    // Add IPv6 Extended Reachability Attribute Flags.
    if !prefix_attr_flags.is_empty() {
        sub_tlvs.prefix_attr_flags =
            Some(PrefixAttrFlagsStlv::new(prefix_attr_flags));
    }

    // Add Source Router ID Sub-TLV(s).
    if let Some(router_id) = instance.config.ipv4_router_id {
        sub_tlvs.ipv4_source_rid = Some(Ipv4SourceRidStlv::new(router_id));
    }
    if let Some(router_id) = instance.config.ipv6_router_id {
        sub_tlvs.ipv6_source_rid = Some(Ipv6SourceRidStlv::new(router_id));
    }

    // Add Prefix-SID Sub-TLV(s).
    if add_prefix_sid && instance.config.sr.enabled {
        let algo = IgpAlgoType::Spf;
        if let Some(prefix_sid_cfg) = instance
            .shared
            .sr_config
            .prefix_sids
            .get(&(prefix.into(), algo))
        {
            let prefix_sid = lsp_build_prefix_sid_stlv(prefix_sid_cfg);
            sub_tlvs.prefix_sids.insert(algo, prefix_sid);
        }
    }

    // Add BIER Sub-TLV(s) if BIER is enabled and allowed to advertise.
    if instance.config.bier.enabled && instance.config.bier.advertise {
        for ((sd_id, _), sd_cfg) in
            bier_config.sd_cfg.iter().filter(|((_, af), sd_cfg)| {
                *af == AddressFamily::Ipv6
                    && sd_cfg.bfr_prefix == prefix.into()
                    // Enforce RFC8401 Section 4.2
                    && sd_cfg.bfr_prefix.prefix() == 128
                    && sd_cfg.underlay_protocol == UnderlayProtocolType::IsIs
            })
        {
            let bier_encaps = sd_cfg
                .encap
                .iter()
                .filter_map(|((bsl, encap_type), encap)| {
                    match encap_type {
                        BierEncapsulationType::Mpls => {
                            // TODO: where is the label defined?
                            Some(BierEncapId::Mpls(Label::new(0)))
                        }
                        _ => match encap.in_bift_id {
                            BierInBiftId::Base(id) => Some(id),
                            BierInBiftId::Encoding(true) => Some(0),
                            _ => None,
                        }
                        .map(|id| BierEncapId::NonMpls(BiftId::new(id))),
                    }
                    .map(|id| {
                        BierSubStlv::BierEncapSubStlv(BierEncapSubStlv::new(
                            encap.max_si,
                            (*bsl).into(),
                            id,
                        ))
                    })
                })
                .collect::<Vec<_>>();

            let bier = BierInfoStlv::new(
                sd_cfg.bar,
                sd_cfg.ipa,
                *sd_id,
                sd_cfg.bfr_id,
                bier_encaps,
            );
            sub_tlvs.bier.push(bier);
        }
    }

    sub_tlvs
}

fn lsp_build_prefix_sid_stlv(prefix_sid_cfg: &SrCfgPrefixSid) -> PrefixSidStlv {
    let mut flags = PrefixSidFlags::empty();
    match prefix_sid_cfg.last_hop {
        SidLastHopBehavior::ExpNull => {
            flags.insert(PrefixSidFlags::P);
            flags.insert(PrefixSidFlags::E);
        }
        SidLastHopBehavior::NoPhp => {
            flags.insert(PrefixSidFlags::P);
        }
        SidLastHopBehavior::Php => (),
    }
    let algo = IgpAlgoType::Spf;
    let sid = Sid::Index(prefix_sid_cfg.index);
    PrefixSidStlv::new(flags, algo, sid)
}

fn lsp_build_fragments(
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    level: LevelNumber,
    pseudonode_id: u8,
    mut tlvs: LspTlvs,
) -> Vec<Lsp> {
    let system_id = instance.config.system_id.unwrap();
    let auth = instance.config.auth.all.method(&instance.shared.keychains);
    let auth = auth.as_ref().and_then(|auth| auth.get_key_send());
    let max_len = instance.config.lsp_mtu as usize
        - Lsp::HEADER_LEN as usize
        - auth.map_or(0, Pdu::auth_tlv_len);

    let mut fragments = vec![];
    for frag_id in 0..=255 {
        let Some(mut tlvs) = tlvs.next_chunk(max_len) else {
            break;
        };

        let lsp_id = LspId::from((system_id, pseudonode_id, frag_id));
        let lsdb = instance.state.lsdb.get(level);
        let seqno = lsdb
            .get_by_lspid(&arenas.lsp_entries, &lsp_id)
            .map(|(_, lse)| lse.data.seqno + 1)
            .unwrap_or(LSP_INIT_SEQNO);

        // Initialize LSP flags and MT-specific flags.
        let lsp_flags = lsp_build_flags(instance, arenas, level, lsp_id);
        if lsp_id.pseudonode == 0 && lsp_id.fragment == 0 {
            for mt in tlvs
                .multi_topology_mut()
                .filter(|mt| mt.mt_id != MtId::Standard as u16)
            {
                mt.flags =
                    lsp_build_mt_flags(instance, arenas, level, mt.mt_id);
            }
        }

        let fragment = Lsp::new(
            level,
            instance.config.lsp_lifetime,
            lsp_id,
            seqno,
            lsp_flags,
            tlvs,
            auth,
        );
        fragments.push(fragment);
    }
    fragments
}

// Propagates L1 TLVs to L2 for inter-area routing.
fn lsp_propagate_l1_to_l2(
    instance: &InstanceUpView<'_>,
    arenas: &InstanceArenas,
    l2_router_cap: &mut Vec<RouterCapTlv>,
    l2_ipv4_internal_reach: &mut BTreeMap<Ipv4Network, LegacyIpv4Reach>,
    l2_ipv4_external_reach: &mut BTreeMap<Ipv4Network, LegacyIpv4Reach>,
    l2_ext_ipv4_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    l2_ipv6_reach: &mut BTreeMap<Ipv6Network, Ipv6Reach>,
) {
    let system_id = instance.config.system_id.unwrap();
    let metric_type = &instance.config.metric_type;
    let lsdb = instance.state.lsdb.get(LevelNumber::L1);

    // Iterate over all valid non-pseudonode L1 LSPs.
    for l1_lsp in lsdb
        .iter(&arenas.lsp_entries)
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.seqno != 0)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .filter(|lsp| !lsp.lsp_id.is_pseudonode())
        .filter(|lsp| lsp.lsp_id.system_id != system_id)
    {
        // Propagate the Router Capability TLV.
        for l1_router_cap in l1_lsp
            .tlvs
            .router_cap
            .iter()
            .filter(|router_cap| router_cap.flags.contains(RouterCapFlags::S))
            .cloned()
        {
            l2_router_cap.push(l1_router_cap);
        }

        // Standard topology: get the distance to the corresponding L1 router
        // from the SPT.
        if let Some(l1_lsp_dist) = instance
            .state
            .spt
            .standard
            .get(LevelNumber::L1)
            .get(&VertexId::new(LanId::from((l1_lsp.lsp_id.system_id, 0))))
            .map(|vertex| vertex.distance)
        {
            // Propagate IPv4 reachability information.
            //
            // Propagation for both old and new metric types occurs only if the
            // corresponding metric type is enabled on both levels.
            if instance.config.is_af_enabled(AddressFamily::Ipv4) {
                if LevelType::All
                    .into_iter()
                    .all(|level| metric_type.get(level).is_standard_enabled())
                {
                    propagate_ip_reach(
                        instance,
                        l1_lsp_dist,
                        l1_lsp.tlvs.ipv4_internal_reach(),
                        l2_ipv4_internal_reach,
                    );
                    propagate_ip_reach(
                        instance,
                        l1_lsp_dist,
                        l1_lsp.tlvs.ipv4_external_reach(),
                        l2_ipv4_external_reach,
                    );
                }
                if LevelType::All
                    .into_iter()
                    .all(|level| metric_type.get(level).is_wide_enabled())
                {
                    propagate_ip_reach(
                        instance,
                        l1_lsp_dist,
                        l1_lsp.tlvs.ext_ipv4_reach(),
                        l2_ext_ipv4_reach,
                    );
                }
            }

            // Propagate IPv6 reachability information.
            if !instance.config.is_topology_enabled(MtId::Ipv6Unicast)
                && instance.config.is_af_enabled(AddressFamily::Ipv6)
            {
                propagate_ip_reach(
                    instance,
                    l1_lsp_dist,
                    l1_lsp.tlvs.ipv6_reach(),
                    l2_ipv6_reach,
                );
            }
        }

        // IPv6 unicast topology: get the distance to the corresponding L1
        // router from the SPT.
        if let Some(l1_lsp_dist) = instance
            .state
            .spt
            .ipv6_unicast
            .get(LevelNumber::L1)
            .get(&VertexId::new(LanId::from((l1_lsp.lsp_id.system_id, 0))))
            .map(|vertex| vertex.distance)
        {
            // Propagate MT-IPv6 reachability information.
            propagate_ip_reach(
                instance,
                l1_lsp_dist,
                l1_lsp.tlvs.mt_ipv6_reach_by_id(MtId::Ipv6Unicast),
                l2_ipv6_reach,
            );
        }
    }

    // Add active summary routes.
    for (prefix, summary) in &instance.state.summaries {
        match prefix {
            IpNetwork::V4(prefix) => {
                if !instance.config.is_af_enabled(AddressFamily::Ipv4) {
                    continue;
                }
                if metric_type.get(LevelNumber::L2).is_standard_enabled() {
                    let entry = LegacyIpv4Reach {
                        up_down: false,
                        ie_bit: false,
                        metric: std::cmp::min(
                            summary.metric(),
                            MAX_NARROW_METRIC,
                        ) as u8,
                        metric_delay: None,
                        metric_expense: None,
                        metric_error: None,
                        prefix: *prefix,
                    };
                    l2_ipv4_internal_reach.insert(*prefix, entry);
                }
                if metric_type.get(LevelNumber::L2).is_wide_enabled() {
                    let sub_tlvs = lsp_build_ipv4_reach_stlvs(
                        instance,
                        *prefix,
                        PrefixAttrFlags::empty(),
                        false,
                    );
                    let entry = Ipv4Reach {
                        up_down: false,
                        metric: summary.metric(),
                        prefix: *prefix,
                        sub_tlvs,
                    };
                    l2_ext_ipv4_reach.insert(*prefix, entry);
                }
            }
            IpNetwork::V6(prefix) => {
                if !instance.config.is_af_enabled(AddressFamily::Ipv6) {
                    continue;
                }
                let sub_tlvs = lsp_build_ipv6_reach_stlvs(
                    instance,
                    *prefix,
                    PrefixAttrFlags::empty(),
                    false,
                );
                let entry = Ipv6Reach {
                    metric: summary.metric(),
                    up_down: false,
                    external: false,
                    prefix: *prefix,
                    sub_tlvs,
                };
                l2_ipv6_reach.insert(*prefix, entry);
            }
        }
    }
}

// Propagates IP reachability entries from an L1 LSP to an L2 LSP.
fn propagate_ip_reach<'a, T: IpReachTlvEntry + 'a>(
    instance: &InstanceUpView<'_>,
    l1_lsp_dist: u32,
    l1_reach: impl Iterator<Item = &'a T>,
    l2_reach: &mut BTreeMap<T::IpNetwork, T>,
) {
    for mut reach in l1_reach
        // Exclude prefixes with the up/down bit set.
        .filter(|reach| !reach.up_down())
        // Exclude prefixes that are covered by configured summary routes.
        .filter(|reach| {
            instance
                .config
                .summaries
                .get_spm(&reach.prefix().into())
                .is_none()
        })
        .cloned()
    {
        // RFC 1195 - Section 3.2:
        // "The metric value announced in the level 2 LSPs is calculated from
        // the sum of the metric value announced in the corresponding level 1
        // LSP, plus the distance from the level 2 router to the appropriate
        // level 1 router".
        reach.metric_add(l1_lsp_dist);

        // Set the Re-advertisement Flag for reachability TLVs that support
        // the Extended Reachability Attribute Flags Sub-TLV.
        reach.prefix_attr_flags_set(PrefixAttrFlags::R);

        // Update flags for each associated Prefix-SID.
        for prefix_sid in reach.prefix_sids_mut() {
            // Set the Re-advertisement Flag.
            prefix_sid.flags.insert(PrefixSidFlags::R);

            // When propagating a reachability advertisement originated by
            // another IS-IS speaker, the router MUST set the P-Flag and MUST
            // clear the E-Flag of the related Prefix-SIDs.
            prefix_sid.flags.insert(PrefixSidFlags::P);
            prefix_sid.flags.remove(PrefixSidFlags::E);
        }

        // Keep only the entry with the lowest total metric for each prefix.
        match l2_reach.entry(reach.prefix()) {
            btree_map::Entry::Occupied(mut e) => {
                if reach.metric() < e.get().metric() {
                    e.insert(reach);
                }
            }
            btree_map::Entry::Vacant(e) => {
                e.insert(reach);
            }
        }
    }
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
    if instance.config.trace_opts.lsdb {
        Debug::LspInstall(level, &lsp).log();
    }

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
        && lsp.is_expired() == old_lsp.is_expired()
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
    let lsp = &lse.data;

    // Update hostname database.
    if lsp.lsp_id.pseudonode == 0 && lsp.lsp_id.fragment == 0 {
        let system_id = lsp.lsp_id.system_id;
        if let Some(hostname) = lsp.tlvs.hostname()
            && lsp.rem_lifetime != 0
        {
            instance
                .state
                .hostnames
                .insert(system_id, hostname.to_owned());
        } else {
            instance.state.hostnames.remove(&system_id);
        }
    }

    // Start the delete timer if the LSP has expired.
    if lsp.is_expired() {
        lse.flags.insert(LspEntryFlags::PURGED);
        let delete_timer = tasks::lsp_delete_timer(
            level,
            lse.id,
            LSP_ZERO_AGE_LIFETIME,
            &instance.tx.protocol_input.lsp_delete,
        );
        lse.delete_timer = Some(delete_timer);
    }

    // Add entry to LSP log.
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
        spf_sched.trigger_lsps.insert(lsp_log_id.lsp_id, lsp_log_id);
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
    let lsdb = instance.state.lsdb.get(level);
    let before: HashSet<_> = lsdb
        .iter_for_system_id(&arenas.lsp_entries, system_id)
        .map(|lse| lse.data.lsp_id)
        .collect();
    let mut after = HashSet::new();

    // Build updated local LSP.
    for lsp in lsp_build(instance, arenas, level) {
        after.insert(lsp.lsp_id);

        // Get the current instance of this LSP (if any) from the LSDB.
        let lsdb = instance.state.lsdb.get(level);
        let old_lsp = lsdb
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
        if instance.config.trace_opts.lsdb {
            Debug::LspOriginate(level, &lsp).log();
        }

        // Send YANG notification.
        notification::lsp_generation(instance, &lsp);

        // Originate new LSP version.
        lsp_originate(instance, arenas, level, lsp);
    }

    // Purge any LSP fragments that are no longer in use.
    for (_, lse) in before.difference(&after).filter_map(|lsp_id| {
        let lsdb = instance.state.lsdb.get(level);
        lsdb.get_by_lspid(&arenas.lsp_entries, lsp_id)
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
