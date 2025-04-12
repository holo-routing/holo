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
use holo_utils::UnboundedSender;
use holo_utils::bier::{
    BierEncapId, BierEncapsulationType, BierInBiftId, BiftId,
    UnderlayProtocolType,
};
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt, Ipv6NetworkExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use holo_utils::task::TimeoutTask;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::adjacency::AdjacencyState;
use crate::collections::{Arena, LspEntryId};
use crate::debug::{Debug, LspPurgeReason};
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType};
use crate::northbound::configuration::MetricType;
use crate::northbound::notification;
use crate::packet::consts::LspFlags;
use crate::packet::pdu::{Lsp, LspTlvs, Pdu};
use crate::packet::subtlvs::capability::{
    LabelBlockEntry, SrAlgoSubTlv, SrCapabilitiesFlags, SrCapabilitiesSubTlv,
    SrLocalBlockSubTlv,
};
use crate::packet::subtlvs::prefix::{
    BierEncapSubSubTlv, BierInfoSubTlv, BierSubSubTlv, Ipv4SourceRidSubTlv,
    Ipv6SourceRidSubTlv, PrefixAttrFlags, PrefixAttrFlagsSubTlv,
};
use crate::packet::tlv::{
    ExtIpv4Reach, ExtIsReach, IpReachTlvEntry, Ipv4Reach, Ipv4ReachSubTlvs,
    Ipv6Reach, Ipv6ReachSubTlvs, IsReach, MAX_NARROW_METRIC, Nlpid,
    RouterCapFlags, RouterCapTlv,
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
        && instance
            .is_l2_attached_to_backbone(&arenas.interfaces, &arenas.adjacencies)
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
    let mut ipv4_addrs = BTreeSet::new();
    let mut ipv4_internal_reach = BTreeMap::new();
    let mut ipv4_external_reach = BTreeMap::new();
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

    // Add router capabilities.
    lsp_build_tlvs_router_cap(instance, &mut router_cap);

    // Iterate over all active interfaces.
    for iface in arenas.interfaces.iter().filter(|iface| iface.state.active) {
        // Add IS reachability information.
        lsp_build_tlvs_is_reach(
            iface,
            level,
            metric_type,
            &mut is_reach,
            &mut ext_is_reach,
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

    LspTlvs::new(
        protocols_supported,
        router_cap,
        instance.config.area_addrs.clone(),
        instance.shared.hostname.clone(),
        Some(instance.config.lsp_mtu),
        is_reach,
        ext_is_reach,
        ipv4_addrs,
        ipv4_internal_reach.into_values(),
        ipv4_external_reach.into_values(),
        ext_ipv4_reach.into_values(),
        instance.config.ipv4_router_id,
        ipv6_addrs,
        ipv6_reach.into_values(),
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

    LspTlvs::new(
        [],
        [].into(),
        [],
        None,
        None,
        is_reach,
        ext_is_reach,
        [],
        [],
        [],
        [],
        None,
        [],
        [],
        None,
    )
}

fn lsp_build_tlvs_router_cap(
    instance: &mut InstanceUpView<'_>,
    router_cap: &mut Vec<RouterCapTlv>,
) {
    let sr_config = &instance.shared.sr_config;
    if instance.config.sr.enabled && !sr_config.srgb.is_empty() {
        let mut cap = RouterCapTlv::default();
        cap.router_id =
            instance.config.ipv4_router_id.or(instance.system.router_id);

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
        cap.sub_tlvs.sr_cap =
            Some(SrCapabilitiesSubTlv::new(sr_cap_flags, srgb));

        // Add SR-Algorithm Sub-TLV.
        cap.sub_tlvs.sr_algo =
            Some(SrAlgoSubTlv::new([IgpAlgoType::Spf].into()));

        // Add SR Local Block Sub-TLV.
        let mut srlb = vec![];
        for range in &sr_config.srlb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srlb.push(LabelBlockEntry::new(range, first));
        }
        if !srlb.is_empty() {
            cap.sub_tlvs.srlb = Some(SrLocalBlockSubTlv::new(srlb));
        }

        router_cap.push(cap);
    }
}

fn lsp_build_tlvs_is_reach(
    iface: &Interface,
    level: LevelNumber,
    metric_type: MetricType,
    is_reach: &mut Vec<IsReach>,
    ext_is_reach: &mut Vec<ExtIsReach>,
) {
    let metric = iface.config.metric.get(level);

    match iface.config.interface_type {
        InterfaceType::Broadcast => {
            if let Some(dis) = iface.state.dis.get(level) {
                if metric_type.is_standard_enabled() {
                    is_reach.push(IsReach {
                        metric: std::cmp::min(metric, MAX_NARROW_METRIC) as u8,
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
                        metric: std::cmp::min(metric, MAX_NARROW_METRIC) as u8,
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
}

fn lsp_build_tlvs_ip_local(
    instance: &mut InstanceUpView<'_>,
    iface: &Interface,
    level: LevelNumber,
    ipv4_addrs: &mut BTreeSet<Ipv4Addr>,
    ipv4_internal_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    ext_ipv4_reach: &mut BTreeMap<Ipv4Network, ExtIpv4Reach>,
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
        for addr in iface.system.ipv4_addr_list.iter() {
            ipv4_addrs.insert(addr.ip());

            let prefix = addr.apply_mask();
            if metric_type.is_standard_enabled() {
                ipv4_internal_reach.insert(
                    prefix,
                    Ipv4Reach {
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
                if iface.is_loopback() && prefix.is_host_prefix() {
                    prefix_attr_flags.insert(PrefixAttrFlags::N);
                }
                let sub_tlvs =
                    lsp_build_ipv4_reach_sub_tlvs(instance, prefix_attr_flags);
                ext_ipv4_reach.insert(
                    prefix,
                    ExtIpv4Reach {
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
    {
        for addr in iface
            .system
            .ipv6_addr_list
            .iter()
            .filter(|addr| !addr.ip().is_unicast_link_local())
        {
            ipv6_addrs.insert(addr.ip());

            let prefix = addr.apply_mask();
            let mut prefix_attr_flags = PrefixAttrFlags::empty();
            if iface.is_loopback() && prefix.is_host_prefix() {
                prefix_attr_flags.insert(PrefixAttrFlags::N);
            }
            let sub_tlvs = lsp_build_ipv6_reach_sub_tlvs(
                instance,
                prefix,
                prefix_attr_flags,
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
    ipv4_external_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    ext_ipv4_reach: &mut BTreeMap<Ipv4Network, ExtIpv4Reach>,
    ipv6_reach: &mut BTreeMap<Ipv6Network, Ipv6Reach>,
) {
    if instance.config.is_af_enabled(AddressFamily::Ipv4) {
        let metric_type = instance.config.metric_type.get(level);
        for (prefix, route) in instance.system.ipv4_routes.get(level) {
            let prefix = prefix.apply_mask();
            if metric_type.is_standard_enabled() {
                ipv4_external_reach.insert(
                    prefix,
                    Ipv4Reach {
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
                let sub_tlvs =
                    lsp_build_ipv4_reach_sub_tlvs(instance, prefix_attr_flags);
                ext_ipv4_reach.insert(
                    prefix,
                    ExtIpv4Reach {
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
        for (prefix, route) in instance.system.ipv6_routes.get(level) {
            let prefix = prefix.apply_mask();
            let prefix_attr_flags = PrefixAttrFlags::empty();
            let sub_tlvs = lsp_build_ipv6_reach_sub_tlvs(
                instance,
                prefix,
                prefix_attr_flags,
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

fn lsp_build_ipv4_reach_sub_tlvs(
    instance: &mut InstanceUpView<'_>,
    prefix_attr_flags: PrefixAttrFlags,
) -> Ipv4ReachSubTlvs {
    let mut sub_tlvs = Ipv4ReachSubTlvs::default();

    // Add IPv4 Extended Reachability Attribute Flags.
    if !prefix_attr_flags.is_empty() {
        sub_tlvs.prefix_attr_flags =
            Some(PrefixAttrFlagsSubTlv::new(prefix_attr_flags));
    }

    // Add Source Router ID Sub-TLV(s).
    if let Some(router_id) = instance.config.ipv4_router_id {
        sub_tlvs.ipv4_source_rid = Some(Ipv4SourceRidSubTlv::new(router_id));
    }
    if let Some(router_id) = instance.config.ipv6_router_id {
        sub_tlvs.ipv6_source_rid = Some(Ipv6SourceRidSubTlv::new(router_id));
    }

    sub_tlvs
}

fn lsp_build_ipv6_reach_sub_tlvs(
    instance: &mut InstanceUpView<'_>,
    prefix: Ipv6Network,
    prefix_attr_flags: PrefixAttrFlags,
) -> Ipv6ReachSubTlvs {
    let bier_config = &instance.shared.bier_config;
    let mut sub_tlvs = Ipv6ReachSubTlvs::default();

    // Add IPv6 Extended Reachability Attribute Flags.
    if !prefix_attr_flags.is_empty() {
        sub_tlvs.prefix_attr_flags =
            Some(PrefixAttrFlagsSubTlv::new(prefix_attr_flags));
    }

    // Add Source Router ID Sub-TLV(s).
    if let Some(router_id) = instance.config.ipv4_router_id {
        sub_tlvs.ipv4_source_rid = Some(Ipv4SourceRidSubTlv::new(router_id));
    }
    if let Some(router_id) = instance.config.ipv6_router_id {
        sub_tlvs.ipv6_source_rid = Some(Ipv6SourceRidSubTlv::new(router_id));
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
                        BierSubSubTlv::BierEncapSubSubTlv(
                            BierEncapSubSubTlv::new(
                                encap.max_si,
                                (*bsl).into(),
                                id,
                            ),
                        )
                    })
                })
                .collect::<Vec<_>>();

            let bier = BierInfoSubTlv::new(
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
        let Some(tlvs) = tlvs.next_chunk(max_len) else {
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
        let lsp_flags = lsp_build_flags(instance, arenas, level, lsp_id);
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
    instance: &mut InstanceUpView<'_>,
    arenas: &InstanceArenas,
    l2_router_cap: &mut Vec<RouterCapTlv>,
    l2_ipv4_internal_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    l2_ipv4_external_reach: &mut BTreeMap<Ipv4Network, Ipv4Reach>,
    l2_ext_ipv4_reach: &mut BTreeMap<Ipv4Network, ExtIpv4Reach>,
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
        // Get the distance to the corresponding L1 router from the SPT.
        let Some(l1_lsp_dist) = instance
            .state
            .spt
            .get(LevelNumber::L1)
            .get(&VertexId::new(LanId::from((l1_lsp.lsp_id.system_id, 0))))
            .map(|vertex| vertex.distance)
        else {
            continue;
        };

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
                    l1_lsp_dist,
                    l1_lsp.tlvs.ipv4_internal_reach(),
                    l2_ipv4_internal_reach,
                );
                propagate_ip_reach(
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
                    l1_lsp_dist,
                    l1_lsp.tlvs.ext_ipv4_reach(),
                    l2_ext_ipv4_reach,
                );
            }
        }

        // Propagate IPv6 reachability information.
        if instance.config.is_af_enabled(AddressFamily::Ipv6) {
            propagate_ip_reach(
                l1_lsp_dist,
                l1_lsp.tlvs.ipv6_reach(),
                l2_ipv6_reach,
            );
        }
    }
}

// Propagates IP reachability entries from an L1 LSP to an L2 LSP.
fn propagate_ip_reach<'a, T: IpReachTlvEntry + 'a>(
    l1_lsp_dist: u32,
    l1_reach: impl Iterator<Item = &'a T>,
    l2_reach: &mut BTreeMap<T::IpNetwork, T>,
) {
    for mut reach in l1_reach
        // RFC 5302 - Section 2:
        // "Prefixes with the up/down bit set that are learned via L1 routing
        // MUST NOT be advertised by L1L2 routers back into L2".
        .filter(|reach| !reach.up_down())
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
