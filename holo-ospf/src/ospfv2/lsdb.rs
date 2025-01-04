//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use holo_utils::ibus::SrCfgEvent;
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid, SidLastHopBehavior};
use ipnetwork::{IpNetwork, Ipv4Network};
use itertools::Itertools;

use crate::area::{Area, AreaType, AreaVersion, OptionsLocation};
use crate::collections::{
    lsdb_get, AreaIndex, Arena, InterfaceIndex, LsaEntryId, LsdbId, LsdbIndex,
};
use crate::debug::LsaFlushReason;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{ism, Interface, InterfaceType};
use crate::lsdb::{LsaEntry, LsaOriginateEvent, LsdbVersion, MAX_LINK_METRIC};
use crate::neighbor::nsm;
use crate::ospfv2::packet::lsa::{
    LsaBody, LsaHdr, LsaNetwork, LsaRouter, LsaRouterFlags, LsaRouterLink,
    LsaRouterLinkType, LsaSummary, LsaType, LsaTypeCode,
};
use crate::ospfv2::packet::lsa_opaque::{
    ExtLinkTlv, ExtPrefixRouteType, ExtPrefixTlv, LsaExtLink, LsaExtPrefix,
    LsaExtPrefixFlags, LsaOpaque, LsaOpaqueType, LsaRouterInfo, OpaqueLsaId,
    PrefixSid,
};
use crate::ospfv2::packet::Options;
use crate::packet::lsa::{
    Lsa, LsaHdrVersion, LsaKey, LsaScope, LsaTypeVersion,
};
use crate::packet::tlv::{
    DynamicHostnameTlv, PrefixSidFlags, RouterInfoCaps, RouterInfoCapsTlv,
    SidLabelRangeTlv, SrAlgoTlv, SrLocalBlockTlv,
};
use crate::route::{SummaryNet, SummaryRtr};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl LsdbVersion<Self> for Ospfv2 {
    fn lsa_type_is_valid(
        area_type: Option<AreaType>,
        nbr_options: Option<Options>,
        lsa_type: LsaType,
    ) -> bool {
        // Reject LSAs of unknown type.
        if lsa_type.type_code().is_none() {
            return false;
        }

        // Opaque LSAs are only flooded to opaque-capable neighbors.
        if let Some(nbr_options) = nbr_options {
            if lsa_type.is_opaque() && !nbr_options.contains(Options::O) {
                return false;
            }
        }

        // Reject AS-external and type-4 summary LSAs (as per errata 3746 of RFC
        // 2328) on stub/NSSA areas.
        if let Some(area_type) = area_type {
            if area_type != AreaType::Normal
                && matches!(
                    lsa_type.type_code(),
                    Some(
                        LsaTypeCode::SummaryRouter
                            | LsaTypeCode::AsExternal
                            | LsaTypeCode::OpaqueAs
                    )
                )
            {
                return false;
            }
        }

        true
    }

    fn lsa_is_self_originated(
        lsa: &Lsa<Self>,
        router_id: Ipv4Addr,
        interfaces: &Arena<Interface<Self>>,
    ) -> bool {
        // 1) The LSA's Advertising Router is equal to the router's own Router
        // ID.
        if lsa.hdr.adv_rtr == router_id {
            return true;
        }

        // 2) The LSA is a network-LSA and its Link State ID is equal to one of
        // the router's own IP interface addresses.
        if lsa.hdr.lsa_type.type_code() == Some(LsaTypeCode::Network)
            && interfaces
                .iter()
                .filter_map(|(_, iface)| iface.system.primary_addr)
                .any(|iface_primary_addr| {
                    lsa.hdr.lsa_id == iface_primary_addr.ip()
                })
        {
            return true;
        }

        false
    }

    fn lsa_orig_event(
        instance: &InstanceUpView<'_, Self>,
        arenas: &InstanceArenas<Self>,
        event: LsaOriginateEvent,
    ) -> Result<(), Error<Self>> {
        match event {
            LsaOriginateEvent::AreaStart { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // Originate Router Information LSA(s).
                lsa_orig_router_info(area, instance);
            }
            LsaOriginateEvent::InterfaceStateChange { .. } => {
                // (Re)originate Router-LSA in all areas since the ABR status
                // might have changed.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::InterfaceDrChange { area_id, iface_id }
            | LsaOriginateEvent::GrHelperExit { area_id, iface_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate or flush Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full)
                {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }
            }
            LsaOriginateEvent::InterfaceAddrAddDel { area_id, .. } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceCostChange { area_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }
            LsaOriginateEvent::NeighborToFromFull { area_id, iface_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Extended Link Opaque LSA(s).
                lsa_orig_ext_link(area, instance, arenas);

                // (Re)originate Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full)
                {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }
            }
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id, ..
            } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // (Re)originate Router-LSA.
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Extended Link Opaque LSA(s).
                lsa_orig_ext_link(area, instance, arenas);
            }
            LsaOriginateEvent::SelfOriginatedLsaRcvd { lsdb_id, lse_id } => {
                // Check if the received self-originated LSA needs to be
                // reoriginated or flushed.
                process_self_originated_lsa(instance, arenas, lsdb_id, lse_id)?;
            }
            LsaOriginateEvent::StubRouterChange => {
                // (Re)originate Router-LSA in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::GrHelperChange => {
                // (Re)originate Router Information LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            LsaOriginateEvent::SrEnableChange => {
                // (Re)originate Router Information LSA(s), Extended Prefix
                // Opaque LSA(s) and Extended Link Opaque LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                    lsa_orig_ext_prefix(area, instance, arenas);
                    lsa_orig_ext_link(area, instance, arenas);
                }
            }
            LsaOriginateEvent::SrCfgChange { change } => {
                match change {
                    SrCfgEvent::LabelRangeUpdate => {
                        // Reoriginate Router Information LSA(s) in all areas.
                        for area in arenas.areas.iter() {
                            lsa_orig_router_info(area, instance);
                        }
                    }
                    SrCfgEvent::PrefixSidUpdate(af) => {
                        if af == AddressFamily::Ipv4 {
                            // (Re)originate Extended Prefix Opaque LSA(s) in
                            // all areas.
                            for area in arenas.areas.iter() {
                                lsa_orig_ext_prefix(area, instance, arenas);
                            }
                        }
                    }
                }
            }
            LsaOriginateEvent::HostnameChange => {
                // (Re)originate Router Information LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            _ => (),
        };

        Ok(())
    }

    fn lsa_orig_inter_area_network(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        prefix: Ipv4Network,
        _lsa_id: Option<u32>,
        summary: &SummaryNet<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);

        // LSA's header options.
        let options = Self::area_options(area, OptionsLocation::Lsa);

        // TODO: implement Appendix's E algorithm for assigning Link State IDs.
        let lsa_id = prefix.ip();

        // (Re)originate Type-3 Summary-LSA.
        let lsa_body = LsaBody::SummaryNetwork(LsaSummary {
            mask: prefix.mask(),
            metric: summary.metric,
        });
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        lsa_id.into()

        // TODO: propagate SR Prefix-SIDs separately.
    }

    fn lsa_orig_inter_area_router(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        router_id: Ipv4Addr,
        _lsa_id: Option<u32>,
        summary: &SummaryRtr<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);

        // LSA ID.
        let lsa_id = router_id;

        // (Re)originate Type-4 Summary-LSA.
        let lsa_body = LsaBody::SummaryRouter(LsaSummary {
            mask: Ipv4Addr::BROADCAST,
            metric: summary.metric,
        });
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(summary.options),
            lsa_id,
            lsa_body,
        );

        lsa_id.into()
    }

    fn lsdb_get_by_lsa_type(
        iface_idx: InterfaceIndex,
        area_idx: AreaIndex,
        lsa_type: LsaType,
    ) -> LsdbIndex {
        match lsa_type.scope() {
            LsaScope::Link => LsdbIndex::Link(area_idx, iface_idx),
            LsaScope::Area => LsdbIndex::Area(area_idx),
            LsaScope::As => LsdbIndex::As,
            LsaScope::Unknown => {
                unreachable!();
            }
        }
    }

    fn lsdb_install(
        instance: &InstanceUpView<'_, Self>,
        arenas: &mut InstanceArenas<Self>,
        lsdb_idx: LsdbIndex,
        _lsdb_id: LsdbId,
        lsa: &Lsa<Self>,
    ) {
        // Keep track of self-originated Network-LSAs in the corresponding
        // interface structures. This is necessary to allow flushing those LSAs
        // later, since the interface address might change.
        if lsa.hdr.lsa_type.type_code() == Some(LsaTypeCode::Network)
            && lsa.hdr.adv_rtr == instance.state.router_id
        {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &mut arenas.areas[area_idx];
            if let Some((_, iface)) = area
                .interfaces
                .get_mut_by_addr(&mut arenas.interfaces, lsa.hdr.lsa_id)
            {
                if lsa.hdr.is_maxage() {
                    iface.state.network_lsa_self = None;
                } else {
                    iface.state.network_lsa_self = Some(lsa.hdr.key());
                }
            }
        }
    }
}

// ===== helper functions =====

fn lsa_orig_router(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Router-LSA's flags.
    let mut flags = LsaRouterFlags::empty();
    if arenas.areas.is_abr(&arenas.interfaces) {
        flags.insert(LsaRouterFlags::B);
    }

    // Router-LSA's links.
    let mut links = vec![];
    for iface in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip interfaces in the "Down" state.
        .filter(|iface| !iface.is_down())
    {
        let primary_addr = iface.system.primary_addr.unwrap();

        // Add Type-3 (stub) links to interfaces in Loopback state.
        if iface.state.ism_state == ism::State::Loopback {
            links.extend(iface.system.addr_list.iter().map(|addr| {
                LsaRouterLink::new(
                    LsaRouterLinkType::StubNetwork,
                    addr.ip(),
                    Ipv4Addr::BROADCAST,
                    0,
                )
            }));
            continue;
        }

        // When stub-router is configured (RFC 6987), set the cost of all
        // non-stub links to MaxLinkMetric.
        let non_stub_cost = if instance.config.stub_router {
            MAX_LINK_METRIC
        } else {
            iface.config.cost
        };

        let mut add_stub_links = false;
        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                // Add a Type-1 link (p2p) for each fully adjacent neighbor.
                for nbr in iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .filter(|nbr| nbr.state == nsm::State::Full)
                {
                    let link_data = if iface.system.unnumbered {
                        Ipv4Addr::from(iface.system.ifindex.unwrap())
                    } else {
                        primary_addr.ip()
                    };
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::PointToPoint,
                        nbr.router_id,
                        link_data,
                        non_stub_cost,
                    );
                    links.push(link);
                }

                // Add Type-3 (stub) links, unless the interface is unnumbered.
                if !iface.system.unnumbered {
                    add_stub_links = true;
                }
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                if iface.state.ism_state == ism::State::Waiting {
                    // Add Type-3 (stub) links.
                    add_stub_links = true;
                } else if (iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full))
                    || iface
                        .state
                        .dr
                        .and_then(|net_id| {
                            iface
                                .state
                                .neighbors
                                .get_by_net_id(&arenas.neighbors, net_id)
                                .filter(|(_, nbr)| {
                                    nbr.state == nsm::State::Full
                                })
                        })
                        .is_some()
                {
                    // Add a Type-2 (transit) link.
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::TransitNetwork,
                        iface.state.dr.unwrap().get(),
                        primary_addr.ip(),
                        non_stub_cost,
                    );
                    links.push(link);
                } else {
                    // Add Type-3 (stub) links.
                    add_stub_links = true;
                }
            }
        }

        if add_stub_links {
            links.extend(
                iface
                    .system
                    .addr_list
                    .iter()
                    .map(|addr| addr.apply_mask())
                    .map(|addr| {
                        LsaRouterLink::new(
                            LsaRouterLinkType::StubNetwork,
                            addr.ip(),
                            addr.mask(),
                            iface.config.cost,
                        )
                    }),
            );
        }
    }

    // (Re)originate Router-LSA.
    let lsa_body = LsaBody::Router(LsaRouter { flags, links });
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        instance.state.router_id,
        lsa_body,
    );
}

fn lsa_orig_network(
    iface: &Interface<Ospfv2>,
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // The Link State ID for a network-LSA is the IP interface address of the
    // Designated Router.
    let lsa_id = iface.system.primary_addr.unwrap().ip();

    // Network-LSA's mask.
    let mask = iface.system.primary_addr.unwrap().mask();

    // Network-LSA's attached routers.
    let myself = instance.state.router_id;
    let nbrs = iface
        .state
        .neighbors
        .iter(&arenas.neighbors)
        .filter(|nbr| nbr.state == nsm::State::Full)
        .map(|nbr| nbr.router_id);
    let attached_rtrs = std::iter::once(myself).chain(nbrs).collect();

    // (Re)originate Network-LSA.
    let lsa_body = LsaBody::Network(LsaNetwork {
        mask,
        attached_rtrs,
    });
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        lsa_id,
        lsa_body,
    );
}

fn lsa_flush_network(
    iface: &Interface<Ospfv2>,
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    if let Some(lsa_key) = &iface.state.network_lsa_self {
        lsa_flush_area(area, instance, &arenas.lsa_entries, lsa_key);
    }
}

fn lsa_orig_router_info(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Initialize Opaque LSA ID.
    let lsa_id = OpaqueLsaId::new(LsaOpaqueType::RouterInfo as u8, 0).into();

    let mut sr_algo = None;
    let mut srgb = vec![];
    let mut srlb = vec![];
    if instance.config.sr_enabled {
        // Fill in supported SR algorithms.
        sr_algo = Some(SrAlgoTlv::new([IgpAlgoType::Spf].into()));

        // Fill in local SRGB.
        for range in &sr_config.srgb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srgb.push(SidLabelRangeTlv::new(first, range));
        }

        // Fill in local SRLB.
        for range in &sr_config.srlb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srlb.push(SrLocalBlockTlv::new(first, range));
        }
    }

    // (Re)originate Router Information LSA.
    let mut info_caps = RouterInfoCaps::STUB_ROUTER;
    if instance.config.gr.helper_enabled {
        info_caps.insert(RouterInfoCaps::GR_HELPER);
    }
    let lsa_body = LsaBody::OpaqueArea(LsaOpaque::RouterInfo(LsaRouterInfo {
        info_caps: Some(RouterInfoCapsTlv::new(info_caps)),
        func_caps: None,
        sr_algo,
        srgb,
        srlb,
        msds: None,
        srms_pref: None,
        info_hostname: instance
            .shared
            .hostname
            .as_ref()
            .map(|hostname| DynamicHostnameTlv::new(hostname.to_string())),
        unknown_tlvs: vec![],
    }));
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        lsa_id,
        lsa_body,
    );
}

fn lsa_orig_ext_prefix(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Initialize prefixes.
    let mut prefixes = BTreeMap::new();
    if instance.config.sr_enabled {
        for ((prefix, algo), prefix_sid) in sr_config.prefix_sids.iter() {
            if let IpNetwork::V4(prefix) = prefix {
                let mut flags = LsaExtPrefixFlags::empty();
                if prefix.prefix() == 32 {
                    flags.insert(LsaExtPrefixFlags::N);
                }

                // Add Prefix-SID Sub-TLV.
                let mut psid_flags = PrefixSidFlags::empty();
                let mut prefix_sids = BTreeMap::new();
                match prefix_sid.last_hop {
                    SidLastHopBehavior::ExpNull => {
                        psid_flags.insert(PrefixSidFlags::NP);
                        psid_flags.insert(PrefixSidFlags::E);
                    }
                    SidLastHopBehavior::NoPhp => {
                        psid_flags.insert(PrefixSidFlags::NP);
                    }
                    SidLastHopBehavior::Php => (),
                }
                let sid = Sid::Index(prefix_sid.index);
                prefix_sids
                    .insert(*algo, PrefixSid::new(psid_flags, *algo, sid));

                prefixes.insert(
                    *prefix,
                    ExtPrefixTlv {
                        route_type: ExtPrefixRouteType::IntraArea,
                        af: 0,
                        flags,
                        prefix: *prefix,
                        prefix_sids,
                        unknown_tlvs: vec![],
                    },
                );
            }
        }
    }

    // (Re)originate as many Extended Prefix Opaque LSAs as necessary.
    let mut opaque_id: u32 = 0;
    let mut originate_fn = |prefixes| {
        // Initialize Opaque LSA ID.
        let lsa_id =
            OpaqueLsaId::new(LsaOpaqueType::ExtPrefix as u8, opaque_id).into();

        // (Re)originate Extended Prefix Opaque LSA.
        let lsa_body =
            LsaBody::OpaqueArea(LsaOpaque::ExtPrefix(LsaExtPrefix {
                prefixes,
            }));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        // Increment the Opaque ID.
        opaque_id += 1;
    };
    if prefixes.is_empty() {
        originate_fn(prefixes);
    } else {
        for prefixes in prefixes
            .into_iter()
            .chunks(
                (Lsa::<Ospfv2>::MAX_LENGTH - LsaHdr::LENGTH as usize)
                    / ExtPrefixTlv::BASE_LENGTH as usize,
            )
            .into_iter()
        {
            originate_fn(prefixes.collect());
        }
    }

    // Flush self-originated Extended Prefix Opaque LSAs that are no longer
    // needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaTypeCode::OpaqueArea.into(),
            instance.state.router_id,
        )
        .filter(|(_, lse)| {
            let opaque_lsa_id = OpaqueLsaId::from(lse.data.hdr.lsa_id);
            opaque_lsa_id.opaque_type == LsaOpaqueType::ExtPrefix as u8
                && opaque_lsa_id.opaque_id >= opaque_id
        })
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_ext_link(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Originate as many Extended Link Opaque LSAs as necessary.
    let mut opaque_id: u32 = 0;
    let mut originate_fn = |link_tlv| {
        // Initialize Opaque LSA ID.
        let lsa_id =
            OpaqueLsaId::new(LsaOpaqueType::ExtLink as u8, opaque_id).into();

        // (Re)originate Extended Link Opaque LSA.
        let lsa_body = LsaBody::OpaqueArea(LsaOpaque::ExtLink(LsaExtLink {
            link: Some(link_tlv),
        }));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        // Increment the Opaque ID.
        opaque_id += 1;
    };

    if instance.config.sr_enabled {
        for iface in area
            .interfaces
            .iter(&arenas.interfaces)
            // Skip interfaces in the "Down" state.
            .filter(|iface| !iface.is_down())
            // Skip loopback interfaces.
            .filter(|iface| iface.state.ism_state != ism::State::Loopback)
        {
            let primary_addr = iface.system.primary_addr.unwrap();
            match iface.config.if_type {
                InterfaceType::PointToPoint
                | InterfaceType::PointToMultipoint => {
                    for nbr in iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .filter(|nbr| nbr.state == nsm::State::Full)
                    {
                        let link_tlv = ExtLinkTlv::new(
                            LsaRouterLinkType::PointToPoint,
                            nbr.router_id,
                            primary_addr.ip(),
                            nbr.adj_sids.clone(),
                            None,
                        );
                        originate_fn(link_tlv);
                    }
                }
                InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                    if (iface.state.ism_state == ism::State::Dr
                        && iface
                            .state
                            .neighbors
                            .iter(&arenas.neighbors)
                            .any(|nbr| nbr.state == nsm::State::Full))
                        || iface
                            .state
                            .dr
                            .and_then(|net_id| {
                                iface
                                    .state
                                    .neighbors
                                    .get_by_net_id(&arenas.neighbors, net_id)
                                    .filter(|(_, nbr)| {
                                        nbr.state == nsm::State::Full
                                    })
                            })
                            .is_some()
                    {
                        let adj_sids = iface
                            .state
                            .neighbors
                            .iter(&arenas.neighbors)
                            .flat_map(|nbr| nbr.adj_sids.iter())
                            .copied()
                            .collect();
                        let link_tlv = ExtLinkTlv::new(
                            LsaRouterLinkType::TransitNetwork,
                            iface.state.dr.unwrap().get(),
                            primary_addr.ip(),
                            adj_sids,
                            None,
                        );
                        originate_fn(link_tlv);
                    };
                }
            }
        }
    }

    // Flush self-originated Extended Link Opaque LSAs that are no longer
    // needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaTypeCode::OpaqueArea.into(),
            instance.state.router_id,
        )
        .filter(|(_, lse)| {
            let opaque_lsa_id = OpaqueLsaId::from(lse.data.hdr.lsa_id);
            opaque_lsa_id.opaque_type == LsaOpaqueType::ExtLink as u8
                && opaque_lsa_id.opaque_id >= opaque_id
        })
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn process_self_originated_lsa(
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) -> Result<(), Error<Ospfv2>> {
    let mut flush = false;

    // Lookup LSDB and LSA entry.
    let (lsdb_idx, lsdb) = lsdb_get(
        &instance.state.lsdb,
        &arenas.areas,
        &arenas.interfaces,
        &lsdb_id.into(),
    )?;
    let (_, lse) = lsdb.get_by_id(&arenas.lsa_entries, lse_id)?;
    let lsa = &lse.data;

    // Check LSA type.
    match lsa.hdr.lsa_type.type_code() {
        Some(LsaTypeCode::Router) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Router-LSA.
            lsa_orig_router(area, instance, arenas);
        }
        Some(LsaTypeCode::Network) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Check if the router is still the DR for the network.
            if let Some(iface) = area
                .interfaces
                .iter(&arenas.interfaces)
                .find(|iface| {
                    iface.system.primary_addr.unwrap().ip() == lsa.hdr.lsa_id
                })
                .filter(|iface| iface.state.ism_state == ism::State::Dr)
                .filter(|_| {
                    // Ensure the Router-ID hasn't changed.
                    lsa.hdr.adv_rtr == instance.state.router_id
                })
            {
                // Reoriginate Network-LSA.
                lsa_orig_network(iface, area, instance, arenas);
            } else {
                // Flush Network-LSA.
                flush = true;
            }
        }
        Some(LsaTypeCode::SummaryNetwork | LsaTypeCode::SummaryRouter) => {
            // Do nothing. These LSAs will be either reoriginated or flushed
            // once SPF runs and the routing table is computed.
        }
        Some(LsaTypeCode::AsExternal) => {
            // Flush AS-External-LSA (redistribution of local routes isn't
            // supported at the moment).
            flush = true;
        }
        Some(
            LsaTypeCode::OpaqueLink
            | LsaTypeCode::OpaqueArea
            | LsaTypeCode::OpaqueAs,
        ) => {
            // Flush Opaque-LSA.
            flush = true;
        }
        None => {
            // Receiving self-originated LSAs of unknown type shouldn't happen
            // in practice. If it does, the LSA will be rejected early on before
            // it reaches this point.
            flush = true;
        }
    }

    if flush {
        // Effetively flush the received self-originated LSA.
        lsa_flush(instance, lsdb_id, lse_id);
    }

    Ok(())
}

fn lsa_flush_area(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    lsa_entries: &Arena<LsaEntry<Ospfv2>>,
    lsa_key: &LsaKey<LsaType>,
) {
    if let Some((_, lse)) = area.state.lsdb.get(lsa_entries, lsa_key) {
        let lsdb_id = LsdbId::Area(area.id);
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_flush(
    instance: &InstanceUpView<'_, Ospfv2>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) {
    instance.tx.protocol_input.lsa_flush(
        lsdb_id,
        lse_id,
        LsaFlushReason::PrematureAging,
    );
}
