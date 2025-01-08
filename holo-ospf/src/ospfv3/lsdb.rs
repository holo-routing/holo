//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{hash_map, BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use holo_utils::bier::{BierEncapsulationType, BierInBiftId, BiftId};
use holo_utils::ibus::{BierCfgEvent, SrCfgEvent};
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid, SidLastHopBehavior};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use tracing::debug;

use crate::area::{Area, AreaType, AreaVersion, OptionsLocation};
use crate::collections::{
    lsdb_get, AreaIndex, Arena, InterfaceIndex, LsaEntryId, LsdbId, LsdbIndex,
};
use crate::debug::LsaFlushReason;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{ism, Interface, InterfaceType};
use crate::lsdb::{LsaOriginateEvent, LsdbVersion, MAX_LINK_METRIC};
use crate::neighbor::nsm;
use crate::ospfv3::packet::lsa::{
    LsaBody, LsaFunctionCode, LsaHdr, LsaInterAreaPrefix, LsaInterAreaRouter,
    LsaIntraAreaPrefix, LsaIntraAreaPrefixEntry, LsaLink, LsaLinkPrefix,
    LsaNetwork, LsaRouter, LsaRouterFlags, LsaRouterInfo, LsaRouterLink,
    LsaRouterLinkType, LsaScopeCode, LsaType, PrefixOptions, PrefixSid,
};
use crate::ospfv3::packet::Options;
use crate::packet::lsa::{
    Lsa, LsaHdrVersion, LsaKey, LsaScope, LsaTypeVersion, PrefixSidVersion,
};
use crate::packet::tlv::{
    BierEncapId, BierEncapSubSubTlv, BierSubSubTlv, BierSubTlv,
    DynamicHostnameTlv, PrefixSidFlags, RouterInfoCaps, RouterInfoCapsTlv,
    SidLabelRangeTlv, SrAlgoTlv, SrLocalBlockTlv,
};
use crate::route::{SummaryNet, SummaryNetFlags, SummaryRtr};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl LsdbVersion<Self> for Ospfv3 {
    fn lsa_type_is_valid(
        area_type: Option<AreaType>,
        _nbr_options: Option<Options>,
        lsa_type: LsaType,
    ) -> bool {
        // Reject LSAs of unknown (reserved) scope.
        if lsa_type.scope() == LsaScope::Unknown {
            return false;
        }

        // Reject AS-scoped and type-4 summary LSAs (as per errata 3746 of RFC
        // 2328) on stub/NSSA areas.
        if let Some(area_type) = area_type {
            if area_type != AreaType::Normal
                && (lsa_type.scope() == LsaScope::As
                    || lsa_type.function_code_normalized()
                        == Some(LsaFunctionCode::InterAreaRouter))
            {
                return false;
            }
        }

        true
    }

    fn lsa_is_self_originated(
        lsa: &Lsa<Self>,
        router_id: Ipv4Addr,
        _interfaces: &Arena<Interface<Self>>,
    ) -> bool {
        // For IPv6, self-originated LSAs are those LSAs whose Advertising
        // Router is equal to the router's own Router ID.
        lsa.hdr.adv_rtr == router_id
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
            LsaOriginateEvent::InterfaceStateChange { area_id, iface_id } => {
                // (Re)originate Router-LSA(s) in all areas since the ABR status
                // might have changed.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }

                // (Re)originate or flush Network-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
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

                // (Re)originate or flush Link-LSA.
                if iface.state.ism_state >= ism::State::Waiting {
                    lsa_orig_link(iface, area, instance);
                } else {
                    lsa_flush_link(iface, area, instance, arenas);
                }

                // (Re)originate Intra-area-prefix-LSA(s).
                if iface.state.ism_state == ism::State::Dr {
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::InterfaceDrChange { area_id, iface_id }
            | LsaOriginateEvent::GrHelperExit { area_id, iface_id } => {
                // (Re)originate Router-LSA(s).
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

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceAddrAddDel { area_id, iface_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;

                if iface.state.ism_state >= ism::State::Waiting {
                    // (Re)originate or flush Link-LSA.
                    if iface.state.ism_state >= ism::State::Waiting {
                        lsa_orig_link(iface, area, instance);
                    } else {
                        lsa_flush_link(iface, area, instance, arenas);
                    }
                } else {
                    // (Re)originate Intra-area-prefix-LSA(s).
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::InterfaceCostChange { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // (Re)originate Router-LSA(s).
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::NeighborToFromFull { area_id, iface_id } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

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

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id, ..
            } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }

            LsaOriginateEvent::NeighborInterfaceIdChange {
                area_id, ..
            } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }
            LsaOriginateEvent::LinkLsaRcvd { area_id, iface_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if iface.state.ism_state == ism::State::Dr {
                    // (Re)originate Network-LSA.
                    if iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full)
                    {
                        lsa_orig_network(iface, area, instance, arenas);
                    }

                    // (Re)originate Intra-area-prefix-LSA(s).
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::SelfOriginatedLsaRcvd { lsdb_id, lse_id } => {
                // Check if the received self-originated LSA needs to be
                // reoriginated or flushed.
                process_self_originated_lsa(instance, arenas, lsdb_id, lse_id)?;
            }
            LsaOriginateEvent::StubRouterChange => {
                // (Re)originate Router-LSA(s) in all areas.
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
                // Reoriginate Router Information LSA(s) and
                // Intra-area-prefix-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                    lsa_orig_intra_area_prefix(area, instance, arenas);
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
                        if af == instance.state.af {
                            // (Re)originate Intra-area-prefix-LSA(s) in all
                            // areas.
                            for area in arenas.areas.iter() {
                                lsa_orig_intra_area_prefix(
                                    area, instance, arenas,
                                );
                            }
                        }
                    }
                }
            }
            LsaOriginateEvent::HostnameChange => {
                // (Re)originate Router-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::BierEnableChange => {
                // Reoriginate Intra-area-prefix-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::BierCfgChange { change } => match change {
                BierCfgEvent::EncapUpdate(af)
                | BierCfgEvent::SubDomainUpdate(af) => {
                    if af == instance.state.af {
                        for area in arenas.areas.iter() {
                            // Reoriginate Intra-area-prefix-LSA(s) in all areas.
                            lsa_orig_intra_area_prefix(area, instance, arenas);
                        }
                    }
                }
            },
        };

        Ok(())
    }

    fn lsa_orig_inter_area_network(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        prefix: IpNetwork,
        lsa_id: Option<u32>,
        summary: &SummaryNet<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);
        let extended_lsa = instance.config.extended_lsa;

        // Get LSA-ID.
        let lsa_id = match lsa_id {
            Some(lsa_id) => lsa_id,
            None => {
                area.state.version.next_type3_lsa_id += 1;
                area.state.version.next_type3_lsa_id
            }
        };

        // Get SR Prefix-SIDs.
        let mut prefix_sids = BTreeMap::new();
        if let Some(mut prefix_sid) = summary.prefix_sid {
            // For non-connected prefixes, disable Prefix-SID PHP to ensure
            // end-to-end MPLS forwarding.
            if summary.flags.contains(SummaryNetFlags::CONNECTED) {
                let flags = prefix_sid.flags_mut();
                flags.insert(PrefixSidFlags::NP);
                flags.remove(PrefixSidFlags::E);
            }

            prefix_sids.insert(IgpAlgoType::Spf, prefix_sid);
        }

        // (Re)originate Inter-Area-Network-LSA.
        let lsa_body = LsaBody::InterAreaPrefix(LsaInterAreaPrefix::new(
            extended_lsa,
            summary.metric,
            summary.prefix_options,
            prefix,
            prefix_sids,
        ));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        lsa_id
    }

    fn lsa_orig_inter_area_router(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        router_id: Ipv4Addr,
        lsa_id: Option<u32>,
        summary: &SummaryRtr<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);
        let extended_lsa = instance.config.extended_lsa;

        // Get LSA-ID.
        let lsa_id = match lsa_id {
            Some(lsa_id) => lsa_id,
            None => {
                area.state.version.next_type4_lsa_id += 1;
                area.state.version.next_type4_lsa_id
            }
        };

        // (Re)originate Inter-Area-Router-LSA.
        let lsa_body = LsaBody::InterAreaRouter(LsaInterAreaRouter::new(
            extended_lsa,
            summary.options,
            summary.metric,
            router_id,
        ));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        lsa_id
    }

    fn lsdb_get_by_lsa_type(
        iface_idx: InterfaceIndex,
        area_idx: AreaIndex,
        lsa_type: LsaType,
    ) -> LsdbIndex {
        match lsa_type.scope() {
            LsaScope::Link => LsdbIndex::Link(area_idx, iface_idx),
            LsaScope::Area => {
                if lsa_type.function_code().is_none() && !lsa_type.u_bit() {
                    LsdbIndex::Link(area_idx, iface_idx)
                } else {
                    LsdbIndex::Area(area_idx)
                }
            }
            LsaScope::As => {
                if lsa_type.function_code().is_none() && !lsa_type.u_bit() {
                    LsdbIndex::Link(area_idx, iface_idx)
                } else {
                    LsdbIndex::As
                }
            }
            LsaScope::Unknown => {
                unreachable!();
            }
        }
    }

    fn lsdb_install(
        instance: &mut InstanceUpView<'_, Self>,
        _arenas: &mut InstanceArenas<Self>,
        _lsdb_idx: LsdbIndex,
        lsdb_id: LsdbId,
        lsa: &Lsa<Self>,
    ) {
        // (Re)originate LSAs that might have been affected.
        if let LsdbId::Link(area_id, iface_id) = lsdb_id {
            if lsa.hdr.lsa_type().function_code_normalized()
                == Some(LsaFunctionCode::Link)
            {
                instance.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::LinkLsaRcvd { area_id, iface_id },
                );
            }
        }

        // Check for DynamicHostnameTlv
        if lsa.hdr.lsa_type.function_code_normalized()
            == Some(LsaFunctionCode::RouterInfo)
        {
            if let LsaBody::RouterInfo(router_info) = &lsa.body {
                if let Some(hostname_tlv) = router_info.info_hostname.as_ref() {
                    debug!(
                        "Router {} has hostname {}",
                        lsa.hdr.adv_rtr, hostname_tlv.hostname
                    );
                    instance
                        .state
                        .hostnames
                        .insert(lsa.hdr.adv_rtr, hostname_tlv.hostname.clone());
                } else {
                    instance.state.hostnames.remove(&lsa.hdr.adv_rtr);
                }
            }
        }
    }
}

// ===== helper functions =====

fn lsa_orig_router(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    // Router-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

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
        // Skip interfaces in the "Down" or "Loopback" states.
        .filter(|iface| {
            !matches!(
                iface.state.ism_state,
                ism::State::Down | ism::State::Loopback,
            )
        })
        // Skip interfaces without any full adjacencies.
        .filter(|iface| {
            iface
                .state
                .neighbors
                .iter(&arenas.neighbors)
                .any(|nbr| nbr.state == nsm::State::Full)
        })
    {
        let ifindex = iface.system.ifindex.unwrap();

        // When stub-router is configured (RFC 6987), set the cost of all
        // links to MaxLinkMetric.
        let cost = if instance.config.stub_router {
            MAX_LINK_METRIC
        } else {
            iface.config.cost
        };

        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                // Add a Type-1 link (p2p) for each fully adjacent neighbor.
                for nbr in iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .filter(|nbr| nbr.state == nsm::State::Full)
                {
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::PointToPoint,
                        cost,
                        ifindex,
                        nbr.iface_id.unwrap(),
                        nbr.router_id,
                        nbr.adj_sids.clone(),
                    );
                    links.push(link);
                }
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                let (dr_router_id, dr_iface_id) = if iface.state.ism_state
                    == ism::State::Dr
                {
                    // The router itself is the DR.
                    (instance.state.router_id, ifindex)
                } else {
                    match iface.state.dr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&arenas.neighbors, net_id)
                            .filter(|(_, nbr)| nbr.state == nsm::State::Full)
                    }) {
                        Some((_, nbr)) => {
                            // The router is fully adjacent to the DR.
                            (nbr.router_id, nbr.iface_id.unwrap())
                        }
                        None => continue,
                    }
                };

                // Add a Type-2 (transit) link.
                let adj_sids = iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .flat_map(|nbr| nbr.adj_sids.iter())
                    .copied()
                    .collect();
                let link = LsaRouterLink::new(
                    LsaRouterLinkType::TransitNetwork,
                    cost,
                    ifindex,
                    dr_iface_id,
                    dr_router_id,
                    adj_sids,
                );
                links.push(link);
            }
        }
    }

    // Originate as many Router-LSAs as necessary.
    let mut lsa_id: u32 = 0;
    let mut originate_fn = |links| {
        let lsa_body = LsaBody::Router(LsaRouter::new(
            extended_lsa,
            flags,
            options,
            links,
        ));

        // (Re)originate Router-LSA.
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        // Increment the LSA-ID.
        lsa_id += 1;
    };
    if links.is_empty() {
        originate_fn(links);
    } else {
        for links in links
            .into_iter()
            .chunks(
                (Lsa::<Ospfv3>::MAX_LENGTH
                    - LsaHdr::LENGTH as usize
                    - LsaRouter::BASE_LENGTH as usize)
                    / LsaRouterLink::max_length(extended_lsa),
            )
            .into_iter()
        {
            originate_fn(links.collect());
        }
    }

    // Flush self-originated Router-LSAs that are no longer needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaRouter::lsa_type(extended_lsa),
            instance.state.router_id,
        )
        .filter(|(_, lse)| lse.data.hdr.lsa_id >= Ipv4Addr::from(lsa_id))
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_network(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    // Network-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

    // An IPv6 network-LSA's Link State ID is set to the Interface ID of the
    // Designated Router on the link.
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());

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
    let lsa_body =
        LsaBody::Network(LsaNetwork::new(extended_lsa, options, attached_rtrs));
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn lsa_flush_network(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    let adv_rtr = instance.state.router_id;
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());
    let lsa_key =
        LsaKey::new(LsaNetwork::lsa_type(extended_lsa), adv_rtr, lsa_id);
    if let Some((_, lse)) = area.state.lsdb.get(&arenas.lsa_entries, &lsa_key) {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_link(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
) {
    let lsdb_id = LsdbId::Link(area.id, iface.id);
    let extended_lsa = instance.config.extended_lsa;

    // Link-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

    // The Link State ID is set to the router's Interface ID on Link L.
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());

    // Link-LSA's prefixes.
    let prefixes = iface
        .system
        .addr_list
        .iter()
        // Filter by address family.
        .filter(|addr| addr.address_family() == instance.state.af)
        // Filter out IPv6 link-local addresses.
        .filter(|addr| {
            if let IpAddr::V6(addr) = addr.ip() {
                !addr.is_unicast_link_local()
            } else {
                true
            }
        })
        .map(|addr| addr.apply_mask())
        .map(|addr| LsaLinkPrefix::new(PrefixOptions::empty(), addr))
        .collect();

    // Select link-local address.
    //
    // When routing for the IPv4 address-family, select the primary IPv4 address
    // of the interface.
    let linklocal = match instance.state.af {
        AddressFamily::Ipv4 => iface.system.addr_list.first().unwrap().ip(),
        AddressFamily::Ipv6 => iface.system.linklocal_addr.unwrap().ip().into(),
    };

    // (Re)originate Link-LSA.
    let lsa_body = LsaBody::Link(LsaLink::new(
        extended_lsa,
        iface.config.priority,
        options,
        linklocal,
        prefixes,
    ));
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn lsa_flush_link(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Link(area.id, iface.id);
    let extended_lsa = instance.config.extended_lsa;

    let adv_rtr = instance.state.router_id;
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());
    let lsa_key = LsaKey::new(LsaLink::lsa_type(extended_lsa), adv_rtr, lsa_id);
    if let Some((_, lse)) = iface.state.lsdb.get(&arenas.lsa_entries, &lsa_key)
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_intra_area_prefix(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let sr_config = &instance.shared.sr_config;
    let bier_config = &instance.shared.bier_config;
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;
    let adv_rtr = instance.state.router_id;
    let mut adv_list = vec![];

    // Router's attached stub links and looped-back interfaces.
    let mut prefixes = vec![];
    for (iface, prefix) in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip interfaces in the "Down" state.
        .filter(|iface| !iface.is_down())
        // Skip interfaces reported as transit networks in the Router-LSA.
        .filter(|iface| {
            !((iface.state.ism_state == ism::State::Dr
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
                            .filter(|(_, nbr)| nbr.state == nsm::State::Full)
                    })
                    .is_some())
        })
        // Get all interface addresses.
        .flat_map(|iface| {
            iface
                .system
                .addr_list
                .iter()
                .map(move |addr| (iface, addr.apply_mask()))
        })
        // Filter by address family.
        .filter(|(_, addr)| addr.address_family() == instance.state.af)
        // Filter out IPv6 link-local addresses.
        .filter(|(_, addr)| {
            if let IpAddr::V6(addr) = addr.ip() {
                !addr.is_unicast_link_local()
            } else {
                true
            }
        })
    {
        let mut entry = if iface.state.ism_state == ism::State::Loopback
            || iface.config.if_type == InterfaceType::PointToMultipoint
        {
            // If the interface type is point-to-multipoint or the interface is
            // in the state Loopback, the global scope IPv6 addresses associated
            // with the interface (if any) are copied into the
            // intra-area-prefix-LSA with the PrefixOptions LA-bit set, the
            // PrefixLength set to 128, and the metric set to 0.
            let plen = instance.state.af.max_prefixlen();
            let prefix = IpNetwork::new(prefix.ip(), plen).unwrap();
            let prefix_options = PrefixOptions::LA | PrefixOptions::N;
            LsaIntraAreaPrefixEntry::new(prefix_options, prefix, 0)
        } else {
            // Otherwise, the list of global prefixes configured in RTX for the
            // link are copied into the intra-area-prefix-LSA by specifying the
            // PrefixLength, PrefixOptions, and Address Prefix fields. The
            // Metric field for each of these prefixes is set to the interface's
            // output cost.
            LsaIntraAreaPrefixEntry::new(
                PrefixOptions::empty(),
                prefix,
                iface.config.cost,
            )
        };

        // Add Prefix-SID Sub-TLV.
        if instance.config.sr_enabled {
            if let Some(prefix_sid) =
                sr_config.prefix_sids.get(&(prefix, IgpAlgoType::Spf))
            {
                let mut flags = PrefixSidFlags::empty();
                match prefix_sid.last_hop {
                    SidLastHopBehavior::ExpNull => {
                        flags.insert(PrefixSidFlags::NP);
                        flags.insert(PrefixSidFlags::E);
                    }
                    SidLastHopBehavior::NoPhp => {
                        flags.insert(PrefixSidFlags::NP);
                    }
                    SidLastHopBehavior::Php => (),
                }
                let algo = IgpAlgoType::Spf;
                let sid = Sid::Index(prefix_sid.index);
                entry
                    .prefix_sids
                    .insert(algo, PrefixSid::new(flags, algo, sid));
            }
        }

        // Add BIER Sub-TLV(s) if BIER is enabled and allowed to advertise
        if instance.config.bier.enabled && instance.config.bier.advertise {
            bier_config
                .sd_cfg
                .iter()
                // Search for subdomain configuration(s) for current prefix
                .filter(|((_, af), sd_cfg)| {
                    af == &AddressFamily::Ipv6 && sd_cfg.bfr_prefix == prefix
                })
                .for_each(|((sd_id, _), sd_cfg)| {
                    // BIER prefix has configured encap ?
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
                                .map(|id| {
                                    BierEncapId::NonMpls(BiftId::new(id))
                                }),
                            }
                            .map(|id| {
                                BierSubSubTlv::BierEncapSubSubTlv(
                                    BierEncapSubSubTlv::new(
                                        encap.max_si,
                                        id,
                                        (*bsl).into(),
                                    ),
                                )
                            })
                        })
                        .collect::<Vec<BierSubSubTlv>>();

                    let bier = BierSubTlv::new(
                        *sd_id,
                        sd_cfg.mt_id,
                        sd_cfg.bfr_id,
                        sd_cfg.bar,
                        sd_cfg.ipa,
                        bier_encaps,
                    );

                    entry.bier.push(bier);
                });
        }

        prefixes.push(entry);
    }
    let ref_lsa = LsaKey::new(
        LsaRouter::lsa_type(extended_lsa),
        adv_rtr,
        Ipv4Addr::from(0),
    );
    adv_list.push((ref_lsa, prefixes));

    // Designated Router's attached links.
    for iface in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip non-DR interfaces.
        .filter(|iface| iface.state.ism_state == ism::State::Dr)
    {
        let mut prefixes = HashMap::new();
        for prefix in iface
            .state
            .lsdb
            // Get all interface Link-LSAs.
            .iter_by_type(&arenas.lsa_entries, LsaLink::lsa_type(extended_lsa))
            .map(|(_, lse)| &lse.data)
            // Check if the link-LSA's Advertising Router is fully adjacent to
            // the DR and the Link State ID matches the neighbor's interface ID.
            .filter(|lsa| {
                iface
                    .state
                    .neighbors
                    .get_by_router_id(&arenas.neighbors, lsa.hdr.adv_rtr)
                    .filter(|(_, nbr)| nbr.state == nsm::State::Full)
                    .filter(|(_, nbr)| {
                        lsa.hdr.lsa_id == Ipv4Addr::from(nbr.iface_id.unwrap())
                    })
                    .is_some()
            })
            // Get all Link-LSA prefixes.
            .flat_map(|lsa| {
                let link_lsa = lsa.body.as_link().unwrap();
                link_lsa.prefixes.iter().cloned()
            })
            // Filter out prefixes with the NU/LA options.
            .filter(|prefix| {
                !prefix
                    .options
                    .intersects(PrefixOptions::NU | PrefixOptions::LA)
            })
            // Filter out IPv6 link-local addresses.
            .filter(|prefix| {
                if let IpAddr::V6(addr) = prefix.value.ip() {
                    !addr.is_unicast_link_local()
                } else {
                    true
                }
            })
        {
            match prefixes.entry(prefix.value) {
                hash_map::Entry::Occupied(mut o) => {
                    // PrefixOptions fields should be logically OR'ed together.
                    *o.get_mut() |= prefix.options;
                }
                hash_map::Entry::Vacant(v) => {
                    v.insert(prefix.options);
                }
            }
        }

        let ref_lsa = LsaKey::new(
            LsaNetwork::lsa_type(extended_lsa),
            adv_rtr,
            Ipv4Addr::from(iface.system.ifindex.unwrap()),
        );
        let prefixes = prefixes
            .into_iter()
            // The Metric field for all prefixes is set to 0.
            .map(|(prefix, prefix_options)| {
                LsaIntraAreaPrefixEntry::new(prefix_options, prefix, 0)
            })
            .collect();
        adv_list.push((ref_lsa, prefixes));
    }

    // Originate as many Intra-Area-Prefix-LSAs as necessary.
    let mut lsa_id: u32 = 0;
    let mut originate_fn = |ref_lsa: LsaKey<LsaType>, prefixes| {
        let lsa_body = LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix::new(
            extended_lsa,
            ref_lsa.lsa_type,
            ref_lsa.lsa_id,
            ref_lsa.adv_rtr,
            prefixes,
        ));

        // (Re)originate Intra-Area-Prefix-LSA.
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        // Increment the LSA-ID.
        lsa_id += 1;
    };
    for (ref_lsa, prefixes) in adv_list {
        if prefixes.is_empty() {
            originate_fn(ref_lsa, prefixes);
        } else {
            for prefixes in prefixes
                .into_iter()
                .chunks(
                    (Lsa::<Ospfv3>::MAX_LENGTH
                        - LsaHdr::LENGTH as usize
                        - LsaIntraAreaPrefix::BASE_LENGTH as usize)
                        / LsaIntraAreaPrefixEntry::max_length(extended_lsa),
                )
                .into_iter()
            {
                originate_fn(ref_lsa, prefixes.collect());
            }
        }
    }

    // Flush self-originated Intra-Area-Prefix-LSAs that are no longer needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaIntraAreaPrefix::lsa_type(extended_lsa),
            adv_rtr,
        )
        .filter(|(_, lse)| lse.data.hdr.lsa_id >= Ipv4Addr::from(lsa_id))
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_router_info(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);
    let lsa_id = Ipv4Addr::from(0);

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
    let scope = LsaScopeCode::Area;
    let mut info_caps = RouterInfoCaps::STUB_ROUTER;
    if instance.config.gr.helper_enabled {
        info_caps.insert(RouterInfoCaps::GR_HELPER);
    }
    let lsa_body = LsaBody::RouterInfo(LsaRouterInfo {
        scope,
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
    });
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn process_self_originated_lsa(
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) -> Result<(), Error<Ospfv3>> {
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
    match lsa.hdr.lsa_type.function_code() {
        Some(LsaFunctionCode::Router) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Router-LSA.
            lsa_orig_router(area, instance, arenas);
        }
        Some(LsaFunctionCode::Network) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Check if the router is still the DR for the network.
            if let Some(iface) = area
                .interfaces
                .iter(&arenas.interfaces)
                .find(|iface| {
                    iface.system.ifindex == Some(u32::from(lsa.hdr.lsa_id) as _)
                })
                .filter(|iface| iface.state.ism_state == ism::State::Dr)
            {
                // Reoriginate Network-LSA.
                lsa_orig_network(iface, area, instance, arenas);
            } else {
                // Flush Network-LSA.
                flush = true;
            }
        }
        Some(
            LsaFunctionCode::InterAreaPrefix | LsaFunctionCode::InterAreaRouter,
        ) => {
            // Do nothing. These LSAs will be either reoriginated or flushed
            // once SPF runs and the routing table is computed.
        }
        Some(LsaFunctionCode::AsExternal) => {
            // Flush AS-External-LSA (redistribution of local routes isn't
            // supported at the moment).
            flush = true;
        }
        Some(LsaFunctionCode::Link) => {
            let (area_idx, iface_idx) = lsdb_idx.into_link().unwrap();
            let area = &arenas.areas[area_idx];
            let iface = &arenas.interfaces[iface_idx];

            if iface.state.ism_state >= ism::State::Waiting {
                // Reoriginate Link-LSA.
                lsa_orig_link(iface, area, instance);
            } else {
                // Flush Link-LSA.
                flush = true;
            }
        }
        Some(LsaFunctionCode::IntraAreaPrefix) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Intra-area-prefix-LSA(s).
            lsa_orig_intra_area_prefix(area, instance, arenas);
        }
        Some(LsaFunctionCode::RouterInfo) => {
            // Flush Router-Information-LSA.
            flush = true;
        }
        _ => {
            // Flush unknown LSA.
            flush = true;
        }
    }

    if flush {
        // Effetively flush the received self-originated LSA.
        lsa_flush(instance, lsdb_id, lse_id);
    }

    Ok(())
}

fn lsa_flush(
    instance: &InstanceUpView<'_, Ospfv3>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) {
    instance.tx.protocol_input.lsa_flush(
        lsdb_id,
        lse_id,
        LsaFlushReason::PrematureAging,
    );
}
