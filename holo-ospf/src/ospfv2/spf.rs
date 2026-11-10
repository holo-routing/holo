//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use enum_as_inner::EnumAsInner;
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt};
use holo_utils::sr::PrefixSidAlgo;
use ipnetwork::Ipv4Network;

use crate::area::Area;
use crate::collections::{Arena, Lsdb};
use crate::error::Error;
use crate::interface::{Interface, InterfaceType};
use crate::lsdb::LsaEntry;
use crate::neighbor::Neighbor;
use crate::ospfv2::packet::iana::{
    LsaRouterFlags, LsaRouterLinkType, LsaTypeCode, Options,
};
use crate::ospfv2::packet::lsa::{
    LsaAsExternalFlags, LsaBody, LsaRouterLink, LsaType, kind,
};
use crate::ospfv2::packet::lsa_opaque::{
    ExtPrefixRouteType, LsaOpaque, PrefixSid,
};
use crate::packet::lsa::{LsaHdrVersion, LsaKey, TypedLsa};
use crate::route::{Nexthop, NexthopKey, Nexthops};
use crate::spf::{
    SpfComputation, SpfExternalNetwork, SpfInterAreaNetwork,
    SpfInterAreaRouter, SpfIntraAreaNetwork, SpfPartialComputation,
    SpfRouterInfo, SpfTriggerLsa, SpfVersion, Vertex, VertexEdgeVersion,
    VertexIdVersion, VertexLsaVersion,
};
use crate::version::Ospfv2;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VertexId {
    Network { dr_addr: Ipv4Addr },
    Router { router_id: Ipv4Addr },
}

#[derive(Clone, Debug, EnumAsInner)]
pub enum VertexLsa {
    Network(VertexLsaNetwork),
    Router(VertexLsaRouter),
}

// Network-LSA of a network vertex.
pub type VertexLsaNetwork = TypedLsa<Ospfv2, kind::Network>;

// Router-LSA of a router vertex.
pub type VertexLsaRouter = TypedLsa<Ospfv2, kind::Router>;

// Edge from a vertex to one of its neighbors, along with the neighbor's LSA.
#[derive(Debug)]
pub enum VertexEdge<'a> {
    // Router-LSA link to a router or transit network.
    Router {
        // Position of the link among the non-stub links of the Router-LSA.
        link_pos: usize,
        link: &'a LsaRouterLink,
        dest: VertexLsa,
    },
    // Router attached to a transit network.
    Network {
        network: &'a VertexLsaNetwork,
        dest: VertexLsaRouter,
    },
}

// ===== impl VertexId =====

impl VertexIdVersion for VertexId {
    fn new_root(router_id: Ipv4Addr) -> Self {
        VertexId::Router { router_id }
    }

    fn is_router(&self) -> bool {
        matches!(self, VertexId::Router { .. })
    }
}

// ===== impl VertexLsa =====

impl VertexLsaVersion<Ospfv2> for VertexLsa {
    fn router(&self) -> Option<(Ipv4Addr, Options, LsaRouterFlags)> {
        let lsa = self.as_router()?;
        Some((lsa.hdr.adv_rtr, lsa.hdr.options, lsa.body().flags))
    }

    fn origin(&self) -> LsaKey<LsaType> {
        match self {
            VertexLsa::Network(lsa) => lsa.hdr.key(),
            VertexLsa::Router(lsa) => lsa.hdr.key(),
        }
    }
}

// ===== impl VertexLsa =====

impl VertexLsa {
    // Returns the ID of the vertex.
    fn id(&self) -> VertexId {
        match self {
            VertexLsa::Network(lsa) => lsa.id(),
            VertexLsa::Router(lsa) => lsa.id(),
        }
    }

    // Returns whether the vertex's LSA has a link to the given vertex.
    fn links_to(&self, vertex_id: VertexId) -> bool {
        match self {
            VertexLsa::Network(lsa) => lsa.links_to(vertex_id),
            VertexLsa::Router(lsa) => lsa.links_to(vertex_id),
        }
    }
}

// ===== impl VertexLsaNetwork =====

impl VertexLsaNetwork {
    // Returns the ID of the network vertex.
    fn id(&self) -> VertexId {
        VertexId::Network {
            dr_addr: self.hdr.lsa_id,
        }
    }

    // Returns whether the Network-LSA lists the given vertex as an attached
    // router.
    fn links_to(&self, vertex_id: VertexId) -> bool {
        self.body().attached_rtrs.iter().any(|router_id| {
            VertexId::Router {
                router_id: *router_id,
            } == vertex_id
        })
    }
}

// ===== impl VertexLsaRouter =====

impl VertexLsaRouter {
    // Finds the Router-LSA of the given router.
    fn find(
        router_id: Ipv4Addr,
        area: &Area<Ospfv2>,
        lsa_entries: &Arena<LsaEntry<Ospfv2>>,
    ) -> Option<VertexLsaRouter> {
        let lsa_key =
            LsaKey::new(LsaTypeCode::Router.into(), router_id, router_id);
        area.state
            .lsdb
            .get(lsa_entries, &lsa_key)
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .and_then(TypedLsa::new)
    }

    // Returns the ID of the router vertex.
    fn id(&self) -> VertexId {
        VertexId::Router {
            router_id: self.hdr.adv_rtr,
        }
    }

    // Returns whether the Router-LSA has a link to the given vertex.
    fn links_to(&self, vertex_id: VertexId) -> bool {
        self.body()
            .links
            .iter()
            .filter_map(link_vertex_id)
            .any(|link_vid| link_vid == vertex_id)
    }
}

// ===== impl VertexEdge =====

impl VertexEdgeVersion<Ospfv2> for VertexEdge<'_> {
    fn id(&self) -> VertexId {
        match self {
            VertexEdge::Router { dest, .. } => dest.id(),
            VertexEdge::Network { dest, .. } => dest.id(),
        }
    }

    fn cost(&self) -> u16 {
        match self {
            VertexEdge::Router { link, .. } => link.metric,
            VertexEdge::Network { .. } => 0,
        }
    }

    fn links_back_to(&self, vertex_id: VertexId) -> bool {
        match self {
            VertexEdge::Router { dest, .. } => dest.links_to(vertex_id),
            VertexEdge::Network { dest, .. } => dest.links_to(vertex_id),
        }
    }

    fn vertex_lsa(&self) -> VertexLsa {
        match self {
            VertexEdge::Router { dest, .. } => dest.clone(),
            VertexEdge::Network { dest, .. } => VertexLsa::Router(dest.clone()),
        }
    }
}

// ===== impl Ospfv2 =====

impl SpfVersion<Self> for Ospfv2 {
    type VertexId = VertexId;
    type VertexLsa = VertexLsa;
    type VertexEdge<'a> = VertexEdge<'a>;

    fn spf_computation_type(
        trigger_lsas: &[SpfTriggerLsa<Self>],
    ) -> SpfComputation<Self> {
        // Router-LSA and Network-LSA changes represent topological changes,
        // hence a full SPF run is required to recompute the SPT.
        //
        // Certain Opaque-LSA changes don't strictly require a full SPF run, but
        // doing so greatly simplify things (e.g. no need to keep track of which
        // routes are affected by which SRGBs).
        if trigger_lsas.iter().map(|tlsa| &tlsa.new).any(|lsa| {
            matches!(
                lsa.body,
                LsaBody::Router(_)
                    | LsaBody::Network(_)
                    | LsaBody::OpaqueArea(
                        LsaOpaque::RouterInfo(_)
                            | LsaOpaque::ExtPrefix(_)
                            | LsaOpaque::ExtLink(_)
                    )
                    | LsaBody::OpaqueAs(LsaOpaque::ExtPrefix(_))
            )
        }) {
            return SpfComputation::Full;
        }

        // In OSPFv2 intra-area information is embedded in Router-LSAs and
        // Network-LSAs.
        let intra = Default::default();

        // Check Type-3 Summary LSA changes.
        let inter_network = trigger_lsas
            .iter()
            .flat_map(SpfTriggerLsa::old_and_new)
            .filter_map(|lsa| {
                lsa.body
                    .as_summary_network()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .filter_map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask).ok()
            })
            .collect();

        // Check Type-4 Summary LSA changes.
        let inter_router = trigger_lsas
            .iter()
            .flat_map(SpfTriggerLsa::old_and_new)
            .filter_map(|lsa| lsa.body.as_summary_router().map(|_| lsa.hdr))
            .map(|lsa_hdr| lsa_hdr.lsa_id)
            .collect::<BTreeSet<_>>();

        // Check AS-External LSA changes.
        let external = trigger_lsas
            .iter()
            .flat_map(SpfTriggerLsa::old_and_new)
            .filter_map(|lsa| {
                lsa.body
                    .as_as_external()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .filter_map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask).ok()
            })
            .collect();

        SpfComputation::Partial(SpfPartialComputation {
            intra,
            inter_network,
            inter_router,
            external,
        })
    }

    fn calc_nexthops(
        area: &Area<Self>,
        parent: &Vertex<Self>,
        edge: &VertexEdge<'_>,
        interfaces: &Arena<Interface<Self>>,
        neighbors: &Arena<Neighbor<Self>>,
        _extended_lsa: bool,
        _lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Result<Nexthops<Ipv4Addr>, Error<Self>> {
        let mut nexthops = Nexthops::new();
        let dest_id = edge.id();

        match edge {
            // The parent vertex is the root.
            VertexEdge::Router {
                link_pos: parent_link_pos,
                dest: dest_lsa,
                ..
            } => {
                // The destination is either a directly connected network or
                // directly connected router.

                // Get nexthop interface based on the parent's Router-LSA link
                // position.
                let (iface_idx, iface) = area
                    .interfaces
                    .indexes()
                    .map(|iface_idx| (iface_idx, &interfaces[iface_idx]))
                    .filter(|(_, iface)| iface.state.neighbors.count() > 0)
                    .nth(*parent_link_pos)
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // If the interface is a virtual link, do not resolve the
                // nexthop here. Virtual link nexthops are handled later,
                // as specified in RFC 2328 section 16.3.
                if iface.is_virtual_link() {
                    return Ok(nexthops);
                }

                match dest_lsa {
                    VertexLsa::Router(dest_lsa) => {
                        // Add nexthop(s).
                        match iface.config.if_type {
                            InterfaceType::PointToPoint
                            | InterfaceType::VirtualLink => {
                                // RFC 2328 assumes that routes using
                                // point-to-point interfaces don't need a
                                // nexthop address. In practice, however, it's
                                // common to use the point-to-point mode on
                                // multi-access links such as Ethernet, so a
                                // nexthop address is required.
                                //
                                // To determine the nexthop address, we use the
                                // neighbor's source address. Examining the
                                // destination's Router-LSA to find the link
                                // pointing back to the calculating router
                                // wouldn't work for unnumbered interfaces.
                                let nbr_router_id = dest_lsa.hdr.adv_rtr;
                                let (_, nbr) = iface
                                    .state
                                    .neighbors
                                    .get_by_router_id(neighbors, nbr_router_id)
                                    .ok_or(Error::SpfNexthopCalcError(
                                        dest_id,
                                    ))?;
                                let nexthop_addr = nbr.src;

                                nexthops.insert(
                                    NexthopKey::new(
                                        iface_idx,
                                        Some(nexthop_addr),
                                    ),
                                    Nexthop::new(
                                        iface_idx,
                                        Some(nexthop_addr),
                                        Some(nbr_router_id),
                                    ),
                                );
                            }
                            InterfaceType::PointToMultipoint => {
                                // If the destination is a router which connects
                                // to the calculating router via a
                                // Point-to-MultiPoint network, the
                                // destination's next hop IP address(es) can be
                                // determined by examining the destination's
                                // router-LSA: each link pointing back to the
                                // calculating router and having a Link Data
                                // field belonging to the Point-to-MultiPoint
                                // network provides an IP address of the next
                                // hop router.
                                nexthops.extend(
                                    dest_lsa
                                        .body()
                                        .links
                                        .iter()
                                        .filter(|link| {
                                            iface
                                                .system
                                                .contains_addr(&link.link_data)
                                        })
                                        .map(|link| {
                                            let nexthop_addr = link.link_data;
                                            let nbr_router_id =
                                                dest_lsa.hdr.adv_rtr;
                                            (
                                                NexthopKey::new(
                                                    iface_idx,
                                                    Some(nexthop_addr),
                                                ),
                                                Nexthop::new(
                                                    iface_idx,
                                                    Some(nexthop_addr),
                                                    Some(nbr_router_id),
                                                ),
                                            )
                                        }),
                                );
                            }
                            _ => {}
                        }
                        if nexthops.is_empty() {
                            return Err(Error::SpfNexthopCalcError(dest_id));
                        }
                    }
                    VertexLsa::Network(_lsa) => {
                        // Add nexthop.
                        nexthops.insert(
                            NexthopKey::new(iface_idx, None),
                            Nexthop::new(iface_idx, None, None),
                        );
                    }
                }
            }
            // The parent vertex is a network that directly connects the
            // calculating router to the destination router.
            VertexEdge::Network {
                network: parent_lsa,
                dest: dest_lsa,
            } => {
                // The list of next hops is then determined by examining the
                // destination's router-LSA. For each link in the router-LSA
                // that points back to the parent network, the link's Link
                // Data field provides the IP address of a next hop router.
                let parent_network = Ipv4Network::with_netmask(
                    parent_lsa.hdr.lsa_id,
                    parent_lsa.body().mask,
                )
                .map_err(|_| Error::SpfNexthopCalcError(dest_id))?;
                let dest_link = dest_lsa
                    .body()
                    .links
                    .iter()
                    .find(|link| parent_network.contains(link.link_data))
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // Inherit outgoing interface from the parent network.
                let iface_idx = parent
                    .nexthops
                    .values()
                    .next()
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?
                    .iface_idx;

                // Get nexthop address.
                let nbr_router_id = dest_lsa.hdr.adv_rtr;
                let nexthop_addr = dest_link.link_data;

                // Add nexthop.
                nexthops.insert(
                    NexthopKey::new(iface_idx, Some(nexthop_addr)),
                    Nexthop::new(
                        iface_idx,
                        Some(nexthop_addr),
                        Some(nbr_router_id),
                    ),
                );
            }
        }

        Ok(nexthops)
    }

    fn vertex_lsa_find(
        _af: AddressFamily,
        id: VertexId,
        area: &Area<Self>,
        _extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<VertexLsa> {
        match id {
            VertexId::Network { dr_addr } => {
                // For OSPFv2, SPF needs to find a Network-LSA knowing only its
                // LS-ID but not its advertising router.
                area.state
                    .lsdb
                    .iter_by_type(lsa_entries, LsaTypeCode::Network.into())
                    .map(|(_, lse)| &lse.data)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .find(|lsa| lsa.hdr.lsa_id == dr_addr)
                    .and_then(TypedLsa::new)
                    .map(VertexLsa::Network)
            }
            VertexId::Router { router_id } => {
                VertexLsaRouter::find(router_id, area, lsa_entries)
                    .map(VertexLsa::Router)
            }
        }
    }

    fn vertex_edges<'a>(
        vertex_lsa: &'a VertexLsa,
        af: AddressFamily,
        area: &'a Area<Ospfv2>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Ospfv2>>,
    ) -> Box<dyn Iterator<Item = VertexEdge<'a>> + 'a> {
        match vertex_lsa {
            VertexLsa::Network(lsa) => {
                let iter = lsa.body().attached_rtrs.iter().filter_map(
                    move |router_id| {
                        let dest = VertexLsaRouter::find(
                            *router_id,
                            area,
                            lsa_entries,
                        )?;
                        Some(VertexEdge::Network { network: lsa, dest })
                    },
                );
                Box::new(iter)
            }
            VertexLsa::Router(lsa) => {
                let iter = lsa
                    .body()
                    .links
                    .iter()
                    .filter_map(|link| {
                        link_vertex_id(link).map(|link_vid| (link, link_vid))
                    })
                    .enumerate()
                    .filter_map(move |(link_pos, (link, link_vid))| {
                        let dest = Ospfv2::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            false,
                            lsa_entries,
                        )?;
                        Some(VertexEdge::Router {
                            link_pos,
                            link,
                            dest,
                        })
                    });
                Box::new(iter)
            }
        }
    }

    fn intra_area_networks<'a>(
        area: &'a Area<Self>,
        _extended_lsa: bool,
        _lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfIntraAreaNetwork<'a, Self>> + 'a {
        let mut stubs = vec![];

        for vertex in area.state.spt.values() {
            match &vertex.lsa {
                VertexLsa::Network(lsa) => {
                    let Some(prefix) = Ipv4Network::with_netmask(
                        lsa.hdr.lsa_id,
                        lsa.body().mask,
                    )
                    .ok() else {
                        continue;
                    };
                    let prefix = prefix.apply_mask();
                    let prefix_sids = route_prefix_sids(
                        area,
                        lsa.hdr.adv_rtr,
                        &prefix,
                        ExtPrefixRouteType::IntraArea,
                    );

                    stubs.push(SpfIntraAreaNetwork {
                        vertex,
                        prefix,
                        prefix_options: Default::default(),
                        metric: 0,
                        prefix_sids,
                        // FIXME: BIER not supported yet for OSPFv2
                        bier: Default::default(),
                    });
                }
                VertexLsa::Router(lsa) => {
                    stubs.extend(
                        lsa.body()
                            .links
                            .iter()
                            .filter(|link| {
                                link.link_type == LsaRouterLinkType::StubNetwork
                            })
                            .filter_map(|link| {
                                let prefix = Ipv4Network::with_netmask(
                                    link.link_id,
                                    link.link_data,
                                )
                                .ok()?;
                                let prefix = prefix.apply_mask();
                                let metric = link.metric;
                                let prefix_sids = route_prefix_sids(
                                    area,
                                    lsa.hdr.adv_rtr,
                                    &prefix,
                                    ExtPrefixRouteType::IntraArea,
                                );

                                Some(SpfIntraAreaNetwork {
                                    vertex,
                                    prefix,
                                    prefix_options: Default::default(),
                                    metric,
                                    prefix_sids,
                                    // FIXME: BIER not supported yet for OSPFv2
                                    bier: Default::default(),
                                })
                            }),
                    )
                }
            }
        }

        stubs.into_iter()
    }

    fn inter_area_networks<'a>(
        area: &'a Area<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaNetwork<Self>> + 'a {
        area.state
            .lsdb
            .iter_typed(lsa_entries, kind::SummaryNetwork)
            .filter(|(lsa_hdr, _)| !lsa_hdr.is_maxage())
            .filter_map(|(lsa_hdr, lsa_body)| {
                let prefix =
                    Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask)
                        .ok()?;
                let prefix_sids = route_prefix_sids(
                    area,
                    lsa_hdr.adv_rtr,
                    &prefix,
                    ExtPrefixRouteType::InterArea,
                );

                Some(SpfInterAreaNetwork {
                    adv_rtr: lsa_hdr.adv_rtr,
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    prefix_sids,
                })
            })
    }

    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaRouter<Self>> + 'a {
        lsdb.iter_typed(lsa_entries, kind::SummaryRouter)
            .filter(|(lsa_hdr, _)| !lsa_hdr.is_maxage())
            .map(|(lsa_hdr, lsa_body)| SpfInterAreaRouter {
                adv_rtr: lsa_hdr.adv_rtr,
                router_id: lsa_hdr.lsa_id,
                options: lsa_hdr.options,
                flags: LsaRouterFlags::E,
                metric: lsa_body.metric,
            })
    }

    fn external_networks<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfExternalNetwork<Self>> + 'a {
        lsdb.iter_typed(lsa_entries, kind::AsExternal)
            .filter(|(lsa_hdr, _)| !lsa_hdr.is_maxage())
            .filter_map(|(lsa_hdr, lsa_body)| {
                let prefix =
                    Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask)
                        .ok()?;

                Some(SpfExternalNetwork {
                    adv_rtr: lsa_hdr.adv_rtr,
                    e_bit: lsa_body.flags.contains(LsaAsExternalFlags::E),
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    fwd_addr: lsa_body.fwd_addr,
                    tag: Some(lsa_body.tag),
                })
            })
    }

    fn area_router_information<'a>(
        lsdb: &'a Lsdb<Self>,
        router_id: Ipv4Addr,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> SpfRouterInfo<'a> {
        let mut ri_agg = SpfRouterInfo::default();

        for ri_lsa in lsdb
            .iter_typed_advrtr(lsa_entries, kind::OpaqueArea, router_id)
            .filter(|(lsa_hdr, _)| !lsa_hdr.is_maxage())
            .filter_map(|(_, lsa_body)| lsa_body.as_router_info())
        {
            if let Some(sr_algo) = &ri_lsa.sr_algo {
                // When multiple SR-Algorithm TLVs are received from a given
                // router, the receiver MUST use the first occurrence of the TLV
                // in the Router Information Opaque LSA.
                //
                // If the SR-Algorithm TLV appears in multiple RI Opaque LSAs
                // that have the same flooding scope, the SR-Algorithm TLV in RI
                // Opaque LSA with the numerically smallest Instance ID MUST be
                // used and subsequent instances of the SR-Algorithm TLV MUST be
                // ignored.
                ri_agg.sr_algo.get_or_insert(sr_algo);
            }

            // Multiple occurrences of the SID/Label Range TLV MAY be advertised
            // in order to advertise multiple ranges.
            ri_agg.srgb.extend(&ri_lsa.srgb);
        }

        ri_agg
    }

    fn area_opaque_data_compile(
        area: &mut Area<Self>,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) {
        area.state.version.ext_prefix_db.clear();

        for (lsa_hdr, lsa_body) in area
            .state
            .lsdb
            .iter_typed(lsa_entries, kind::OpaqueArea)
            .filter(|(lsa_hdr, _)| !lsa_hdr.is_maxage())
        {
            if let Some(lsa_body) = lsa_body.as_ext_prefix() {
                // If this TLV is advertised multiple times for the same prefix
                // in different OSPFv2 Extended Prefix Opaque LSAs originated by
                // the same OSPFv2 router, the OSPFv2 advertising router is
                // re-originating OSPFv2 Extended Prefix Opaque LSAs for
                // multiple prefixes and is most likely repacking
                // Extended-Prefix-TLVs in OSPFv2 Extended Prefix Opaque LSAs.
                // In this case, the Extended-Prefix-TLV in the OSPFv2 Extended
                // Prefix Opaque LSA with the smallest Opaque ID is used by
                // receiving OSPFv2 routers.
                for (prefix, tlv) in &lsa_body.prefixes {
                    area.state
                        .version
                        .ext_prefix_db
                        .entry((lsa_hdr.adv_rtr, *prefix))
                        .or_insert_with(|| tlv.clone());
                }
            }
        }
    }
}

// ===== helper functions =====

// Returns the ID of the vertex a Router-LSA link points to, if any.
fn link_vertex_id(link: &LsaRouterLink) -> Option<VertexId> {
    match link.link_type {
        LsaRouterLinkType::PointToPoint | LsaRouterLinkType::VirtualLink => {
            Some(VertexId::Router {
                router_id: link.link_id,
            })
        }
        LsaRouterLinkType::TransitNetwork => Some(VertexId::Network {
            dr_addr: link.link_id,
        }),
        LsaRouterLinkType::StubNetwork => None,
    }
}

fn route_prefix_sids(
    area: &Area<Ospfv2>,
    adv_rtr: Ipv4Addr,
    prefix: &Ipv4Network,
    route_type: ExtPrefixRouteType,
) -> BTreeMap<u8, PrefixSid> {
    let mut prefix_sids = BTreeMap::new();

    if let Some(prefix_sid) = area
        .state
        .version
        .ext_prefix_db
        .get(&(adv_rtr, *prefix))
        .filter(|tlv| {
            route_type == tlv.route_type
                || route_type == ExtPrefixRouteType::Unspecified
        })
        .and_then(|tlv| tlv.prefix_sids.get(&(PrefixSidAlgo::Spf as u8)))
    {
        prefix_sids.insert(PrefixSidAlgo::Spf as u8, *prefix_sid);
    }

    prefix_sids
}
