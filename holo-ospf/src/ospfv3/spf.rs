//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use holo_utils::ip::AddressFamily;

use crate::area::Area;
use crate::collections::{Arena, Lsdb};
use crate::error::Error;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::neighbor::Neighbor;
use crate::ospfv3::packet::lsa::{
    LsaAsExternal, LsaAsExternalFlags, LsaFunctionCode, LsaInterAreaPrefix,
    LsaInterAreaRouter, LsaIntraAreaPrefix, LsaLink, LsaNetwork, LsaRouter,
    LsaRouterFlags, LsaRouterInfo, LsaRouterLink, LsaRouterLinkType,
    LsaScopeCode, LsaType, PrefixOptions,
};
use crate::ospfv3::packet::Options;
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::route::{Nexthop, NexthopKey, Nexthops};
use crate::spf::{
    SpfComputation, SpfExternalNetwork, SpfInterAreaNetwork,
    SpfInterAreaRouter, SpfIntraAreaNetwork, SpfLink, SpfPartialComputation,
    SpfRouterInfo, SpfTriggerLsa, SpfVersion, Vertex, VertexIdVersion,
    VertexLsaVersion,
};
use crate::version::Ospfv3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VertexId {
    Network { router_id: Ipv4Addr, iface_id: u32 },
    Router { router_id: Ipv4Addr },
}

#[derive(Debug, Eq, PartialEq, EnumAsInner)]
pub enum VertexLsa {
    Network(Arc<Lsa<Ospfv3>>),
    Router(Vec<Arc<Lsa<Ospfv3>>>),
}

// ===== impl VertexId =====

impl VertexIdVersion for VertexId {
    fn new_root(router_id: Ipv4Addr) -> Self {
        VertexId::Router { router_id }
    }
}

// ===== impl VertexLsa =====

impl VertexLsaVersion<Ospfv3> for VertexLsa {
    fn is_router(&self) -> bool {
        matches!(self, VertexLsa::Router(_))
    }

    fn router_v_bit(&self) -> bool {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags.contains(LsaRouterFlags::V)
    }

    fn router_id(&self) -> Ipv4Addr {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        lsa.hdr.adv_rtr
    }

    fn router_options(&self) -> Options {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.options
    }

    fn router_flags(&self) -> LsaRouterFlags {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags
    }

    fn origin(&self) -> LsaKey<LsaType> {
        let lsa = match self {
            VertexLsa::Network(lsa) => lsa,
            VertexLsa::Router(lsas) => lsas.iter().next().unwrap(),
        };
        lsa.hdr.key()
    }
}

// ===== impl Ospfv3 =====

impl SpfVersion<Self> for Ospfv3 {
    type VertexId = VertexId;
    type VertexLsa = VertexLsa;

    fn spf_computation_type(
        trigger_lsas: &[SpfTriggerLsa<Self>],
    ) -> SpfComputation<Self> {
        // Router-LSA and Network-LSA changes represent topological changes,
        // hence a full SPF run is required to recompute the SPT.
        //
        // Link-LSA and Router Information LSA changes don't strictly require a
        // full SPF run, but doing so greatly simplify things (e.g. no need to
        // keep track of which routes are affected by which SRGBs).
        if trigger_lsas.iter().map(|tlsa| &tlsa.new).any(|lsa| {
            matches!(
                lsa.hdr.lsa_type.function_code_normalized(),
                Some(
                    LsaFunctionCode::Router
                        | LsaFunctionCode::Network
                        | LsaFunctionCode::Link
                        | LsaFunctionCode::RouterInfo
                )
            )
        }) {
            return SpfComputation::Full;
        }

        // Check Intra-Area-Prefix LSA changes.
        //
        // For that to work, for each changed Intra-Area-Prefix LSA, we merge
        // the prefixes from the old and new version of the LSA.
        let intra = trigger_lsas
            .iter()
            .flat_map(|tlsa| std::iter::once(&tlsa.new).chain(tlsa.old.iter()))
            .filter_map(|lsa| lsa.body.as_intra_area_prefix())
            .flat_map(|lsa_body| {
                lsa_body.prefixes.iter().map(move |prefix| prefix.value)
            })
            .collect();

        // Check Inter-Area-Prefix LSA changes.
        let inter_network = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_inter_area_prefix())
            .map(|lsa_body| lsa_body.prefix)
            .collect();

        // Check Inter-Area-Router LSA changes.
        let inter_router = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_inter_area_router())
            .map(|lsa_body| lsa_body.router_id)
            .collect::<BTreeSet<_>>();

        // Check AS-External LSA changes.
        let external = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_as_external())
            .map(|lsa_body| lsa_body.prefix)
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
        parent_link: Option<(usize, &LsaRouterLink)>,
        dest_id: VertexId,
        dest_lsa: &VertexLsa,
        interfaces: &Arena<Interface<Self>>,
        _neighbors: &Arena<Neighbor<Self>>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Result<Nexthops<IpAddr>, Error<Self>> {
        let mut nexthops = Nexthops::new();

        match &parent.lsa {
            // The parent vertex is the root.
            VertexLsa::Router(_parent_lsa) => {
                // The destination is either a directly connected network or
                // directly connected router.
                // The outgoing interface in this case is simply the OSPF
                // interface connecting to the destination network/router.
                let (_, parent_link) = parent_link.unwrap();

                // Get nexthop interface.
                let (iface_idx, iface) = area
                    .interfaces
                    .get_by_ifindex(interfaces, parent_link.iface_id as _)
                    .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;

                match dest_lsa {
                    VertexLsa::Router(dest_lsa) => {
                        let nexthop_addr = calc_nexthop_lladdr(
                            iface,
                            parent_link.nbr_router_id,
                            parent_link.nbr_iface_id,
                            extended_lsa,
                            lsa_entries,
                        )
                        .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;
                        let nbr_router_id =
                            dest_lsa.iter().next().unwrap().hdr.adv_rtr;

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
            VertexLsa::Network(parent_lsa) => {
                // The list of next hops is then determined by examining the
                // destination's router-LSA. For each link in the router-LSA
                // that points back to the parent network, the link's Link
                // Data field provides the IP address of a next hop router.
                let dest_lsa = dest_lsa.as_router().unwrap();
                let dest_link = dest_lsa
                    .iter()
                    .map(|dest_lsa| dest_lsa.body.as_router().unwrap())
                    .flat_map(|dest_lsa_body| dest_lsa_body.links.iter())
                    .find(|dest_link| {
                        dest_link.nbr_router_id == parent_lsa.hdr.adv_rtr
                            && Ipv4Addr::from(dest_link.nbr_iface_id)
                                == parent_lsa.hdr.lsa_id
                    })
                    .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;

                // Inherit outgoing interface from the parent network.
                let iface_idx = parent
                    .nexthops
                    .values()
                    .next()
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?
                    .iface_idx;
                let iface = &interfaces[iface_idx];

                // Get nexthop address.
                let nbr_router_id = dest_lsa.iter().next().unwrap().hdr.adv_rtr;
                let nexthop_addr = calc_nexthop_lladdr(
                    iface,
                    nbr_router_id,
                    dest_link.iface_id,
                    extended_lsa,
                    lsa_entries,
                )
                .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;

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
        af: AddressFamily,
        id: VertexId,
        area: &Area<Self>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<VertexLsa> {
        match id {
            VertexId::Network {
                router_id,
                iface_id,
            } => {
                // Network-LSAs are always standalone.
                let lsa_key = LsaKey::new(
                    LsaNetwork::lsa_type(extended_lsa),
                    router_id,
                    Ipv4Addr::from(iface_id),
                );
                area.state
                    .lsdb
                    .get(lsa_entries, &lsa_key)
                    .map(|(_, lse)| &lse.data)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .cloned()
                    .map(VertexLsa::Network)
            }
            VertexId::Router { router_id } => {
                // RFC 5340 - Section 4.8.1:
                // "All router-LSAs with the Advertising Router set to V's OSPF
                // Router ID MUST be processed as an aggregate, treating them as
                // fragments of a single large router-LSA".
                let lsas = area
                    .state
                    .lsdb
                    .iter_by_type_advrtr(
                        lsa_entries,
                        LsaRouter::lsa_type(extended_lsa),
                        router_id,
                    )
                    .map(|(_, lse)| &lse.data)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .filter(|lsa| {
                        let lsa_body = lsa.body.as_router().unwrap();

                        // Ensure the R and V6 bits are set (except for AFs
                        // other than IPv6 unicast).
                        lsa_body.options.contains(Options::R)
                            && (af != AddressFamily::Ipv6
                                || lsa_body.options.contains(Options::V6))
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                if !lsas.is_empty() {
                    Some(VertexLsa::Router(lsas))
                } else {
                    None
                }
            }
        }
    }

    fn vertex_lsa_links<'a>(
        vertex_lsa: &'a VertexLsa,
        af: AddressFamily,
        area: &'a Area<Ospfv3>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Ospfv3>>,
    ) -> Box<dyn Iterator<Item = SpfLink<'a, Ospfv3>> + 'a> {
        match vertex_lsa {
            VertexLsa::Network(lsa) => {
                let lsa_body = lsa.body.as_network().unwrap();
                let iter = lsa_body.attached_rtrs.iter().filter_map(
                    move |router_id| {
                        let link_vid = VertexId::Router {
                            router_id: *router_id,
                        };
                        Ospfv3::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            extended_lsa,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(None, link_vid, link_vlsa, 0)
                        })
                    },
                );
                Box::new(iter)
            }
            VertexLsa::Router(lsas) => {
                let iter = lsas
                    .iter()
                    .map(|lsa| lsa.body.as_router().unwrap())
                    .flat_map(|lsa| lsa.links.iter())
                    .filter_map(|link| match link.link_type {
                        LsaRouterLinkType::PointToPoint => {
                            let link_vid = VertexId::Router {
                                router_id: link.nbr_router_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::TransitNetwork => {
                            let link_vid = VertexId::Network {
                                router_id: link.nbr_router_id,
                                iface_id: link.nbr_iface_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::VirtualLink => {
                            // TODO: not supported yet.
                            None
                        }
                    })
                    .enumerate()
                    .filter_map(move |(link_pos, (link, link_vid, cost))| {
                        Ospfv3::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            extended_lsa,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(
                                Some((link_pos, link)),
                                link_vid,
                                link_vlsa,
                                cost,
                            )
                        })
                    });
                Box::new(iter)
            }
        }
    }

    fn intra_area_networks<'a>(
        area: &'a Area<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfIntraAreaNetwork<'a, Self>> + 'a {
        // Instead of examining the stub links within router-LSAs, the list of
        // the area's intra-area-prefix-LSAs is examined.
        area.state
            .lsdb
            .iter_by_type(
                lsa_entries,
                LsaIntraAreaPrefix::lsa_type(extended_lsa),
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(move |lsa| {
                // Find SPT vertex corresponding to referenced LSA.
                let lsa_body = lsa.body.as_intra_area_prefix().unwrap();
                if lsa_body.ref_lsa_type == LsaRouter::lsa_type(extended_lsa) {
                    if lsa_body.ref_lsa_id != Ipv4Addr::UNSPECIFIED {
                        return None;
                    }
                    let vid = VertexId::Router {
                        router_id: lsa_body.ref_adv_rtr,
                    };
                    area.state.spt.get(&vid)
                } else if lsa_body.ref_lsa_type
                    == LsaNetwork::lsa_type(extended_lsa)
                {
                    let vid = VertexId::Network {
                        router_id: lsa_body.ref_adv_rtr,
                        iface_id: lsa_body.ref_lsa_id.into(),
                    };
                    area.state.spt.get(&vid)
                } else {
                    None
                }
                .map(|vertex| (vertex, &lsa_body.prefixes))
            })
            .flat_map(|(vertex, prefixes)| {
                prefixes
                    .iter()
                    // A prefix advertisement whose NU-bit is set SHOULD NOT be
                    // included in the routing calculation.
                    .filter(|prefix| {
                        !prefix.options.contains(PrefixOptions::NU)
                    })
                    .cloned()
                    .map(move |prefix| SpfIntraAreaNetwork {
                        vertex,
                        prefix: prefix.value,
                        prefix_options: prefix.options,
                        metric: prefix.metric,
                        prefix_sids: prefix.prefix_sids,
                        bier: prefix.bier,
                    })
            })
    }

    fn inter_area_networks<'a>(
        area: &'a Area<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaNetwork<Self>> + 'a {
        area.state
            .lsdb
            .iter_by_type(
                lsa_entries,
                LsaInterAreaPrefix::lsa_type(extended_lsa),
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_inter_area_prefix().unwrap();
                (!lsa_body.prefix_options.contains(PrefixOptions::NU))
                    .then_some(SpfInterAreaNetwork {
                        adv_rtr: lsa.hdr.adv_rtr,
                        prefix: lsa_body.prefix,
                        prefix_options: lsa_body.prefix_options,
                        metric: lsa_body.metric,
                        prefix_sids: lsa_body.prefix_sids.clone(),
                    })
            })
    }

    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaRouter<Self>> + 'a {
        lsdb.iter_by_type(
            lsa_entries,
            LsaInterAreaRouter::lsa_type(extended_lsa),
        )
        .map(|(_, lse)| &lse.data)
        .filter(|lsa| !lsa.hdr.is_maxage())
        .map(|lsa| {
            let lsa_body = lsa.body.as_inter_area_router().unwrap();
            SpfInterAreaRouter {
                adv_rtr: lsa.hdr.adv_rtr,
                router_id: lsa_body.router_id,
                options: lsa_body.options,
                flags: LsaRouterFlags::E,
                metric: lsa_body.metric,
            }
        })
    }

    fn external_networks<'a>(
        lsdb: &'a Lsdb<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfExternalNetwork<Self>> + 'a {
        lsdb.iter_by_type(lsa_entries, LsaAsExternal::lsa_type(extended_lsa))
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_as_external().unwrap();
                (!lsa_body.prefix_options.contains(PrefixOptions::NU))
                    .then_some(SpfExternalNetwork {
                        adv_rtr: lsa.hdr.adv_rtr,
                        e_bit: lsa_body.flags.contains(LsaAsExternalFlags::E),
                        prefix: lsa_body.prefix,
                        prefix_options: lsa_body.prefix_options,
                        metric: lsa_body.metric,
                        fwd_addr: lsa_body.fwd_addr,
                        tag: lsa_body.tag,
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
            .iter_by_type_advrtr(
                lsa_entries,
                LsaRouterInfo::lsa_type_scope(LsaScopeCode::Area),
                router_id,
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| lsa.body.as_router_info())
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
}

// ===== helper functions =====

fn calc_nexthop_lladdr(
    iface: &Interface<Ospfv3>,
    nbr_router_id: Ipv4Addr,
    nbr_iface_id: u32,
    extended_lsa: bool,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> Option<IpAddr> {
    let lsa_key = LsaKey::new(
        LsaLink::lsa_type(extended_lsa),
        nbr_router_id,
        Ipv4Addr::from(nbr_iface_id),
    );
    iface
        .state
        .lsdb
        .get(lsa_entries, &lsa_key)
        .map(|(_, lse)| &lse.data)
        .filter(|lsa| !lsa.hdr.is_maxage())
        .map(|lsa| lsa.body.as_link().unwrap().linklocal)
}
