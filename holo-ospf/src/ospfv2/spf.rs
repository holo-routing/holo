//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt};
use holo_utils::sr::IgpAlgoType;
use ipnetwork::Ipv4Network;

use crate::area::Area;
use crate::collections::{Arena, Lsdb};
use crate::error::Error;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::ospfv2::packet::lsa::{
    LsaAsExternalFlags, LsaBody, LsaRouterFlags, LsaRouterLink,
    LsaRouterLinkType, LsaType, LsaTypeCode,
};
use crate::ospfv2::packet::lsa_opaque::{
    ExtPrefixRouteType, LsaOpaque, PrefixSid,
};
use crate::ospfv2::packet::Options;
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::route::{Nexthop, NexthopKey, Nexthops};
use crate::spf::{
    SpfComputation, SpfExternalNetwork, SpfInterAreaNetwork,
    SpfInterAreaRouter, SpfIntraAreaNetwork, SpfLink, SpfPartialComputation,
    SpfRouterInfo, SpfTriggerLsa, SpfVersion, Vertex, VertexIdVersion,
    VertexLsaVersion,
};
use crate::version::Ospfv2;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VertexId {
    Network { dr_addr: Ipv4Addr },
    Router { router_id: Ipv4Addr },
}

#[derive(Debug, Eq, PartialEq, EnumAsInner)]
pub enum VertexLsa {
    Network(Arc<Lsa<Ospfv2>>),
    Router(Arc<Lsa<Ospfv2>>),
}

// ===== impl VertexId =====

impl VertexIdVersion for VertexId {
    fn new_root(router_id: Ipv4Addr) -> Self {
        VertexId::Router { router_id }
    }
}

// ===== impl VertexLsa =====

impl VertexLsaVersion<Ospfv2> for VertexLsa {
    fn is_router(&self) -> bool {
        matches!(self, VertexLsa::Router(_))
    }

    fn router_v_bit(&self) -> bool {
        let lsa = self.as_router().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags.contains(LsaRouterFlags::V)
    }

    fn router_id(&self) -> Ipv4Addr {
        let lsa = self.as_router().unwrap();
        lsa.hdr.adv_rtr
    }

    fn router_options(&self) -> Options {
        let lsa = self.as_router().unwrap();
        lsa.hdr.options
    }

    fn router_flags(&self) -> LsaRouterFlags {
        let lsa = self.as_router().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags
    }

    fn origin(&self) -> LsaKey<LsaType> {
        let lsa = match self {
            VertexLsa::Network(lsa) => lsa,
            VertexLsa::Router(lsa) => lsa,
        };
        lsa.hdr.key()
    }
}

// ===== impl Ospfv2 =====

impl SpfVersion<Self> for Ospfv2 {
    type VertexId = VertexId;
    type VertexLsa = VertexLsa;

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
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| {
                lsa.body
                    .as_summary_network()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask)
                    .unwrap()
            })
            .collect();

        // Check Type-4 Summary LSA changes.
        let inter_router = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_summary_router().map(|_| lsa.hdr))
            .map(|lsa_hdr| lsa_hdr.lsa_id)
            .collect::<BTreeSet<_>>();

        // Check AS-External LSA changes.
        let external = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| {
                lsa.body
                    .as_as_external()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask)
                    .unwrap()
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
        parent_link: Option<&LsaRouterLink>,
        dest_id: VertexId,
        dest_lsa: &VertexLsa,
        interfaces: &Arena<Interface<Self>>,
        _extended_lsa: bool,
        _lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Result<Nexthops<Ipv4Addr>, Error<Self>> {
        let mut nexthops = Nexthops::new();

        match &parent.lsa {
            // The parent vertex is the root.
            VertexLsa::Router(_parent_lsa) => {
                // The destination is either a directly connected network or
                // directly connected router.
                // The outgoing interface in this case is simply the OSPF
                // interface connecting to the destination network/router.
                let parent_link = parent_link.unwrap();

                // Get nexthop interface.
                let parent_link_addr = parent_link.link_data;
                let (iface_idx, iface) = area
                    .interfaces
                    .get_by_addr(interfaces, parent_link_addr)
                    .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;

                match dest_lsa {
                    VertexLsa::Router(dest_lsa) => {
                        // Add nexthop(s).
                        nexthops.extend(
                            dest_lsa
                                .body
                                .as_router()
                                .unwrap()
                                .links
                                .iter()
                                .filter(|link| {
                                    iface.system.contains_addr(&link.link_data)
                                })
                                .map(|link| {
                                    let nexthop_addr = link.link_data;
                                    let nbr_router_id = dest_lsa.hdr.adv_rtr;
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
            VertexLsa::Network(parent_lsa) => {
                // The list of next hops is then determined by examining the
                // destination's router-LSA. For each link in the router-LSA
                // that points back to the parent network, the link's Link
                // Data field provides the IP address of a next hop router.
                let lsa_body = parent_lsa.body.as_network().unwrap();
                let parent_network = Ipv4Network::with_netmask(
                    parent_lsa.hdr.lsa_id,
                    lsa_body.mask,
                )
                .unwrap();
                let dest_lsa = dest_lsa.as_router().unwrap();
                let dest_link = dest_lsa
                    .body
                    .as_router()
                    .unwrap()
                    .links
                    .iter()
                    .find(|link| parent_network.contains(link.link_data))
                    .ok_or_else(|| Error::SpfNexthopCalcError(dest_id))?;

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
                    .find(|lsa| lsa.hdr.lsa_id == dr_addr)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .map(|lsa| VertexLsa::Network(lsa.clone()))
            }
            VertexId::Router { router_id } => {
                let lsa_key = LsaKey::new(
                    LsaTypeCode::Router.into(),
                    router_id,
                    router_id,
                );
                area.state
                    .lsdb
                    .get(lsa_entries, &lsa_key)
                    .filter(|(_, lse)| !lse.data.hdr.is_maxage())
                    .map(|(_, lse)| VertexLsa::Router(lse.data.clone()))
            }
        }
    }

    fn vertex_lsa_links<'a>(
        vertex_lsa: &'a VertexLsa,
        af: AddressFamily,
        area: &'a Area<Ospfv2>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Ospfv2>>,
    ) -> Box<dyn Iterator<Item = SpfLink<'a, Ospfv2>> + 'a> {
        match vertex_lsa {
            VertexLsa::Network(lsa) => {
                let lsa_body = lsa.body.as_network().unwrap();
                let iter = lsa_body.attached_rtrs.iter().filter_map(
                    move |router_id| {
                        let link_vid = VertexId::Router {
                            router_id: *router_id,
                        };
                        Ospfv2::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            false,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(None, link_vid, link_vlsa, 0)
                        })
                    },
                );
                Box::new(iter)
            }
            VertexLsa::Router(lsa) => {
                let lsa_body = lsa.body.as_router().unwrap();
                let iter = lsa_body
                    .links
                    .iter()
                    .filter_map(|link| match link.link_type {
                        LsaRouterLinkType::PointToPoint => {
                            let link_vid = VertexId::Router {
                                router_id: link.link_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::TransitNetwork => {
                            let link_vid = VertexId::Network {
                                dr_addr: link.link_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::StubNetwork => None,
                        LsaRouterLinkType::VirtualLink => {
                            // TODO: not supported yet.
                            None
                        }
                    })
                    .filter_map(move |(link, link_vid, cost)| {
                        Ospfv2::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            false,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(Some(link), link_vid, link_vlsa, cost)
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
    ) -> Box<dyn Iterator<Item = SpfIntraAreaNetwork<'a, Self>> + 'a> {
        let mut stubs = vec![];

        for vertex in area.state.spt.values() {
            match &vertex.lsa {
                VertexLsa::Network(lsa) => {
                    let lsa_body = lsa.body.as_network().unwrap();
                    let prefix = Ipv4Network::with_netmask(
                        lsa.hdr.lsa_id,
                        lsa_body.mask,
                    )
                    .unwrap();
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
                    });
                }
                VertexLsa::Router(lsa) => {
                    let lsa_body = lsa.body.as_router().unwrap();
                    stubs.extend(
                        lsa_body
                            .links
                            .iter()
                            .filter(|link| {
                                link.link_type == LsaRouterLinkType::StubNetwork
                            })
                            .map(|link| {
                                let prefix = Ipv4Network::with_netmask(
                                    link.link_id,
                                    link.link_data,
                                )
                                .unwrap();
                                let prefix = prefix.apply_mask();
                                let metric = link.metric;
                                let prefix_sids = route_prefix_sids(
                                    area,
                                    lsa.hdr.adv_rtr,
                                    &prefix,
                                    ExtPrefixRouteType::IntraArea,
                                );

                                SpfIntraAreaNetwork {
                                    vertex,
                                    prefix,
                                    prefix_options: Default::default(),
                                    metric,
                                    prefix_sids,
                                }
                            }),
                    )
                }
            }
        }

        Box::new(stubs.into_iter())
    }

    fn inter_area_networks<'a>(
        area: &'a Area<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> Box<dyn Iterator<Item = SpfInterAreaNetwork<Self>> + 'a> {
        let iter = area
            .state
            .lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::SummaryNetwork.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| {
                let lsa_body = lsa.body.as_summary_network().unwrap();
                let prefix =
                    Ipv4Network::with_netmask(lsa.hdr.lsa_id, lsa_body.mask)
                        .unwrap();
                let prefix_sids = route_prefix_sids(
                    area,
                    lsa.hdr.adv_rtr,
                    &prefix,
                    ExtPrefixRouteType::InterArea,
                );

                SpfInterAreaNetwork {
                    adv_rtr: lsa.hdr.adv_rtr,
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    prefix_sids,
                }
            });
        Box::new(iter)
    }

    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> Box<dyn Iterator<Item = SpfInterAreaRouter<Self>> + 'a> {
        let iter = lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::SummaryRouter.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| {
                let lsa_body = lsa.body.as_summary_router().unwrap();
                SpfInterAreaRouter {
                    adv_rtr: lsa.hdr.adv_rtr,
                    router_id: lsa.hdr.lsa_id,
                    options: lsa.hdr.options,
                    flags: LsaRouterFlags::E,
                    metric: lsa_body.metric,
                }
            });
        Box::new(iter)
    }

    fn external_networks<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> Box<dyn Iterator<Item = SpfExternalNetwork<Self>> + 'a> {
        let iter = lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::AsExternal.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| {
                let lsa_body = lsa.body.as_as_external().unwrap();
                let prefix =
                    Ipv4Network::with_netmask(lsa.hdr.lsa_id, lsa_body.mask)
                        .unwrap();

                SpfExternalNetwork {
                    adv_rtr: lsa.hdr.adv_rtr,
                    e_bit: lsa_body.flags.contains(LsaAsExternalFlags::E),
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    fwd_addr: lsa_body.fwd_addr,
                    tag: Some(lsa_body.tag),
                }
            });
        Box::new(iter)
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
                LsaTypeCode::OpaqueArea.into(),
                router_id,
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| lsa.body.as_opaque_area().unwrap())
            .filter_map(|lsa_body| lsa_body.as_router_info())
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

        for (adv_rtr, lsa_body) in area
            .state
            .lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::OpaqueArea.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| (lsa.hdr.adv_rtr, lsa.body.as_opaque_area().unwrap()))
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
                        .entry((adv_rtr, *prefix))
                        .or_insert_with(|| tlv.clone());
                }
            }
        }
    }
}

// ===== helper functions =====

fn route_prefix_sids(
    area: &Area<Ospfv2>,
    adv_rtr: Ipv4Addr,
    prefix: &Ipv4Network,
    route_type: ExtPrefixRouteType,
) -> BTreeMap<IgpAlgoType, PrefixSid> {
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
        .and_then(|tlv| tlv.prefix_sids.get(&IgpAlgoType::Spf))
    {
        prefix_sids.insert(IgpAlgoType::Spf, *prefix_sid);
    }

    prefix_sids
}
