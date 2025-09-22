//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;

use crate::area::{Area, AreaType, AreaVersion, OptionsLocation};
use crate::collections::Arena;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::ospfv2::packet::Options;
use crate::ospfv2::packet::lsa::{LsaRouterLinkType, LsaTypeCode};
use crate::ospfv2::packet::lsa_opaque::ExtPrefixTlv;
use crate::packet::PacketType;
use crate::packet::lsa::{LsaHdrVersion, LsaKey};
use crate::route::RouteRtr;
use crate::version::Ospfv2;

#[derive(Debug, Default)]
pub struct AreaState {
    pub ext_prefix_db: HashMap<(Ipv4Addr, Ipv4Network), ExtPrefixTlv>,
}

// ===== impl Ospfv2 =====

impl AreaVersion<Self> for Ospfv2 {
    type State = AreaState;

    fn area_options(area: &Area<Self>, location: OptionsLocation) -> Options {
        let mut options = Options::empty();

        if area.config.area_type == AreaType::Normal {
            options.insert(Options::E);
        }

        // The O-bit is not set in packets other than Database Description
        // packets.
        if let OptionsLocation::Packet {
            pkt_type: PacketType::DbDesc,
            ..
        } = location
        {
            options.insert(Options::O);
        }

        if let OptionsLocation::Packet { lls: true, .. } = location {
            options.insert(Options::L);
        }

        options
    }

    fn vlink_source_addr(
        _area: &Area<Self>,
        route_br: &RouteRtr<Self>,
        interfaces: &Arena<Interface<Self>>,
    ) -> Option<Ipv4Addr> {
        // The virtual link source address is taken from the interface used to
        // reach the virtual link endpoint. If multiple ECMP paths exist, only
        // the first interface with a valid address is used.
        for nexthop in route_br.nexthops.values() {
            let iface = &interfaces[nexthop.iface_idx];
            if let Some(addr) = iface.state.src_addr {
                return Some(addr);
            }
        }

        None
    }

    fn vlink_neighbor_addr(
        area: &Area<Self>,
        router_id: Ipv4Addr,
        _extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<Ipv4Addr> {
        let lsa_key =
            LsaKey::new(LsaTypeCode::Router.into(), router_id, router_id);
        let (_, lse) = area
            .state
            .lsdb
            .get(lsa_entries, &lsa_key)
            .filter(|(_, lse)| !lse.data.hdr.is_maxage())?;
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.links.iter().find_map(|link| match link.link_type {
            LsaRouterLinkType::PointToPoint
            | LsaRouterLinkType::TransitNetwork => Some(link.link_data),
            _ => None,
        })
    }
}
