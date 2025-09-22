//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use holo_utils::ip::IpAddrKind;

use crate::area::{Area, AreaType, AreaVersion, OptionsLocation};
use crate::collections::Arena;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::ospfv3::packet::Options;
use crate::ospfv3::packet::lsa::{LsaIntraAreaPrefix, PrefixOptions};
use crate::packet::lsa::LsaHdrVersion;
use crate::route::RouteRtr;
use crate::version::Ospfv3;

#[derive(Debug, Default)]
pub struct AreaState {
    // Next inter-area LSA IDs.
    pub next_type3_lsa_id: u32,
    pub next_type4_lsa_id: u32,
}

// ===== impl Ospfv3 =====

impl AreaVersion<Self> for Ospfv3 {
    type State = AreaState;

    fn area_options(area: &Area<Self>, location: OptionsLocation) -> Options {
        let mut options = Options::R | Options::V6 | Options::AF;

        if area.config.area_type == AreaType::Normal {
            options.insert(Options::E);
        }

        if let OptionsLocation::Packet { auth: true, .. } = location {
            options.insert(Options::AT);
        }

        if let OptionsLocation::Packet { lls: true, .. } = location {
            options.insert(Options::L);
        }

        options
    }

    fn vlink_source_addr(
        area: &Area<Self>,
        _route_br: &RouteRtr<Self>,
        interfaces: &Arena<Interface<Self>>,
    ) -> Option<Ipv6Addr> {
        // RFC 5340 section 4.7 specifies that the IPv6 source address of a
        // virtual link must have global scope. Unlike OSPFv2, there is no
        // requirement that this address come from the interface used to reach
        // the virtual link endpoint. A loopback address, for example, is
        // perfectly valid.
        //
        // We first look for a global address on interfaces that belong to the
        // transit area. If none are found, we fall back to any other global
        // address. This way, if two ABRs share multiple virtual links across
        // different transit areas, each link can use a different source address
        // and both can be established. If no global address exists in the
        // transit area, picking any other global address still allows at least
        // one virtual link to be established over a pair of ABRs.
        area.interfaces
            .iter(interfaces)
            .chain(interfaces.iter().map(|(_, iface)| iface))
            .flat_map(|iface| iface.system.addr_list.iter())
            .filter_map(|addr| Ipv6Addr::get(addr.ip()))
            .find(|addr| !addr.is_unicast_link_local())
    }

    fn vlink_neighbor_addr(
        area: &Area<Self>,
        router_id: Ipv4Addr,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<Ipv6Addr> {
        // The collection of intra-area-prefix-LSAs originated by the virtual
        // neighbor is examined, with the virtual neighbor's IP address being
        // set to the first prefix encountered with the LA-bit set.
        area.state
            .lsdb
            .iter_by_type_advrtr(
                lsa_entries,
                LsaIntraAreaPrefix::lsa_type(extended_lsa),
                router_id,
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .flat_map(move |lsa| {
                let lsa_body = lsa.body.as_intra_area_prefix().unwrap();
                lsa_body.prefixes.iter()
            })
            .find(|prefix| prefix.options.contains(PrefixOptions::LA))
            .map(|prefix| prefix.value.ip())
            // RFC 5838, section 2.8: Virtual links are not supported in AFs
            // other than IPv6 unicast.
            .and_then(Ipv6Addr::get)
    }
}
