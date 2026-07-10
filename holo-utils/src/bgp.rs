//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! BGP definitions common to `holo-bgp` and `holo-policy`
//!
//! This file contains BGP definitions that are common to both `holo-bgp` and
//! `holo-policy`. In the future, the northbound layer should be restructured
//! so that `holo-bgp` can handle the BGP-specific policy definitions itself,
//! eliminating the need for shared definitions.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

use holo_yang::{ToYang, TryFromYang};
use itertools::Itertools;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use regex::Regex;
use serde::{Deserialize, Serialize};

// Configurable (AFI,SAFI) tuples.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AfiSafi {
    Ipv4Unicast,
    Ipv6Unicast,
    L3vpnIpv4Unicast,
    L3vpnIpv6Unicast,
    L2vpnEvpn,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteType {
    Internal,
    External,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    #[default]
    Incomplete = 2,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Comm(pub u32);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct ExtComm(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteDistinguisher {
    As2Administrator { asn: u16, number: u32 },
    Ipv4Administrator { addr: Ipv4Addr, number: u16 },
    As4Administrator { asn: u32, number: u16 },
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteTarget {
    As2Administrator { asn: u16, number: u32 },
    Ipv4Administrator { addr: Ipv4Addr, number: u16 },
    As4Administrator { asn: u32, number: u16 },
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Extv6Comm(pub Ipv6Addr, pub u32);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LargeComm(pub [u8; 12]);

pub type EthernetSegmentId = [u8; 10];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvpnEsiLabel {
    pub single_active: bool,
    pub label: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvpnMacMobility {
    pub sticky: bool,
    pub sequence: u32,
}

// BGP Well-known Communities.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xhtml
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
#[repr(u32)]
pub enum WellKnownCommunities {
    NoExport = 0xFFFFFF01,
    NoAdvertise = 0xFFFFFF02,
    NoExportSubconfed = 0xFFFFFF03,
}

// ===== impl AfiSafi =====

impl ToYang for AfiSafi {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AfiSafi::Ipv4Unicast => "iana-bgp-types:ipv4-unicast".into(),
            AfiSafi::Ipv6Unicast => "iana-bgp-types:ipv6-unicast".into(),
            AfiSafi::L3vpnIpv4Unicast => {
                "iana-bgp-types:l3vpn-ipv4-unicast".into()
            }
            AfiSafi::L3vpnIpv6Unicast => {
                "iana-bgp-types:l3vpn-ipv6-unicast".into()
            }
            AfiSafi::L2vpnEvpn => "iana-bgp-types:l2vpn-evpn".into(),
        }
    }
}

impl TryFromYang for AfiSafi {
    fn try_from_yang(value: &str) -> Option<AfiSafi> {
        match value {
            "iana-bgp-types:ipv4-unicast" => Some(AfiSafi::Ipv4Unicast),
            "iana-bgp-types:ipv6-unicast" => Some(AfiSafi::Ipv6Unicast),
            "iana-bgp-types:l3vpn-ipv4-unicast" => {
                Some(AfiSafi::L3vpnIpv4Unicast)
            }
            "iana-bgp-types:l3vpn-ipv6-unicast" => {
                Some(AfiSafi::L3vpnIpv6Unicast)
            }
            "iana-bgp-types:l2vpn-evpn" => Some(AfiSafi::L2vpnEvpn),
            _ => None,
        }
    }
}

// ===== impl Origin =====

impl ToYang for Origin {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Origin::Igp => "igp".into(),
            Origin::Egp => "egp".into(),
            Origin::Incomplete => "incomplete".into(),
        }
    }
}

impl TryFromYang for Origin {
    fn try_from_yang(value: &str) -> Option<Origin> {
        match value {
            "igp" => Some(Origin::Igp),
            "egp" => Some(Origin::Egp),
            "incomplete" => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

// ===== impl WellKnownCommunities =====

impl ToYang for WellKnownCommunities {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            WellKnownCommunities::NoExport => {
                "iana-bgp-community-types:no-export".into()
            }
            WellKnownCommunities::NoAdvertise => {
                "iana-bgp-community-types:no-advertise".into()
            }
            WellKnownCommunities::NoExportSubconfed => {
                "iana-bgp-community-types:no-export-subconfed".into()
            }
        }
    }
}

impl TryFromYang for WellKnownCommunities {
    fn try_from_yang(value: &str) -> Option<WellKnownCommunities> {
        match value {
            "iana-bgp-community-types:no-export" => {
                Some(WellKnownCommunities::NoExport)
            }
            "iana-bgp-community-types:no-advertise" => {
                Some(WellKnownCommunities::NoAdvertise)
            }
            "iana-bgp-community-types:no-export-subconfed" => {
                Some(WellKnownCommunities::NoExportSubconfed)
            }
            _ => None,
        }
    }
}

// ===== impl Comm =====

impl ToYang for Comm {
    fn to_yang(&self) -> Cow<'static, str> {
        match WellKnownCommunities::from_u32(self.0) {
            Some(comm) => {
                // Return well-known community identity.
                comm.to_yang()
            }
            None => {
                // Return community as plain integer.
                let global = self.0 >> 16;
                let local = self.0 & 0xFFFF;
                format!("{global}:{local}").into()
            }
        }
    }
}

impl TryFromYang for Comm {
    fn try_from_yang(value: &str) -> Option<Comm> {
        // Parse well-known community identity.
        if let Some(comm) = WellKnownCommunities::try_from_yang(value) {
            return Some(Comm(comm as u32));
        }

        // Parse plain integer community.
        if let Ok(comm) = value.parse::<u32>() {
            return Some(Comm(comm));
        }

        // Parse community in the "global:local" format.
        let re = Regex::new(r"^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-5][0-9]{3}|66[0-4][0-9]{2}|665[0-2][0-9]|6653[0-5]):([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-5][0-9]{3}|66[0-4][0-9]{2}|665[0-2][0-9]|6653[0-5])$").unwrap();
        if let Some(captures) = re.captures(value) {
            let global =
                captures.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let local =
                captures.get(2).unwrap().as_str().parse::<u32>().unwrap();
            let comm = (global << 16) | local;
            return Some(Comm(comm));
        }

        None
    }
}

// ===== impl ExtComm =====

impl ToYang for ExtComm {
    fn to_yang(&self) -> Cow<'static, str> {
        if let Some(rt) = RouteTarget::from_ext_comm(self) {
            return rt.to_yang();
        }

        // TODO: cover other cases instead of always using the raw format.
        format!(
            "raw:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7]
        )
        .into()
    }
}

pub fn evpn_es_import_route_target(esi: EthernetSegmentId) -> ExtComm {
    let mut bytes = [0; 8];
    bytes[0] = 0x06;
    bytes[1] = 0x02;
    bytes[2..8].copy_from_slice(&esi[1..7]);
    ExtComm(bytes)
}

pub fn evpn_esi_label_ext_comm(esi_label: EvpnEsiLabel) -> ExtComm {
    let mut bytes = [0; 8];
    bytes[0] = 0x06;
    bytes[1] = 0x01;
    bytes[2] = esi_label.single_active as u8;
    let label = (esi_label.label << 4) | 1;
    bytes[5..8].copy_from_slice(&label.to_be_bytes()[1..4]);
    ExtComm(bytes)
}

pub fn evpn_esi_label_from_ext_comm(comm: &ExtComm) -> Option<EvpnEsiLabel> {
    if comm.0[0] != 0x06 || comm.0[1] != 0x01 {
        return None;
    }
    let label = u32::from_be_bytes([0, comm.0[5], comm.0[6], comm.0[7]]);
    if label & 1 == 0 {
        return None;
    }
    Some(EvpnEsiLabel {
        single_active: comm.0[2] & 1 == 1,
        label: label >> 4,
    })
}

pub fn evpn_mac_mobility_ext_comm(mobility: EvpnMacMobility) -> ExtComm {
    let mut bytes = [0; 8];
    bytes[0] = 0x06;
    bytes[1] = 0x00;
    bytes[2] = mobility.sticky as u8;
    bytes[4..8].copy_from_slice(&mobility.sequence.to_be_bytes());
    ExtComm(bytes)
}

pub fn evpn_mac_mobility_from_ext_comm(
    comm: &ExtComm,
) -> Option<EvpnMacMobility> {
    if comm.0[0] != 0x06 || comm.0[1] != 0x00 {
        return None;
    }
    Some(EvpnMacMobility {
        sticky: comm.0[2] & 1 == 1,
        sequence: u32::from_be_bytes(comm.0[4..8].try_into().unwrap()),
    })
}

// ===== impl RouteDistinguisher =====

impl RouteDistinguisher {
    pub fn encode(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        match self {
            RouteDistinguisher::As2Administrator { asn, number } => {
                bytes[0..2].copy_from_slice(&0u16.to_be_bytes());
                bytes[2..4].copy_from_slice(&asn.to_be_bytes());
                bytes[4..8].copy_from_slice(&number.to_be_bytes());
            }
            RouteDistinguisher::Ipv4Administrator { addr, number } => {
                bytes[0..2].copy_from_slice(&1u16.to_be_bytes());
                bytes[2..6].copy_from_slice(&addr.octets());
                bytes[6..8].copy_from_slice(&number.to_be_bytes());
            }
            RouteDistinguisher::As4Administrator { asn, number } => {
                bytes[0..2].copy_from_slice(&2u16.to_be_bytes());
                bytes[2..6].copy_from_slice(&asn.to_be_bytes());
                bytes[6..8].copy_from_slice(&number.to_be_bytes());
            }
        }
        bytes
    }

    pub fn decode(bytes: [u8; 8]) -> Option<Self> {
        match u16::from_be_bytes(bytes[0..2].try_into().unwrap()) {
            0 => Some(RouteDistinguisher::As2Administrator {
                asn: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
                number: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            }),
            1 => Some(RouteDistinguisher::Ipv4Administrator {
                addr: Ipv4Addr::from(u32::from_be_bytes(
                    bytes[2..6].try_into().unwrap(),
                )),
                number: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            }),
            2 => Some(RouteDistinguisher::As4Administrator {
                asn: u32::from_be_bytes(bytes[2..6].try_into().unwrap()),
                number: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            }),
            _ => None,
        }
    }
}

impl ToYang for RouteDistinguisher {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteDistinguisher::As2Administrator { asn, number } => {
                format!("{asn}:{number}").into()
            }
            RouteDistinguisher::Ipv4Administrator { addr, number } => {
                format!("{addr}:{number}").into()
            }
            RouteDistinguisher::As4Administrator { asn, number } => {
                format!("{asn}:{number}").into()
            }
        }
    }
}

impl TryFromYang for RouteDistinguisher {
    fn try_from_yang(value: &str) -> Option<Self> {
        let mut fields = value.split(':').collect::<Vec<_>>();
        if fields.len() == 3 {
            return match fields[0] {
                "0" => Some(RouteDistinguisher::As2Administrator {
                    asn: fields[1].parse().ok()?,
                    number: fields[2].parse().ok()?,
                }),
                "1" => Some(RouteDistinguisher::Ipv4Administrator {
                    addr: fields[1].parse().ok()?,
                    number: fields[2].parse().ok()?,
                }),
                "2" => Some(RouteDistinguisher::As4Administrator {
                    asn: fields[1].parse().ok()?,
                    number: fields[2].parse().ok()?,
                }),
                _ => None,
            };
        }

        if fields.len() != 2 {
            return None;
        }
        let local = fields.pop().unwrap();
        let global = fields.pop().unwrap();

        if let Ok(asn) = global.parse::<u16>()
            && let Ok(number) = local.parse::<u32>()
        {
            return Some(RouteDistinguisher::As2Administrator { asn, number });
        }

        if let Ok(addr) = global.parse::<Ipv4Addr>()
            && let Ok(number) = local.parse::<u16>()
        {
            return Some(RouteDistinguisher::Ipv4Administrator {
                addr,
                number,
            });
        }

        if let Ok(asn) = global.parse::<u32>()
            && let Ok(number) = local.parse::<u16>()
        {
            return Some(RouteDistinguisher::As4Administrator { asn, number });
        }

        None
    }
}

// ===== impl RouteTarget =====

impl RouteTarget {
    pub fn to_ext_comm(self) -> ExtComm {
        let mut bytes = [0; 8];
        match self {
            RouteTarget::As2Administrator { asn, number } => {
                bytes[0] = 0x00;
                bytes[1] = 0x02;
                bytes[2..4].copy_from_slice(&asn.to_be_bytes());
                bytes[4..8].copy_from_slice(&number.to_be_bytes());
            }
            RouteTarget::Ipv4Administrator { addr, number } => {
                bytes[0] = 0x01;
                bytes[1] = 0x02;
                bytes[2..6].copy_from_slice(&addr.octets());
                bytes[6..8].copy_from_slice(&number.to_be_bytes());
            }
            RouteTarget::As4Administrator { asn, number } => {
                bytes[0] = 0x02;
                bytes[1] = 0x02;
                bytes[2..6].copy_from_slice(&asn.to_be_bytes());
                bytes[6..8].copy_from_slice(&number.to_be_bytes());
            }
        }
        ExtComm(bytes)
    }

    pub fn from_ext_comm(comm: &ExtComm) -> Option<Self> {
        match (comm.0[0], comm.0[1]) {
            (0x00 | 0x40, 0x02) => Some(RouteTarget::As2Administrator {
                asn: u16::from_be_bytes(comm.0[2..4].try_into().unwrap()),
                number: u32::from_be_bytes(comm.0[4..8].try_into().unwrap()),
            }),
            (0x01 | 0x41, 0x02) => Some(RouteTarget::Ipv4Administrator {
                addr: Ipv4Addr::from(u32::from_be_bytes(
                    comm.0[2..6].try_into().unwrap(),
                )),
                number: u16::from_be_bytes(comm.0[6..8].try_into().unwrap()),
            }),
            (0x02 | 0x42, 0x02) => Some(RouteTarget::As4Administrator {
                asn: u32::from_be_bytes(comm.0[2..6].try_into().unwrap()),
                number: u16::from_be_bytes(comm.0[6..8].try_into().unwrap()),
            }),
            _ => None,
        }
    }
}

impl ToYang for RouteTarget {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteTarget::As2Administrator { asn, number } => {
                format!("route-target:{asn}:{number}").into()
            }
            RouteTarget::Ipv4Administrator { addr, number } => {
                format!("route-target:{addr}:{number}").into()
            }
            RouteTarget::As4Administrator { asn, number } => {
                format!("route-target:{asn}:{number}").into()
            }
        }
    }
}

impl TryFromYang for RouteTarget {
    fn try_from_yang(value: &str) -> Option<Self> {
        if let Some(value) = value.strip_prefix("route-target:") {
            let (global, local) = value.split_once(':')?;

            if let Ok(asn) = global.parse::<u16>()
                && let Ok(number) = local.parse::<u32>()
            {
                return Some(RouteTarget::As2Administrator { asn, number });
            }

            if let Ok(addr) = global.parse::<Ipv4Addr>()
                && let Ok(number) = local.parse::<u16>()
            {
                return Some(RouteTarget::Ipv4Administrator { addr, number });
            }

            if let Ok(asn) = global.parse::<u32>()
                && let Ok(number) = local.parse::<u16>()
            {
                return Some(RouteTarget::As4Administrator { asn, number });
            }

            return None;
        }

        let mut fields = value.split(':');
        let comm_type = fields.next()?;
        let global = fields.next()?;
        let local = fields.next()?;
        if fields.next().is_some() {
            return None;
        }

        match comm_type {
            "0" => Some(RouteTarget::As2Administrator {
                asn: global.parse().ok()?,
                number: local.parse().ok()?,
            }),
            "1" => Some(RouteTarget::Ipv4Administrator {
                addr: global.parse().ok()?,
                number: local.parse().ok()?,
            }),
            "2" => Some(RouteTarget::As4Administrator {
                asn: global.parse().ok()?,
                number: local.parse().ok()?,
            }),
            _ => None,
        }
    }
}

// ===== impl Extv6Comm =====

impl ToYang for Extv6Comm {
    fn to_yang(&self) -> Cow<'static, str> {
        // TODO: cover other cases instead of always using the raw format.
        let addr = self
            .0
            .segments()
            .into_iter()
            .map(|s| format!("{s:02x}"))
            .join(":");
        let local = self
            .1
            .to_be_bytes()
            .into_iter()
            .map(|s| format!("{s:02x}"))
            .join(":");
        format!("ipv6-raw:{addr}:{local}",).into()
    }
}

// ===== impl LargeComm =====

impl ToYang for LargeComm {
    fn to_yang(&self) -> Cow<'static, str> {
        format!(
            "{}:{}:{}",
            u32::from_be_bytes(self.0[0..4].try_into().unwrap()),
            u32::from_be_bytes(self.0[4..8].try_into().unwrap()),
            u32::from_be_bytes(self.0[8..12].try_into().unwrap()),
        )
        .into()
    }
}

impl TryFromYang for LargeComm {
    fn try_from_yang(value: &str) -> Option<LargeComm> {
        // Parse large community in the "global:local:local" format.
        let re = Regex::new(r#"^(?:(?:4[0-2][0-9][0-4][0-9][0-6][0-7][0-2][0-9][0-6])|(?:[1-3][0-9]{9}|[1-9]([0-9]{1,7})?[0-9]|[0-9])):(?:(?:4[0-2][0-9][0-4][0-9][0-6][0-7][0-2][0-9][0-6])|(?:[1-3][0-9]{9}|[1-9]([0-9]{1,7})?[0-9]|[0-9])):(?:(?:4[0-2][0-9][0-4][0-9][0-6][0-7][0-2][0-9][0-6])|(?:[1-3][0-9]{9}|[1-9]([0-9]{1,7})?[0-9]|[0-9]))$"#).unwrap();
        if let Some(captures) = re.captures(value) {
            let global =
                captures.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let local1 =
                captures.get(2).unwrap().as_str().parse::<u32>().unwrap();
            let local2 =
                captures.get(3).unwrap().as_str().parse::<u32>().unwrap();

            let mut comm = [0u8; 12];
            comm[..4].copy_from_slice(&global.to_be_bytes());
            comm[4..8].copy_from_slice(&local1.to_be_bytes());
            comm[8..].copy_from_slice(&local2.to_be_bytes());
            return Some(LargeComm(comm));
        }

        None
    }
}
