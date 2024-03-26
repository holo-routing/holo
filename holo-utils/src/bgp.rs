//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! This file contains BGP definitions that are common to both `holo-bgp` and
//! `holo-policy`. In the future, the northbound layer should be restructured
//! so that `holo-bgp` can handle the BGP-specific policy definitions itself,
//! eliminating the need for shared definitions.

use std::borrow::Cow;
use std::net::Ipv6Addr;

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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteType {
    Internal,
    External,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Comm(pub u32);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct ExtComm(pub [u8; 8]);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Extv6Comm(pub Ipv6Addr, pub u32);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LargeComm(pub [u8; 12]);

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
        }
    }
}

impl TryFromYang for AfiSafi {
    fn try_from_yang(value: &str) -> Option<AfiSafi> {
        match value {
            "iana-bgp-types:ipv4-unicast" => Some(AfiSafi::Ipv4Unicast),
            "iana-bgp-types:ipv6-unicast" => Some(AfiSafi::Ipv6Unicast),
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
                format!("{}:{}", global, local).into()
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

// ===== impl Extv6Comm =====

impl ToYang for Extv6Comm {
    fn to_yang(&self) -> Cow<'static, str> {
        // TODO: cover other cases instead of always using the raw format.
        let addr = self
            .0
            .segments()
            .into_iter()
            .map(|s| format!("{:02x}", s))
            .join(":");
        let local = self
            .1
            .to_be_bytes()
            .into_iter()
            .map(|s| format!("{:02x}", s))
            .join(":");
        format!("ipv6-raw:{}:{}", addr, local,).into()
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
