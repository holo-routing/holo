//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::str::FromStr;

use holo_yang::{ToYang, TryFromYang};
use serde::{Deserialize, Serialize};

// The protocols Holo supports.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    BFD,
    BGP,
    DIRECT,
    ISIS,
    LDP,
    OSPFV2,
    OSPFV3,
    RIPV2,
    RIPNG,
    STATIC,
    VRRP,
}

// ===== impl Protocol =====

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::BFD => write!(f, "bfd"),
            Protocol::BGP => write!(f, "bgp"),
            Protocol::DIRECT => write!(f, "direct"),
            Protocol::ISIS => write!(f, "isis"),
            Protocol::LDP => write!(f, "ldp"),
            Protocol::OSPFV2 => write!(f, "ospfv2"),
            Protocol::OSPFV3 => write!(f, "ospfv3"),
            Protocol::RIPV2 => write!(f, "ripv2"),
            Protocol::RIPNG => write!(f, "ripng"),
            Protocol::STATIC => write!(f, "static"),
            Protocol::VRRP => write!(f, "vrrp"),
        }
    }
}

impl FromStr for Protocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "bfd" => Ok(Protocol::BFD),
            "bgp" => Ok(Protocol::BGP),
            "direct" => Ok(Protocol::DIRECT),
            "isis" => Ok(Protocol::ISIS),
            "ldp" => Ok(Protocol::LDP),
            "ospfv2" => Ok(Protocol::OSPFV2),
            "ospfv3" => Ok(Protocol::OSPFV3),
            "ripv2" => Ok(Protocol::RIPV2),
            "ripng" => Ok(Protocol::RIPNG),
            "static" => Ok(Protocol::STATIC),
            "vrrp" => Ok(Protocol::VRRP),
            _ => Err(()),
        }
    }
}

impl ToYang for Protocol {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Protocol::BFD => "ietf-bfd-types:bfdv1".into(),
            Protocol::BGP => "ietf-bgp:bgp".into(),
            Protocol::DIRECT => "ietf-routing:direct".into(),
            Protocol::ISIS => "ietf-isis:isis".into(),
            Protocol::LDP => "ietf-mpls-ldp:mpls-ldp".into(),
            Protocol::OSPFV2 => "ietf-ospf:ospfv2".into(),
            Protocol::OSPFV3 => "ietf-ospf:ospfv3".into(),
            Protocol::RIPV2 => "ietf-rip:ripv2".into(),
            Protocol::RIPNG => "ietf-rip:ripng".into(),
            Protocol::STATIC => "ietf-routing:static".into(),
            Protocol::VRRP => "holo-vrrp:vrrp".into(),
        }
    }
}

impl TryFromYang for Protocol {
    fn try_from_yang(identity: &str) -> Option<Protocol> {
        match identity {
            "ietf-bfd-types:bfdv1" => Some(Protocol::BFD),
            "ietf-bgp:bgp" => Some(Protocol::BGP),
            "ietf-routing:direct" => Some(Protocol::DIRECT),
            "ietf-isis:isis" => Some(Protocol::ISIS),
            "ietf-mpls-ldp:mpls-ldp" => Some(Protocol::LDP),
            "ietf-ospf:ospfv2" => Some(Protocol::OSPFV2),
            "ietf-ospf:ospfv3" => Some(Protocol::OSPFV3),
            "ietf-rip:ripv2" => Some(Protocol::RIPV2),
            "ietf-rip:ripng" => Some(Protocol::RIPNG),
            "ietf-routing:static" => Some(Protocol::STATIC),
            "holo-vrrp:vrrp" => Some(Protocol::VRRP),
            _ => None,
        }
    }
}
