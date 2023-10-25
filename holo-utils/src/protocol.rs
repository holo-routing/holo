//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

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
    DIRECT,
    LDP,
    OSPFV2,
    OSPFV3,
    RIPV2,
    RIPNG,
}

// ===== impl Protocol =====

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::BFD => write!(f, "bfd"),
            Protocol::DIRECT => write!(f, "direct"),
            Protocol::LDP => write!(f, "ldp"),
            Protocol::OSPFV2 => write!(f, "ospfv2"),
            Protocol::OSPFV3 => write!(f, "ospfv3"),
            Protocol::RIPV2 => write!(f, "ripv2"),
            Protocol::RIPNG => write!(f, "ripng"),
        }
    }
}

impl FromStr for Protocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "bfd" => Ok(Protocol::BFD),
            "direct" => Ok(Protocol::DIRECT),
            "ldp" => Ok(Protocol::LDP),
            "ospfv2" => Ok(Protocol::OSPFV2),
            "ospfv3" => Ok(Protocol::OSPFV3),
            "ripv2" => Ok(Protocol::RIPV2),
            "ripng" => Ok(Protocol::RIPNG),
            _ => Err(()),
        }
    }
}

impl ToYang for Protocol {
    fn to_yang(&self) -> String {
        match self {
            Protocol::BFD => "ietf-bfd-types:bfdv1".to_owned(),
            Protocol::DIRECT => "ietf-routing:direct".to_owned(),
            Protocol::LDP => "ietf-mpls-ldp:mpls-ldp".to_owned(),
            Protocol::OSPFV2 => "ietf-ospf:ospfv2".to_owned(),
            Protocol::OSPFV3 => "ietf-ospf:ospfv3".to_owned(),
            Protocol::RIPV2 => "ietf-rip:ripv2".to_owned(),
            Protocol::RIPNG => "ietf-rip:ripng".to_owned(),
        }
    }
}

impl TryFromYang for Protocol {
    fn try_from_yang(identity: &str) -> Option<Protocol> {
        match identity {
            "ietf-bfd-types:bfdv1" => Some(Protocol::BFD),
            "ietf-routing:direct" => Some(Protocol::DIRECT),
            "ietf-mpls-ldp:mpls-ldp" => Some(Protocol::LDP),
            "ietf-ospf:ospfv2" => Some(Protocol::OSPFV2),
            "ietf-ospf:ospfv3" => Some(Protocol::OSPFV3),
            "ietf-rip:ripv2" => Some(Protocol::RIPV2),
            "ietf-rip:ripng" => Some(Protocol::RIPNG),
            _ => None,
        }
    }
}
