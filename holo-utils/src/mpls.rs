//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use derive_new::new;
use holo_yang::ToYang;
use serde::{Deserialize, Serialize};

// MPLS label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Label(u32);

// MPLS label range.
#[derive(Clone, Copy, Debug, Eq, Ord, new, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LabelRange {
    pub lower_bound: u32,
    pub upper_bound: u32,
}

impl Label {
    pub const VALUE_MASK: u32 = 0x000FFFFF;

    // Well-known MPLS labels.
    pub const IPV4_EXPLICIT_NULL: u32 = 0;
    pub const ROUTER_ALERT: u32 = 1;
    pub const IPV6_EXPLICIT_NULL: u32 = 2;
    pub const IMPLICIT_NULL: u32 = 3;
    pub const ELI: u32 = 7;
    pub const GAL: u32 = 13;
    pub const OAM_ALERT: u32 = 14;
    pub const EXTENSION: u32 = 15;

    // MPLS label ranges.
    pub const RESERVED_RANGE: std::ops::RangeInclusive<u32> = 0..=15;
    pub const UNRESERVED_RANGE: std::ops::RangeInclusive<u32> = 16..=1048575;

    pub fn new(label: u32) -> Label {
        if label > *Self::UNRESERVED_RANGE.end() {
            panic!("invalid label value: {}", label);
        }
        Label(label)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        Self::RESERVED_RANGE.contains(&self.0)
    }
}

// ===== impl Label =====

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Label::IPV4_EXPLICIT_NULL => write!(f, "ipv4-explicit-null"),
            Label::ROUTER_ALERT => write!(f, "router-alert"),
            Label::IPV6_EXPLICIT_NULL => write!(f, "ipv6-explicit-null"),
            Label::IMPLICIT_NULL => write!(f, "implicit-null"),
            Label::ELI => write!(f, "entropy-label-indicator"),
            Label::GAL => write!(f, "generic-associated-channel"),
            Label::OAM_ALERT => write!(f, "oam-alert"),
            Label::EXTENSION => write!(f, "extension"),
            _ => write!(f, "{}", self.0),
        }
    }
}

impl ToYang for Label {
    fn to_yang(&self) -> String {
        match self.0 {
            Label::IPV4_EXPLICIT_NULL => {
                "ietf-routing-types:ipv4-explicit-null-label".to_owned()
            }
            Label::ROUTER_ALERT => {
                "ietf-routing-types:router-alert-label".to_owned()
            }
            Label::IPV6_EXPLICIT_NULL => {
                "ietf-routing-types:ipv6-explicit-null-label".to_owned()
            }
            Label::IMPLICIT_NULL => {
                "ietf-routing-types:implicit-null-label".to_owned()
            }
            Label::ELI => {
                "ietf-routing-types:entropy-label-indicator".to_owned()
            }
            Label::GAL => "ietf-routing-types:gal-label".to_owned(),
            Label::OAM_ALERT => "ietf-routing-types:oam-alert-label".to_owned(),
            Label::EXTENSION => "ietf-routing-types:extension-label".to_owned(),
            _ => format!("{}", self.0),
        }
    }
}
