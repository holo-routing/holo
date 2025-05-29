//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeSet;

use derive_new::new;
use holo_yang::ToYang;
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;

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

// MPLS label manager.
#[derive(Debug)]
pub struct LabelManager {
    // Next dynamic label.
    next_dynamic: u32,
    // Reserved label ranges.
    reserved_ranges: BTreeSet<LabelRange>,
}

// MPLS label manager errors.
#[derive(Debug)]
pub enum LabelManagerError {
    LabelRangeInvalid,
    LabelRangeUnavailable,
    LabelSpaceExhausted,
}

// ===== impl Label =====

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
            panic!("invalid label value: {label}");
        }
        Label(label)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        Self::RESERVED_RANGE.contains(&self.0)
    }

    pub fn is_implicit_null(&self) -> bool {
        self.0 == Self::IMPLICIT_NULL
    }

    pub const fn implicit_null() -> Label {
        Label(Self::IMPLICIT_NULL)
    }

    pub const fn explicit_null(af: AddressFamily) -> Label {
        match af {
            AddressFamily::Ipv4 => Label(Self::IPV4_EXPLICIT_NULL),
            AddressFamily::Ipv6 => Label(Self::IPV6_EXPLICIT_NULL),
        }
    }
}

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
    fn to_yang(&self) -> Cow<'static, str> {
        match self.0 {
            Label::IPV4_EXPLICIT_NULL => {
                "ietf-routing-types:ipv4-explicit-null-label".into()
            }
            Label::ROUTER_ALERT => {
                "ietf-routing-types:router-alert-label".into()
            }
            Label::IPV6_EXPLICIT_NULL => {
                "ietf-routing-types:ipv6-explicit-null-label".into()
            }
            Label::IMPLICIT_NULL => {
                "ietf-routing-types:implicit-null-label".into()
            }
            Label::ELI => "ietf-routing-types:entropy-label-indicator".into(),
            Label::GAL => "ietf-routing-types:gal-label".into(),
            Label::OAM_ALERT => "ietf-routing-types:oam-alert-label".into(),
            Label::EXTENSION => "ietf-routing-types:extension-label".into(),
            _ => self.0.to_string().into(),
        }
    }
}

// ===== impl LabelRange =====

impl LabelRange {
    // Checks if this label range overlaps with another.
    fn overlaps(&self, other: &LabelRange) -> bool {
        self.lower_bound < other.upper_bound
            && self.upper_bound > other.lower_bound
    }
}

// ===== impl LabelManager =====

// This is a prototype implementation with the following limitations:
// - Dynamic labels are assigned sequentially using a non-decreasing counter,
//   and they cannot be released back to the label pool.
// - Reservation of label ranges does not check for collisions with existing
//   dynamic labels.
impl LabelManager {
    // Reserves a label range.
    pub fn range_reserve(
        &mut self,
        range: LabelRange,
    ) -> Result<(), LabelManagerError> {
        // Check if the label range is valid.
        if !Label::UNRESERVED_RANGE.contains(&range.lower_bound)
            || !Label::UNRESERVED_RANGE.contains(&range.upper_bound)
        {
            return Err(LabelManagerError::LabelRangeInvalid);
        }

        // Check for overlaps with existing reserved ranges.
        if self
            .reserved_ranges
            .iter()
            .any(|reserved_range| range.overlaps(reserved_range))
        {
            return Err(LabelManagerError::LabelRangeUnavailable);
        }

        // Allocate requested label range.
        self.reserved_ranges.insert(range);

        Ok(())
    }

    // Releases a label range.
    pub fn range_release(&mut self, range: LabelRange) {
        self.reserved_ranges.remove(&range);
    }

    // Allocates a dynamic label.
    pub fn label_request(&mut self) -> Result<Label, LabelManagerError> {
        // Check if the label space was exhausted.
        if self.next_dynamic == *Label::UNRESERVED_RANGE.end() {
            return Err(LabelManagerError::LabelSpaceExhausted);
        }

        // Allocate label.
        self.next_dynamic += 1;
        let label = Label::new(self.next_dynamic);

        Ok(label)
    }

    // Releases a dynamic label.
    pub fn label_release(&mut self, _label: Label) {}
}

impl Default for LabelManager {
    fn default() -> LabelManager {
        LabelManager {
            next_dynamic: *Label::RESERVED_RANGE.end(),
            reserved_ranges: Default::default(),
        }
    }
}

// ===== impl LabelManagerError =====

impl std::fmt::Display for LabelManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LabelManagerError::LabelRangeInvalid => {
                write!(f, "Invalid label range")
            }
            LabelManagerError::LabelRangeUnavailable => {
                write!(f, "Label range is unavailable")
            }
            LabelManagerError::LabelSpaceExhausted => {
                write!(f, "Label space has been exhausted")
            }
        }
    }
}

impl std::error::Error for LabelManagerError {}
