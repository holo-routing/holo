//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;
use crate::mpls::{Label, LabelRange};

// IGP Algorithm Types.
//
// IANA registry:
// https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml#igp-algorithm-types
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum IgpAlgoType {
    Spf = 0,
    StrictSpf = 1,
}

// IGP MSD-Types.
//
// IANA registry:
// https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml#igp-msd-types
#[derive(Clone, Copy, Debug, Eq, Ord, FromPrimitive, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum MsdType {
    BaseMplsImposition = 1,
}

// Segment Routing SID.
#[derive(Clone, Copy, Debug, EnumAsInner, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Sid {
    Index(u32),
    Label(Label),
}

// Prefix-SID last-hop behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum SidLastHopBehavior {
    ExpNull,
    NoPhp,
    Php,
}

// Segment Routing global configuration.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct SrCfg {
    #[serde(with = "vectorize")]
    pub prefix_sids: HashMap<(IpNetwork, IgpAlgoType), SrCfgPrefixSid>,
    pub srgb: BTreeSet<LabelRange>,
    pub srlb: BTreeSet<LabelRange>,
}

// Prefix-SID configuration.
#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct SrCfgPrefixSid {
    pub index: u32,
    pub last_hop: SidLastHopBehavior,
}

// Type of Segment Routing configuration change.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SrCfgEvent {
    LabelRangeUpdate,
    PrefixSidUpdate(AddressFamily),
}

// ===== impl IgpAlgoType =====

impl ToYang for IgpAlgoType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            IgpAlgoType::Spf => {
                "ietf-segment-routing-common:prefix-sid-algorithm-shortest-path"
                    .into()
            }
            IgpAlgoType::StrictSpf => {
                "ietf-segment-routing-common:prefix-sid-algorithm-strict-spf"
                    .into()
            }
        }
    }
}

impl TryFromYang for IgpAlgoType {
    fn try_from_yang(value: &str) -> Option<IgpAlgoType> {
        match value {
            "ietf-segment-routing-common:prefix-sid-algorithm-shortest-path" => {
                Some(IgpAlgoType::Spf)
            }
            "ietf-segment-routing-common:prefix-sid-algorithm-strict-spf" => {
                Some(IgpAlgoType::StrictSpf)
            }
            _ => None,
        }
    }
}

// ===== impl Sid =====

impl Sid {
    pub fn value(&self) -> u32 {
        match self {
            Sid::Index(index) => *index,
            Sid::Label(label) => label.get(),
        }
    }
}

// ===== impl SidLastHopBehavior =====

impl TryFromYang for SidLastHopBehavior {
    fn try_from_yang(value: &str) -> Option<SidLastHopBehavior> {
        match value {
            "explicit-null" => Some(SidLastHopBehavior::ExpNull),
            "no-php" => Some(SidLastHopBehavior::NoPhp),
            "php" => Some(SidLastHopBehavior::Php),
            _ => None,
        }
    }
}
