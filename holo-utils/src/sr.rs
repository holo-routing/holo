//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{BTreeSet, HashMap};

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

use crate::mpls::Label;

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
    pub srgb: BTreeSet<SrCfgLabelRange>,
    pub srlb: BTreeSet<SrCfgLabelRange>,
}

// Prefix-SID configuration.
#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct SrCfgPrefixSid {
    pub index: u32,
    pub last_hop: SidLastHopBehavior,
}

// Label range configuration.
#[derive(Clone, Debug, Eq, Ord, new, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct SrCfgLabelRange {
    pub lower_bound: u32,
    pub upper_bound: u32,
}

// ===== impl IgpAlgoType =====

impl ToYang for IgpAlgoType {
    fn to_yang(&self) -> String {
        match self {
            IgpAlgoType::Spf => "prefix-sid-algorithm-shortest-path".to_owned(),
            IgpAlgoType::StrictSpf => {
                "prefix-sid-algorithm-strict-spf".to_owned()
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
