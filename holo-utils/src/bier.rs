//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use derive_new::new;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;

pub type SubDomainId = u8;
pub type BfrId = u16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct BiftId(u32);

impl BiftId {
    pub const VALUE_MASK: u32 = 0x000FFFFF;

    pub fn new(bift_id: u32) -> Self {
        Self(bift_id)
    }

    pub fn get(&self) -> u32 {
        self.0 & Self::VALUE_MASK
    }
}

#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct BierCfg {
    #[serde(with = "vectorize")]
    pub sd_cfg: BTreeMap<(SubDomainId, AddressFamily), BierSubDomainCfg>,
    #[serde(with = "vectorize")]
    pub bift_cfg: HashMap<BfrId, BierBiftCfg>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierSubDomainCfg {
    pub sd_id: SubDomainId,
    pub af: AddressFamily,
    pub bfr_prefix: IpNetwork,
    pub underlay_protocol: UnderlayProtocolType,
    pub mt_id: u8,
    pub bfr_id: BfrId,
    pub bsl: Bsl,
    pub ipa: u8,
    pub bar: u8,
    pub load_balance_num: u8,
    #[serde(with = "vectorize")]
    pub encap: BTreeMap<(Bsl, BierEncapsulationType), BierEncapsulation>,
}

pub type BierInBiftIdBase = u32;
pub type BierInBiftIdEncoding = bool;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BierInBiftId {
    Base(BierInBiftIdBase),
    Encoding(BierInBiftIdEncoding),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierEncapsulation {
    pub bsl: Bsl,
    pub encap_type: BierEncapsulationType,
    pub max_si: u8,
    pub in_bift_id: BierInBiftId,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierBiftCfg {
    // TODO
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BierEncapsulationType {
    Mpls,
    Ipv6,
    Ethernet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum UnderlayProtocolType {
    IsIs,
    Ospf,
    Bgp,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum Bsl {
    _64,
    _128,
    _256,
    _512,
    _1024,
    _2048,
    _4096,
}

// ===== YANG impl =====

impl TryFromYang for UnderlayProtocolType {
    fn try_from_yang(value: &str) -> Option<Self> {
        match value {
            "IS-IS" => Some(Self::IsIs),
            "OSPF" => Some(Self::Ospf),
            "BGP" => Some(Self::Bgp),
            _ => None,
        }
    }
}

impl TryFromYang for Bsl {
    fn try_from_yang(value: &str) -> Option<Self> {
        match value {
            "64-bit" => Some(Bsl::_64),
            "128-bit" => Some(Bsl::_128),
            "256-bit" => Some(Bsl::_256),
            "512-bit" => Some(Bsl::_512),
            "1024-bit" => Some(Bsl::_1024),
            "2048-bit" => Some(Bsl::_2048),
            "4096-bit" => Some(Bsl::_4096),
            _ => None,
        }
    }
}

impl Into<u8> for Bsl {
    // Mapping defined in RFC8296, Section 2.1.2
    fn into(self) -> u8 {
        match self {
            Self::_64 => 1,
            Self::_128 => 2,
            Self::_256 => 3,
            Self::_512 => 4,
            Self::_1024 => 5,
            Self::_2048 => 6,
            Self::_4096 => 7,
        }
    }
}

impl TryFrom<u8> for Bsl {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::_64),
            2 => Ok(Self::_128),
            3 => Ok(Self::_256),
            4 => Ok(Self::_512),
            5 => Ok(Self::_1024),
            6 => Ok(Self::_2048),
            7 => Ok(Self::_4096),
            _ => Err("Not Supported"),
        }
    }
}

impl TryFromYang for BierEncapsulationType {
    fn try_from_yang(value: &str) -> Option<Self> {
        match value {
            "ietf-bier:bier-encapsulation-mpls" => {
                Some(BierEncapsulationType::Mpls)
            }
            "ietf-bier:bier-encapsulation-ipv6" => {
                Some(BierEncapsulationType::Ipv6)
            }
            "ietf-bier:bier-encapsulation-ethernet" => {
                Some(BierEncapsulationType::Ethernet)
            }
            _ => None,
        }
    }
}

impl ToYang for BierEncapsulationType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Self::Mpls => "ietf-bier:bier-encapsulation-mpls".into(),
            Self::Ipv6 => "ietf-bier:bier-encapsulation-ipv6".into(),
            Self::Ethernet => "ietf-bier:bier-encapsulation-ethernet".into(),
        }
    }
}
