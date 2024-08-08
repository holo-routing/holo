//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use bytes::BytesMut;
use derive_new::new;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;

pub type SubDomainId = u8;
pub type BfrId = u16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct BierInfo {
    pub sd_id: SubDomainId,
    pub bfr_id: BfrId,
    pub bfr_bss: Vec<Bsl>,
}

#[derive(Debug)]
pub struct BirtEntry {
    pub bfr_prefix: IpAddr,
    pub bfr_nbr: IpAddr,
}

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

impl From<Bsl> for usize {
    fn from(val: Bsl) -> Self {
        match val {
            Bsl::_64 => 64,
            Bsl::_128 => 128,
            Bsl::_256 => 256,
            Bsl::_512 => 512,
            Bsl::_1024 => 1024,
            Bsl::_2048 => 2048,
            Bsl::_4096 => 4096,
        }
    }
}

impl From<Bsl> for u8 {
    // Mapping defined in RFC8296, Section 2.1.2
    fn from(val: Bsl) -> Self {
        match val {
            Bsl::_64 => 1,
            Bsl::_128 => 2,
            Bsl::_256 => 3,
            Bsl::_512 => 4,
            Bsl::_1024 => 5,
            Bsl::_2048 => 6,
            Bsl::_4096 => 7,
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

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
#[derive(Serialize, Deserialize)]
pub struct Bitstring {
    bsl: Bsl,
    bs: BytesMut,
}

impl Bitstring {
    pub fn new(bsl: Bsl) -> Self {
        Self {
            bsl,
            bs: BytesMut::zeroed(bsl.into()),
        }
    }

    pub fn from(id: BfrId, bsl: Bsl) -> Self {
        // pub fn from(bfr: BfrId) -> Self {
        // TODO: Ensure value fit in bitstring and use SI if required.
        let byte = id / 8;
        let idx = (id % 8) + 1;
        let mut bs = Self::new(bsl);
        bs.bs[byte as usize] |= 1 << idx;
        bs
    }

    pub fn bsl(&self) -> Bsl {
        self.bsl
    }
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

impl ToYang for Bsl {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            Bsl::_64 => "64-bit".into(),
            Bsl::_128 => "128-bit".into(),
            Bsl::_256 => "256-bit".into(),
            Bsl::_512 => "512-bit".into(),
            Bsl::_1024 => "1024-bit".into(),
            Bsl::_2048 => "2048-bit".into(),
            Bsl::_4096 => "4096-bit".into(),
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
