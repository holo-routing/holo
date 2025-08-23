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
use tracing::warn;

use crate::ip::AddressFamily;
use crate::mpls::Label;

pub type SubDomainId = u8;
pub type BfrId = u16;
pub type SetIdentifier = u8;
pub type Bift = HashMap<
    (SubDomainId, IpAddr, SetIdentifier),
    (Bitstring, Vec<(BfrId, IpAddr)>, u32, String),
>;

#[cfg(feature = "fastclick")]
pub async fn bift_sync_fastclick(bift: &Bift) {
    for ((_sd_id, nbr, _si), (bs, ids, idx, name)) in bift.iter() {
        // List the position of bits that are enabled in the bitstring, this is
        // required by the Bitvectors of Fastclick but this not ideal.
        // FIXME: Find a better way to share a bitstring with Fastclick
        let bs = bs
            .bs
            .iter()
            .enumerate()
            .flat_map(|(idx, b)| {
                (0..8)
                    .filter_map(|i| {
                        if b & (1 << i) != 0 {
                            Some(format!("{}", idx * 8 + i))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<String>>()
            })
            .collect::<Vec<String>>()
            .join(",");

        // Batching BFRs having the same FBM
        let bfrs = ids
            .iter()
            .map(|(id, prefix)| format!("{:#?}_{:#?}", id, prefix))
            .collect::<Vec<String>>()
            .join(",");
        let body = format!("{} {:#?} {} {} {}", bs, nbr, idx, name, bfrs);

        // TODO: Use gRPC rather than plain HTTP
        let client = reqwest::Client::new();
        let _res = client
            // TODO: Make Fastclick BIFT URI configurable through YANG model
            .post("http://127.0.0.1/bift0/add")
            .body(body)
            .send()
            .await;
    }
}

#[allow(unused_variables)]
pub fn bift_sync(bift: Bift) {
    #[cfg(feature = "fastclick")]
    {
        tokio::task::spawn(async move {
            bift_sync_fastclick(&bift).await;
        });
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidBfrId,
    InvalidBitstring,
}

impl Error {
    pub fn log(&self) {
        match self {
            Error::InvalidBfrId => {
                warn!("{}", self);
            }
            Error::InvalidBitstring => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidBfrId => {
                write!(f, "invalid BfrId")
            }
            Error::InvalidBitstring => {
                write!(f, "invalid Bitstring")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum BierEncapId {
    Mpls(Label),
    NonMpls(BiftId),
}

impl BierEncapId {
    pub fn get(self) -> u32 {
        match self {
            Self::Mpls(label) => label.get(),
            Self::NonMpls(bift_id) => bift_id.get(),
        }
    }
}

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
    pub ifindex: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct BiftId(u32);

impl BiftId {
    pub const VALUE_MASK: u32 = 0x000FFFFF;

    pub fn new(bift_id: u32) -> Self {
        Self(bift_id & Self::VALUE_MASK)
    }

    pub fn get(&self) -> u32 {
        self.0
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

// Type of BIER configuration events.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BierCfgEvent {
    SubDomainUpdate(AddressFamily),
    EncapUpdate(AddressFamily),
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

pub type BierOutBiftDefined = u32;
pub type BierOutBiftEncoding = bool;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BierOutBiftId {
    Defined(BierOutBiftDefined),
    Encoding(BierOutBiftEncoding),
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BiftNbr {
    pub bfr_nbr: IpAddr,
    pub encap_type: BierEncapsulationType,
    pub out_bift_id: BierOutBiftId,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierBift {
    pub bsl: Bsl,
    pub nbr: BTreeMap<IpAddr, BiftNbr>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierBiftCfg {
    pub bfr_id: BfrId,
    pub birt: BTreeMap<Bsl, BierBift>,
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
    pub bs: BytesMut,
    pub si: SetIdentifier,
}

impl Bitstring {
    pub fn new(bsl: Bsl) -> Self {
        let len: usize = bsl.into();
        Self {
            bsl,
            bs: BytesMut::zeroed(len / 8),
            si: 0,
        }
    }

    pub fn or(&self, rhs: Self) -> Result<Self, Error> {
        if self.si != rhs.si || self.bsl != rhs.bsl {
            return Err(Error::InvalidBitstring);
        }
        let mut ret = Self::new(self.bsl);
        ret.si = self.si;
        for i in 0..self.bs.len() {
            ret.bs[i] = self.bs[i] | rhs.bs[i];
        }
        Ok(ret)
    }

    pub fn mut_or(&mut self, rhs: Self) -> Result<(), Error> {
        let bs = self.or(rhs)?;
        self.bs = bs.bs;
        Ok(())
    }

    pub fn from(id: BfrId, bsl: Bsl) -> Result<Self, Error> {
        if id == 0 {
            return Err(Error::InvalidBfrId);
        }
        let mut bs = Self::new(bsl);
        let bsl = usize::from(bsl);
        bs.si = ((id - 1) as usize / bsl) as u8;

        let id = (id - bs.si as u16 * bsl as u16) - 1;

        let byte = id / 8;
        let idx = id % 8;
        bs.bs[byte as usize] |= 1 << idx;

        Ok(bs)
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

#[cfg(test)]
mod test_bitstring {
    use super::*;

    fn get_64bits_bs(id: BfrId) -> Bitstring {
        let bsl = Bsl::try_from(1).unwrap(); // 64-bit
        Bitstring::from(id, bsl).unwrap()
    }

    #[test]
    fn test_bfr_id_0() {
        let bsl = Bsl::try_from(1).unwrap();
        if Bitstring::from(0, bsl).is_ok() {
            unreachable!();
        }
    }

    #[test]
    fn test_bsl_64bits_id_1() {
        let bs = get_64bits_bs(1);
        assert!(bs.si == 0);
        assert!(bs.bsl == Bsl::_64);
        println!("{:#x?}", bs.bs);
        assert!(bs.bs[0] == 0b1);
        assert!(bs.bs[1] == 0);
        assert!(bs.bs[2] == 0);
        assert!(bs.bs[3] == 0);
        assert!(bs.bs[4] == 0);
        assert!(bs.bs[5] == 0);
        assert!(bs.bs[6] == 0);
        assert!(bs.bs[7] == 0);
    }

    #[test]
    fn test_bsl_64bits_si0() {
        let bs = get_64bits_bs(64);
        assert!(bs.si == 0);
        assert!(bs.bsl == Bsl::_64);
        println!("{:#x?}", bs.bs);
        assert!(bs.bs[0] == 0);
        assert!(bs.bs[1] == 0);
        assert!(bs.bs[2] == 0);
        assert!(bs.bs[3] == 0);
        assert!(bs.bs[4] == 0);
        assert!(bs.bs[5] == 0);
        assert!(bs.bs[6] == 0);
        assert!(bs.bs[7] == 0b1000_0000);
    }

    #[test]
    fn test_bsl_64bits_si1() {
        let bs = get_64bits_bs(65);
        assert!(bs.si == 1);
        assert!(bs.bsl == Bsl::_64);
        println!("{:#x?}", bs.bs);
        assert!(bs.bs[0] == 1);
        assert!(bs.bs[1] == 0);
        assert!(bs.bs[2] == 0);
        assert!(bs.bs[3] == 0);
        assert!(bs.bs[4] == 0);
        assert!(bs.bs[5] == 0);
        assert!(bs.bs[6] == 0);
        assert!(bs.bs[7] == 0);
    }
}
