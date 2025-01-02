//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bier::BiftId;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

use crate::packet::error::{DecodeError, DecodeResult};

// TLV header size.
pub const TLV_HDR_SIZE: u16 = 4;

// OSPF Router Information (RI) TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#ri-tlv
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum RouterInfoTlvType {
    InformationalCaps = 1,
    FunctionalCaps = 2,
    DynamicHostname = 7,
    SrAlgo = 8,
    SidLabelRange = 9,
    NodeMsd = 12,
    SrLocalBlock = 14,
    SrmsPref = 15,
}

// SID/Label Sub-TLV type.
//
// This Sub-TLV appears in multiple TLVs, some of which don't have a separate
// Sub-TLV registry of their own. Regardless of that, its type value is always
// the same.
const SUBTLV_SID_LABEL: u16 = 1;

// OSPF Router Informational Capability Bits.
//
// IANA registry:
// https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#router-informational-capability
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct RouterInfoCaps: u32 {
        const GR = 1 << 31;
        const GR_HELPER = 1 << 30;
        const STUB_ROUTER = 1 << 29;
        const TE = 1 << 28;
        const P2P_LAN = 1 << 27;
        const EXPERIMENTAL_TE = 1 << 26;
    }
}

//
// OSPF Router Informational Capabilities TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Informational Capabilities                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct RouterInfoCapsTlv(RouterInfoCaps);

// OSPF Router Functional Capability Bits.
//
// IANA registry:
// https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#router-functional-capability
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct RouterFuncCaps: u32 {
    }
}

//
// OSPF Router Functional Capabilities TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Functional Capabilities                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct RouterFuncCapsTlv(RouterFuncCaps);

//
// Dynamic Hostname TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Hostname ...                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct RouterInfoDynamicHostnameTlv {
    pub hostname: String,
}

//
// SR-Algorithm TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Algorithm 1 | Algorithm...  |   Algorithm n |               |
// +-                                                             -+
// |                                                               |
// +                                                               +
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SrAlgoTlv(BTreeSet<IgpAlgoType>);

//
// SID/Label Range TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Range Size                 |   Reserved    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sub-TLVs (variable)                    |
// +-                                                             -+
// |                                                               |
// +                                                               +
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SidLabelRangeTlv {
    pub first: Sid,
    pub range: u32,
}

//
// SR Local Block TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Range Size                 |   Reserved    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sub-TLVs (variable)                    |
// +-                                                             -+
// |                                                               |
// +                                                               +
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SrLocalBlockTlv {
    pub first: Sid,
    pub range: u32,
}

//
// Node/Link MSD TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Type                       |  Length                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    MSD-Type   |  MSD-Value    |  MSD-Type...  |  MSD-Value... |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct MsdTlv(BTreeMap<u8, u8>);

//
// SRMS Preference TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Preference    |                 Reserved                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SrmsPrefTlv(u8);

// Prefix-SID Flags.
//
// For simplicity, use a shared struct for both OSPFv2 and OSPFv3 since the
// flags are the same for both versions (even though they are specified
// separately).
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct PrefixSidFlags: u8 {
        const NP = 0x40;
        const M = 0x20;
        const E = 0x10;
        const V = 0x08;
        const L = 0x04;
    }
}

// (LAN)Adj-SID Flags.
//
// For simplicity, use a shared struct for both OSPFv2 and OSPFv3 since the
// flags are the same for both versions (even though they are specified
// separately).
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AdjSidFlags: u8 {
        const B = 0x80;
        const V = 0x40;
        const L = 0x20;
        const G = 0x10;
        const P = 0x08;
    }
}

// OSPF Grace-LSA's Grace Period TLV.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct GracePeriodTlv(u32);

// OSPF Grace-LSA's Graceful Restart reason TLV.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct GrReasonTlv(u8);

// OSPF Graceful Restart reason value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum GrReason {
    Unknown = 0,
    SoftwareRestart = 1,
    SoftwareUpgrade = 2,
    ControlProcessorSwitchover = 3,
}

//
// BIER Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Sub-domain-ID |      MT-ID    |              BFR-id           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     BAR       |     IPA       |        Reserved               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sub-TLVs (variable)                      |
// +-                                                             -+
// |                                                               |
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct BierSubTlv {
    pub sub_domain_id: u8,
    pub mt_id: u8,
    pub bfr_id: u16,
    pub bar: u8,
    pub ipa: u8,
    pub subtlvs: Vec<BierSubSubTlv>,
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum BierSubSubTlv {
    BierEncapSubSubTlv(BierEncapSubSubTlv),
}

//
// Bier MPLS Encapsulation Sub-Tlv
//
// Encoding format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              Type             |             Length            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Max SI    |                     Label                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |BS Len |                     Reserved                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Bier Non-MPLS Encapsulation Sub-Tlv
//
// Encoding format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              Type             |             Length            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Max SI    |                   BIFT-id                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |BS Len |                     Reserved                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct BierEncapSubSubTlv {
    pub max_si: u8,
    pub id: BierEncapId,
    pub bs_len: u8,
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum BierEncapId {
    Mpls(Label),
    NonMpls(BiftId),
}

impl BierEncapId {
    fn get(self) -> u32 {
        match self {
            Self::Mpls(label) => label.get(),
            Self::NonMpls(bift_id) => bift_id.get(),
        }
    }
}

#[derive(FromPrimitive, ToPrimitive)]
pub enum BierSubTlvType {
    MplsEncap = 41,
    NonMplsEncap = 42,
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct UnknownTlv {
    pub tlv_type: u16,
    pub length: u16,
    pub value: Bytes,
}

// ===== impl BierSubTlv =====

impl BierSubTlv {
    pub(crate) fn decode(_tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        let sub_domain_id = buf.get_u8();
        let mt_id = buf.get_u8();
        let bfr_id = buf.get_u16();
        let bar = buf.get_u8();
        let ipa = buf.get_u8();
        let _reserved = buf.get_u16();
        let mut subtlvs: Vec<BierSubSubTlv> = Vec::new();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let stlv_type = buf.get_u16();

            // Parse and validate Sub-TLV length.
            let stlv_len = buf.get_u16();
            let stlv_wlen = tlv_wire_len(stlv_len);
            if stlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_wlen as usize);
            match BierSubTlvType::from_u16(stlv_type) {
                Some(stlv_type) => {
                    match stlv_type {
                        BierSubTlvType::MplsEncap
                        | BierSubTlvType::NonMplsEncap => {
                            let max_si = buf_stlv.get_u8();
                            let id = buf_stlv.get_u24();
                            let bs_len = (buf_stlv.get_u8() & 0xf0) >> 4;

                            let id = match stlv_type {
                                BierSubTlvType::MplsEncap => {
                                    BierEncapId::Mpls(Label::new(id))
                                }
                                BierSubTlvType::NonMplsEncap => {
                                    BierEncapId::NonMpls(BiftId::new(id))
                                }
                            };
                            subtlvs.push(BierSubSubTlv::BierEncapSubSubTlv(
                                BierEncapSubSubTlv { max_si, id, bs_len },
                            ));
                        }
                    };
                }
                None => {
                    // Ignore unknown Sub-TLV
                    continue;
                }
            }
        }

        Ok(BierSubTlv {
            sub_domain_id,
            mt_id,
            bfr_id,
            bar,
            ipa,
            subtlvs,
        })
    }

    pub(crate) fn encode(
        &self,
        buf: &mut BytesMut,
        stlv_type: impl ToPrimitive,
    ) {
        let start_pos = tlv_encode_start(buf, stlv_type);
        buf.put_u8(self.sub_domain_id);
        buf.put_u8(self.mt_id);
        buf.put_u16(self.bfr_id);
        buf.put_u8(self.bar);
        buf.put_u8(self.ipa);
        buf.put_u16(0);
        for subtlv in &self.subtlvs {
            match subtlv {
                BierSubSubTlv::BierEncapSubSubTlv(encap) => {
                    let start_pos =
                        tlv_encode_start(buf, BierSubTlvType::NonMplsEncap);
                    buf.put_u8(encap.max_si);
                    buf.put_u24(encap.id.clone().get());
                    buf.put_u8((encap.bs_len << 4) & 0xf0);
                    buf.put_u24(0);
                    tlv_encode_end(buf, start_pos);
                }
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl RouterInfoCapsTlv =====

impl RouterInfoCapsTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum TLV length.
        if tlv_len < 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        // Read capabilities (ignoring unknown ones).
        let caps = buf.get_u32();
        let caps = RouterInfoCaps::from_bits_truncate(caps);
        let caps = RouterInfoCapsTlv(caps);

        Ok(caps)
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, RouterInfoTlvType::InformationalCaps);
        buf.put_u32(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &RouterInfoCaps {
        &self.0
    }
}

impl From<RouterInfoCaps> for RouterInfoCapsTlv {
    fn from(caps: RouterInfoCaps) -> RouterInfoCapsTlv {
        RouterInfoCapsTlv(caps)
    }
}

// ===== impl RouterFuncCapsTlv =====

impl RouterFuncCapsTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum TLV length.
        if tlv_len < 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        // Read capabilities (ignoring unknown ones).
        let caps = buf.get_u32();
        let caps = RouterFuncCaps::from_bits_truncate(caps);
        let caps = RouterFuncCapsTlv(caps);

        Ok(caps)
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, RouterInfoTlvType::FunctionalCaps);
        buf.put_u32(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &RouterFuncCaps {
        &self.0
    }
}

impl From<RouterFuncCaps> for RouterFuncCapsTlv {
    fn from(caps: RouterFuncCaps) -> RouterFuncCapsTlv {
        RouterFuncCapsTlv(caps)
    }
}

// ===== impl DynamicHostnameTlv ====

impl RouterInfoDynamicHostnameTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut hostname = String::new();
        for _ in 0..tlv_len {
            let c = buf.get_u8();
            if c == 0 {
                break;
            }
            hostname.push(c as char);
        }

        Ok(RouterInfoDynamicHostnameTlv { hostname })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, RouterInfoTlvType::DynamicHostname);
        for c in self.hostname.chars() {
            buf.put_u8(c as u8);
        }
        //padding with 4 octet allignment
        let padding = 4 - (self.hostname.len() % 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &str {
        &self.hostname
    }
}

// ===== impl SrAlgoTlv =====

impl SrAlgoTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = BTreeSet::new();
        for _ in 0..tlv_len {
            let algo = buf.get_u8();
            let algo = match IgpAlgoType::from_u8(algo) {
                Some(algo) => algo,
                None => {
                    // Unsupported algorithm - ignore.
                    continue;
                }
            };
            list.insert(algo);
        }

        Ok(SrAlgoTlv(list))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterInfoTlvType::SrAlgo);
        for algo in &self.0 {
            buf.put_u8(*algo as u8);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &BTreeSet<IgpAlgoType> {
        &self.0
    }
}

// ===== impl SidLabelRangeTlv =====

impl SidLabelRangeTlv {
    pub(crate) fn decode(_tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut first = None;
        let range = buf.get_u24();
        let _reserved = buf.get_u8();

        // Parse Sub-TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let stlv_type = buf.get_u16();

            // Parse and validate Sub-TLV length.
            let stlv_len = buf.get_u16();
            let stlv_wlen = tlv_wire_len(stlv_len);
            if stlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_wlen as usize);
            match stlv_type {
                SUBTLV_SID_LABEL => {
                    let sid = match stlv_len {
                        4 => Sid::Index(buf_stlv.get_u32()),
                        3 => {
                            let label = buf_stlv.get_u24() & Label::VALUE_MASK;
                            Sid::Label(Label::new(label))
                        }
                        _ => {
                            // Ignore invalid SID.
                            continue;
                        }
                    };
                    first = Some(sid);
                }
                _ => {
                    // Ignore unknown Sub-TLV.
                }
            }
        }

        match first {
            Some(first) => Ok(SidLabelRangeTlv { first, range }),
            None => Err(DecodeError::MissingRequiredTlv(SUBTLV_SID_LABEL)),
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterInfoTlvType::SidLabelRange);
        buf.put_u24(self.range);
        buf.put_u8(0);

        buf.put_u16(SUBTLV_SID_LABEL);
        match self.first {
            Sid::Index(index) => {
                buf.put_u16(4);
                buf.put_u32(index);
            }
            Sid::Label(label) => {
                buf.put_u16(3);
                buf.put_u24(label.get());
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl SrLocalBlockTlv =====

impl SrLocalBlockTlv {
    pub(crate) fn decode(_tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut first = None;
        let range = buf.get_u24();
        let _reserved = buf.get_u8();

        // Parse Sub-TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let stlv_type = buf.get_u16();

            // Parse and validate Sub-TLV length.
            let stlv_len = buf.get_u16();
            let stlv_wlen = tlv_wire_len(stlv_len);
            if stlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_wlen as usize);
            match stlv_type {
                SUBTLV_SID_LABEL => {
                    let sid = match stlv_len {
                        4 => Sid::Index(buf_stlv.get_u32()),
                        3 => {
                            let label = buf_stlv.get_u24() & Label::VALUE_MASK;
                            Sid::Label(Label::new(label))
                        }
                        _ => {
                            // Ignore invalid SID.
                            continue;
                        }
                    };
                    first = Some(sid);
                }
                _ => {
                    // Ignore unknown Sub-TLV.
                }
            }
        }

        match first {
            Some(first) => Ok(SrLocalBlockTlv { first, range }),
            None => Err(DecodeError::MissingRequiredTlv(SUBTLV_SID_LABEL)),
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterInfoTlvType::SrLocalBlock);
        buf.put_u24(self.range);
        buf.put_u8(0);

        buf.put_u16(SUBTLV_SID_LABEL);
        match self.first {
            Sid::Index(index) => {
                buf.put_u16(4);
                buf.put_u32(index);
            }
            Sid::Label(label) => {
                buf.put_u16(3);
                buf.put_u24(label.get());
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl MsdTlv =====

impl MsdTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len % 2 != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let mut msds = BTreeMap::new();
        let mut tlv_rlen = tlv_len;
        while tlv_rlen >= 2 {
            let msd_type = buf.get_u8();
            let msd_value = buf.get_u8();
            msds.insert(msd_type, msd_value);

            tlv_rlen -= 2;
        }

        Ok(MsdTlv(msds))
    }

    pub(crate) fn encode(&self, tlv_type: u16, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, tlv_type);
        for (msd_type, msd_value) in &self.0 {
            buf.put_u8(*msd_type);
            buf.put_u8(*msd_value);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &BTreeMap<u8, u8> {
        &self.0
    }
}

// ===== impl GracePeriodTlv =====

impl GracePeriodTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let period = buf.get_u32();

        Ok(GracePeriodTlv(period))
    }

    pub(crate) fn encode(&self, tlv_type: u16, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, tlv_type);
        buf.put_u32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

// ===== impl GrReasonTlv =====

impl GrReasonTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len != 1 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let reason = buf.get_u8();

        Ok(GrReasonTlv(reason))
    }

    pub(crate) fn encode(&self, tlv_type: u16, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, tlv_type);
        buf.put_u8(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u8 {
        self.0
    }
}

// ===== impl GrReason =====

impl std::fmt::Display for GrReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrReason::Unknown => {
                write!(f, "unknown")
            }
            GrReason::SoftwareRestart => {
                write!(f, "software restart")
            }
            GrReason::SoftwareUpgrade => {
                write!(f, "software upgrade")
            }
            GrReason::ControlProcessorSwitchover => {
                write!(f, "control plane switchover")
            }
        }
    }
}

// ===== impl SrmsPrefTlv =====

impl SrmsPrefTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let pref = buf.get_u8();

        Ok(SrmsPrefTlv(pref))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterInfoTlvType::SrmsPref);
        buf.put_u8(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u8 {
        self.0
    }
}

// ===== global functions =====

// The TLV length is padded to 4-byte alignment.
pub(crate) fn tlv_wire_len(tlv_len: u16) -> u16 {
    (tlv_len + 3) & !0x03
}

pub(crate) fn tlv_encode_start(
    buf: &mut BytesMut,
    tlv_type: impl ToPrimitive,
) -> usize {
    let start_pos = buf.len();
    buf.put_u16(tlv_type.to_u16().unwrap());
    // The TLV length will be rewritten later.
    buf.put_u16(0);
    start_pos
}

pub(crate) fn tlv_encode_end(buf: &mut BytesMut, start_pos: usize) {
    let tlv_len = (buf.len() - start_pos) as u16 - TLV_HDR_SIZE;

    // Rewrite TLV length.
    buf[start_pos + 2..start_pos + 4].copy_from_slice(&tlv_len.to_be_bytes());

    // Add padding if necessary.
    let tlv_wlen = tlv_wire_len(tlv_len);
    if tlv_wlen != tlv_len {
        buf.put_bytes(0, (tlv_wlen - tlv_len) as usize);
    }
}
