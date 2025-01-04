//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{btree_map, BTreeMap};
use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use ipnetwork::Ipv4Network;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::ospfv2::packet::lsa::{LsaRouterLinkType, LsaUnknown};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::lsa::{AdjSidVersion, PrefixSidVersion};
use crate::packet::tlv::{
    tlv_encode_end, tlv_encode_start, tlv_wire_len, AdjSidFlags,
    DynamicHostnameTlv, GrReasonTlv, GracePeriodTlv, MsdTlv, PrefixSidFlags,
    RouterFuncCapsTlv, RouterInfoCapsTlv, RouterInfoTlvType, SidLabelRangeTlv,
    SrAlgoTlv, SrLocalBlockTlv, SrmsPrefTlv, UnknownTlv, TLV_HDR_SIZE,
};

// OSPFv2 opaque LSA types.
//
// IANA registry:
// https://www.iana.org/assignments/ospf-opaque-types/ospf-opaque-types.xhtml#ospf-opaque-types-2
#[derive(Clone, Copy, Debug, Eq, Ord, FromPrimitive, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum LsaOpaqueType {
    Te = 1,
    Grace = 3,
    RouterInfo = 4,
    ExtPrefix = 7,
    ExtLink = 8,
}

// OSPFv2 opaque LSA ID.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct OpaqueLsaId {
    pub opaque_type: u8,
    pub opaque_id: u32,
}

#[derive(Clone, Debug, EnumAsInner, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaOpaque {
    Grace(LsaGrace),
    RouterInfo(LsaRouterInfo),
    ExtPrefix(LsaExtPrefix),
    ExtLink(LsaExtLink),
    Unknown(LsaUnknown),
}

// OSPFv2 Grace LSA Top Level TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-13
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum GraceTlvType {
    GracePeriod = 1,
    GrReason = 2,
    InterfaceAddr = 3,
}

//
// OSPFv2 Grace Opaque LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                            TLVs                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaGrace {
    pub grace_period: Option<GracePeriodTlv>,
    pub gr_reason: Option<GrReasonTlv>,
    pub addr: Option<GrInterfaceAddrTlv>,
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// OSPFv2 Grace-LSA's IP interface address TLV.
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct GrInterfaceAddrTlv(Ipv4Addr);

//
// OSPFv2 Router Information (RI) Opaque LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                            TLVs                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouterInfo {
    pub info_caps: Option<RouterInfoCapsTlv>,
    pub func_caps: Option<RouterFuncCapsTlv>,
    pub sr_algo: Option<SrAlgoTlv>,
    pub srgb: Vec<SidLabelRangeTlv>,
    pub srlb: Vec<SrLocalBlockTlv>,
    pub msds: Option<MsdTlv>,
    pub srms_pref: Option<SrmsPrefTlv>,
    // #[serde(skip)]
    pub info_hostname: Option<DynamicHostnameTlv>,
    pub unknown_tlvs: Vec<UnknownTlv>,
}

//
// OSPFv2 Extended Prefix Opaque LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                            TLVs                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Default, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaExtPrefix {
    pub prefixes: BTreeMap<Ipv4Network, ExtPrefixTlv>,
}

//
// OSPFv2 Extended Link Opaque LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                            TLVs                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaExtLink {
    pub link: Option<ExtLinkTlv>,
}

// OSPFv2 Extended Prefix Opaque LSA TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-prefix-opaque-lsa-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtPrefixTlvType {
    ExtPrefix = 1,
    ExtPrefixRange = 2,
}

//
// OSPFv2 Extended Prefix TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Route Type   | Prefix Length |     AF        |     Flags     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Address Prefix (variable)                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sub-TLVs (variable)                      |
// +-                                                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtPrefixTlv {
    pub route_type: ExtPrefixRouteType,
    pub af: u8,
    pub flags: LsaExtPrefixFlags,
    pub prefix: Ipv4Network,
    #[new(default)]
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSid>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// OSPFv2 Extended Prefix TLV Route Type.
//
// These route types correspond directly to the OSPFv2 LSAs types as defined
// in the "OSPFv2 Link State (LS) Type" registry.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum ExtPrefixRouteType {
    Unspecified = 0,
    IntraArea = 1,
    InterArea = 3,
    AsExternal = 5,
    NssaExternal = 7,
}

// OSPFv2 Extended Prefix TLV Flags.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-prefix-tlv-flags
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LsaExtPrefixFlags: u8 {
        const A = 0x80;
        const N = 0x40;
    }
}

//
// OSPFv2 Extended Prefix TLV Sub-TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-prefix-tlv-sub-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtPrefixSubTlvType {
    SidLabel = 1,
    PrefixSid = 2,
}

//
// Prefix-SID Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Flags    |   Reserved    |      MT-ID    |    Algorithm  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     SID/Index/Label (variable)                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PrefixSid {
    pub flags: PrefixSidFlags,
    pub algo: IgpAlgoType,
    pub sid: Sid,
}

// OSPFv2 Extended Link Opaque LSA TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-link-opaque-lsa-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtLinkTlvType {
    ExtLink = 1,
}

//
// OSPFv2 Extended Link TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Link Type |                  Reserved                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Link ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Link Data                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sub-TLVs (variable)                      |
// +-                                                             -+
// |                             ...                               |
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtLinkTlv {
    pub link_type: LsaRouterLinkType,
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub adj_sids: Vec<AdjSid>,
    pub msds: Option<MsdTlv>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// OSPFv2 Extended Link TLV Sub-TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-link-tlv-sub-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtLinkSubTlvType {
    SidLabel = 1,
    AdjSid = 2,
    LanAdjSid = 3,
    LinkMsd = 6,
}

//
// Adj-SID Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Flags     |    Reserved   |   MT-ID       |  Weight       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   SID/Label/Index (variable)                  |
// +---------------------------------------------------------------+
//
// LAN Adj-SID Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Flags     |    Reserved   |     MT-ID     |    Weight     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Neighbor ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    SID/Label/Index (variable)                 |
// +---------------------------------------------------------------+
//
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AdjSid {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub nbr_router_id: Option<Ipv4Addr>,
    pub sid: Sid,
}

// ===== impl OpaqueLsaId =====

impl From<Ipv4Addr> for OpaqueLsaId {
    fn from(lsa_id: Ipv4Addr) -> OpaqueLsaId {
        let mut lsa_id = lsa_id.octets();
        let opaque_type = lsa_id[0];
        lsa_id[0] = 0;
        let opaque_id = u32::from_be_bytes(lsa_id);

        OpaqueLsaId {
            opaque_type,
            opaque_id,
        }
    }
}

impl From<OpaqueLsaId> for Ipv4Addr {
    fn from(opaque_lsa_id: OpaqueLsaId) -> Ipv4Addr {
        let mut lsa_id = opaque_lsa_id.opaque_id.to_be_bytes();
        lsa_id[0] = opaque_lsa_id.opaque_type;
        Ipv4Addr::from(lsa_id)
    }
}

// ===== impl LsaOpaque =====

impl LsaOpaque {
    pub(crate) fn decode(
        lsa_id: Ipv4Addr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        let opaque_type = lsa_id.octets()[0];
        let lsa = match LsaOpaqueType::from_u8(opaque_type) {
            Some(LsaOpaqueType::Grace) => {
                LsaOpaque::Grace(LsaGrace::decode(buf)?)
            }
            Some(LsaOpaqueType::RouterInfo) => {
                LsaOpaque::RouterInfo(LsaRouterInfo::decode(buf)?)
            }
            Some(LsaOpaqueType::ExtPrefix) => {
                LsaOpaque::ExtPrefix(LsaExtPrefix::decode(buf)?)
            }
            Some(LsaOpaqueType::ExtLink) => {
                LsaOpaque::ExtLink(LsaExtLink::decode(buf)?)
            }
            _ => LsaOpaque::Unknown(LsaUnknown::decode(buf)?),
        };

        Ok(lsa)
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            LsaOpaque::Grace(lsa) => lsa.encode(buf),
            LsaOpaque::RouterInfo(lsa) => lsa.encode(buf),
            LsaOpaque::ExtPrefix(lsa) => lsa.encode(buf),
            LsaOpaque::ExtLink(lsa) => lsa.encode(buf),
            LsaOpaque::Unknown(lsa) => lsa.encode(buf),
        }
    }
}

// ===== impl LsaGrace =====

impl LsaGrace {
    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut grace = LsaGrace::default();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = GraceTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(GraceTlvType::GracePeriod) => {
                    let period = GracePeriodTlv::decode(tlv_len, &mut buf_tlv)?;
                    grace.grace_period.get_or_insert(period);
                }
                Some(GraceTlvType::GrReason) => {
                    let reason = GrReasonTlv::decode(tlv_len, &mut buf_tlv)?;
                    grace.gr_reason.get_or_insert(reason);
                }
                Some(GraceTlvType::InterfaceAddr) => {
                    let addr =
                        GrInterfaceAddrTlv::decode(tlv_len, &mut buf_tlv)?;
                    grace.addr.get_or_insert(addr);
                }
                _ => {
                    // Save unknown TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    grace
                        .unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(grace)
    }

    fn encode(&self, buf: &mut BytesMut) {
        if let Some(grace_period) = &self.grace_period {
            grace_period.encode(GraceTlvType::GracePeriod as u16, buf);
        }
        if let Some(gr_reason) = &self.gr_reason {
            gr_reason.encode(GraceTlvType::GrReason as u16, buf);
        }
        if let Some(addr) = &self.addr {
            addr.encode(buf);
        }
    }
}

// ===== impl GrInterfaceAddrTlv =====

impl GrInterfaceAddrTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(GrInterfaceAddrTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, GraceTlvType::InterfaceAddr as u16);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> Ipv4Addr {
        self.0
    }
}

// ===== impl LsaRouterInfo =====

impl LsaRouterInfo {
    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut router_info = LsaRouterInfo::default();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = RouterInfoTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(RouterInfoTlvType::InformationalCaps) => {
                    let caps =
                        RouterInfoCapsTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.info_caps.get_or_insert(caps);
                }
                Some(RouterInfoTlvType::FunctionalCaps) => {
                    let caps =
                        RouterFuncCapsTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.func_caps.get_or_insert(caps);
                }
                Some(RouterInfoTlvType::DynamicHostname) => {
                    let hostname =
                        DynamicHostnameTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.info_hostname.get_or_insert(hostname);
                }
                Some(RouterInfoTlvType::SrAlgo) => {
                    let sr_algo = SrAlgoTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.sr_algo.get_or_insert(sr_algo);
                }
                Some(RouterInfoTlvType::SidLabelRange) => {
                    let srgb = SidLabelRangeTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.srgb.push(srgb);
                }
                Some(RouterInfoTlvType::SrLocalBlock) => {
                    let srlb = SrLocalBlockTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.srlb.push(srlb);
                }
                Some(RouterInfoTlvType::NodeMsd) => {
                    let msds = MsdTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.msds.get_or_insert(msds);
                }
                Some(RouterInfoTlvType::SrmsPref) => {
                    let srms_pref = SrmsPrefTlv::decode(tlv_len, &mut buf_tlv)?;
                    router_info.srms_pref.get_or_insert(srms_pref);
                }
                _ => {
                    // Save unknown TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    router_info
                        .unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(router_info)
    }

    fn encode(&self, buf: &mut BytesMut) {
        if let Some(info_caps) = &self.info_caps {
            info_caps.encode(buf);
        }
        if let Some(func_caps) = &self.func_caps {
            func_caps.encode(buf);
        }
        if let Some(info_hostname) = &self.info_hostname {
            info_hostname.encode(buf);
        }
        if let Some(sr_algo) = &self.sr_algo {
            sr_algo.encode(buf);
        }
        for srgb in &self.srgb {
            srgb.encode(buf);
        }
        for srlb in &self.srlb {
            srlb.encode(buf);
        }
        if let Some(msds) = &self.msds {
            msds.encode(RouterInfoTlvType::NodeMsd as u16, buf);
        }
        if let Some(srms_pref) = &self.srms_pref {
            srms_pref.encode(buf);
        }
    }
}

// ===== impl LsaExtPrefix =====

impl LsaExtPrefix {
    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut lsa = LsaExtPrefix::default();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtPrefixTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtPrefixTlvType::ExtPrefix) => {
                    // Decode TLV.
                    let prefix_tlv =
                        ExtPrefixTlv::decode(tlv_len, &mut buf_tlv)?;

                    // If this TLV is advertised multiple times for the same
                    // prefix in the same OSPFv2 Extended Prefix Opaque LSA,
                    // only the first instance of the TLV is used by receiving
                    // OSPFv2 routers.
                    if let btree_map::Entry::Vacant(e) =
                        lsa.prefixes.entry(prefix_tlv.prefix)
                    {
                        e.insert(prefix_tlv);
                    }
                }
                _ => {
                    // Ignore unknown TLV.
                }
            }
        }

        Ok(lsa)
    }

    fn encode(&self, buf: &mut BytesMut) {
        for prefix_tlv in self.prefixes.values() {
            prefix_tlv.encode(buf);
        }
    }
}

// ===== impl LsaExtLink =====

impl LsaExtLink {
    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut lsa = LsaExtLink::default();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLinkTlvType::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            match tlv_etype {
                Some(ExtLinkTlvType::ExtLink) => {
                    // Decode TLV.
                    //
                    // Only one OSPFv2 Extended Link TLV SHALL be advertised in
                    // each OSPFv2 Extended Link Opaque LSA.
                    //
                    // If this TLV is advertised multiple times in the same
                    // OSPFv2 Extended Link Opaque LSA, only the first instance
                    // of the TLV is used by receiving OSPFv2 routers.
                    let link_tlv = ExtLinkTlv::decode(tlv_len, buf)?;
                    lsa.link.get_or_insert(link_tlv);
                }
                _ => {
                    // Ignore unknown TLV.
                    buf.advance(tlv_wlen.into());
                }
            }
        }

        Ok(lsa)
    }

    fn encode(&self, buf: &mut BytesMut) {
        if let Some(link_tlv) = &self.link {
            link_tlv.encode(buf);
        }
    }
}

// ===== impl ExtPrefixTlv =====

impl ExtPrefixTlv {
    pub const BASE_LENGTH: u16 = 8;

    fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len < Self::BASE_LENGTH {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        // Parse fixed fields.
        let route_type = buf.get_u8();
        let route_type = ExtPrefixRouteType::from_u8(route_type)
            .ok_or(DecodeError::InvalidExtPrefixRouteType(route_type))?;
        let prefixlen = buf.get_u8();
        let af = buf.get_u8();
        let flags = buf.get_u8();
        let flags = LsaExtPrefixFlags::from_bits_truncate(flags);
        let addr = buf.get_ipv4();
        let prefix = Ipv4Network::new(addr, prefixlen)
            .map_err(|_| DecodeError::InvalidIpPrefix)?;
        let mut tlv = ExtPrefixTlv::new(route_type, af, flags, prefix);

        // Parse Sub-TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtPrefixSubTlvType::from_u16(tlv_type);

            // Parse and validate Sub-TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtPrefixSubTlvType::PrefixSid) => {
                    let flags = buf_stlv.get_u8();
                    let flags = PrefixSidFlags::from_bits_truncate(flags);
                    let _reserved = buf_stlv.get_u8();
                    let mtid = buf_stlv.get_u8();
                    if mtid != 0 {
                        // Unsupported MT-ID - ignore.
                        continue;
                    }
                    let algo = buf_stlv.get_u8();
                    let algo = match IgpAlgoType::from_u8(algo) {
                        Some(algo) => algo,
                        None => {
                            // Unsupported algorithm - ignore.
                            continue;
                        }
                    };

                    // Parse SID (variable length).
                    let sid = if !flags
                        .intersects(PrefixSidFlags::V | PrefixSidFlags::L)
                    {
                        Sid::Index(buf_stlv.get_u32())
                    } else if flags
                        .contains(PrefixSidFlags::V | PrefixSidFlags::L)
                    {
                        let label = buf_stlv.get_u24() & Label::VALUE_MASK;
                        Sid::Label(Label::new(label))
                    } else {
                        // Invalid V-Flag and L-Flag combination - ignore.
                        continue;
                    };

                    let prefix_sid = PrefixSid::new(flags, algo, sid);
                    // TODO: in case there are multiple Prefix-SIDs for the same
                    // algorithm, all of them need to be ignored.
                    tlv.prefix_sids.insert(algo, prefix_sid);
                }
                _ => {
                    // Save unknown Sub-TLV.
                    let value = buf_stlv.copy_to_bytes(tlv_len as usize);
                    tlv.unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(tlv)
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, ExtPrefixTlvType::ExtPrefix);
        buf.put_u8(self.route_type as u8);
        buf.put_u8(self.prefix.prefix());
        buf.put_u8(self.af);
        buf.put_u8(self.flags.bits());
        buf.put_ipv4(&self.prefix.ip());
        // Prefix-SID Sub-TLVs.
        for (algo, prefix_sid) in &self.prefix_sids {
            let start_pos =
                tlv_encode_start(buf, ExtPrefixSubTlvType::PrefixSid);
            buf.put_u8(prefix_sid.flags.bits());
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(*algo as u8);
            match prefix_sid.sid {
                Sid::Index(index) => buf.put_u32(index),
                Sid::Label(label) => buf.put_u24(label.get()),
            }
            tlv_encode_end(buf, start_pos);
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl ExtLinkTlv =====

impl ExtLinkTlv {
    pub const BASE_LENGTH: u16 = 12;

    fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate TLV length.
        if tlv_len < Self::BASE_LENGTH {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        // Parse fixed fields.
        let link_type = buf.get_u8();
        let link_type = LsaRouterLinkType::from_u8(link_type)
            .ok_or(DecodeError::UnknownRouterLinkType(link_type))?;
        let _ = buf.get_u8();
        let _ = buf.get_u16();
        let link_id = buf.get_ipv4();
        let link_data = buf.get_ipv4();
        let mut tlv = ExtLinkTlv::new(
            link_type,
            link_id,
            link_data,
            Default::default(),
            None,
        );

        // Parse Sub-TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLinkSubTlvType::from_u16(tlv_type);

            // Parse and validate Sub-TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLinkSubTlvType::LinkMsd) => {
                    let msds = MsdTlv::decode(tlv_len, &mut buf_stlv)?;
                    tlv.msds.get_or_insert(msds);
                }
                Some(
                    ExtLinkSubTlvType::AdjSid | ExtLinkSubTlvType::LanAdjSid,
                ) => {
                    let flags =
                        AdjSidFlags::from_bits_truncate(buf_stlv.get_u8());
                    let _reserved = buf_stlv.get_u8();
                    let mtid = buf_stlv.get_u8();
                    if mtid != 0 {
                        // Unsupported MT-ID - ignore.
                        continue;
                    }
                    let weight = buf_stlv.get_u8();

                    // Parse Neighbor ID (LAN Adj-SID only).
                    let nbr_router_id = (tlv_etype
                        == Some(ExtLinkSubTlvType::LanAdjSid))
                    .then(|| buf_stlv.get_ipv4());

                    // Parse SID (variable length).
                    let sid = if !flags
                        .intersects(AdjSidFlags::V | AdjSidFlags::L)
                    {
                        Sid::Index(buf_stlv.get_u32())
                    } else if flags.contains(AdjSidFlags::V | AdjSidFlags::L) {
                        let label = buf_stlv.get_u24() & Label::VALUE_MASK;
                        Sid::Label(Label::new(label))
                    } else {
                        // Invalid V-Flag and L-Flag combination - ignore.
                        continue;
                    };

                    let adj_sid =
                        AdjSid::new(flags, weight, nbr_router_id, sid);
                    tlv.adj_sids.push(adj_sid);
                }
                _ => {
                    // Save unknown Sub-TLV.
                    let value = buf_stlv.copy_to_bytes(tlv_len as usize);
                    tlv.unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(tlv)
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, ExtLinkTlvType::ExtLink);
        buf.put_u8(self.link_type as u8);
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_ipv4(&self.link_id);
        buf.put_ipv4(&self.link_data);
        // (LAN)Adj-SID Sub-TLVs.
        for adj_sid in &self.adj_sids {
            let stlv_type = match adj_sid.nbr_router_id.is_some() {
                true => ExtLinkSubTlvType::LanAdjSid,
                false => ExtLinkSubTlvType::AdjSid,
            };
            let start_pos = tlv_encode_start(buf, stlv_type);
            buf.put_u8(adj_sid.flags.bits());
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(adj_sid.weight);
            if let Some(nbr_router_id) = &adj_sid.nbr_router_id {
                buf.put_ipv4(nbr_router_id);
            }
            match adj_sid.sid {
                Sid::Index(index) => buf.put_u32(index),
                Sid::Label(label) => buf.put_u24(label.get()),
            }
            tlv_encode_end(buf, start_pos);
        }
        // MSD Sub-TLV.
        if let Some(msds) = &self.msds {
            msds.encode(ExtLinkSubTlvType::LinkMsd as u16, buf);
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl PrefixSid =====

impl PrefixSidVersion for PrefixSid {
    fn flags(&self) -> PrefixSidFlags {
        self.flags
    }

    fn flags_mut(&mut self) -> &mut PrefixSidFlags {
        &mut self.flags
    }

    fn sid(&self) -> Sid {
        self.sid
    }
}

// ===== impl AdjSid =====

impl AdjSidVersion for AdjSid {
    fn new(label: Label, weight: u8, nbr_router_id: Option<Ipv4Addr>) -> Self {
        AdjSid {
            flags: AdjSidFlags::V | AdjSidFlags::L,
            weight,
            nbr_router_id,
            sid: Sid::Label(label),
        }
    }

    fn flags(&self) -> AdjSidFlags {
        self.flags
    }

    fn sid(&self) -> Sid {
        self.sid
    }
}
