//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::AddressFamily;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::ospfv2::packet::Options;
use crate::ospfv2::packet::lsa_opaque::{AdjSid, LsaOpaque, PrefixSid};
use crate::packet::error::{DecodeError, DecodeResult, LsaValidationError};
#[cfg(feature = "testing")]
use crate::packet::lsa::serde_lsa_age_filter;
use crate::packet::lsa::{
    LsaBodyVersion, LsaHdrVersion, LsaRouterFlagsVersion, LsaScope,
    LsaTypeVersion, LsaVersion, PrefixOptionsVersion,
};
use crate::packet::tlv::GrReason;
use crate::version::Ospfv2;

// Dummy PrefixOptions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PrefixOptions {}

// OSPFv2 LSA type.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LsaType(pub u8);

// OSPFv2 LSA type code.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-5
#[derive(Clone, Copy, Debug, Eq, Ord, FromPrimitive, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum LsaTypeCode {
    Router = 1,
    Network = 2,
    SummaryNetwork = 3,
    SummaryRouter = 4,
    AsExternal = 5,
    OpaqueLink = 9,
    OpaqueArea = 10,
    OpaqueAs = 11,
}

// OSPFv2 LSA.
#[derive(Clone, Debug, EnumAsInner, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaBody {
    Router(LsaRouter),
    Network(LsaNetwork),
    SummaryNetwork(LsaSummary),
    SummaryRouter(LsaSummary),
    AsExternal(LsaAsExternal),
    OpaqueLink(LsaOpaque),
    OpaqueArea(LsaOpaque),
    OpaqueAs(LsaOpaque),
    Unknown(LsaUnknown),
}

//
// OSPFv2 LSA header.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            LS age             |    Options    |    LS type    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Link State ID                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Advertising Router                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     LS sequence number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         LS checksum           |             length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaHdr {
    #[cfg_attr(
        feature = "testing",
        serde(default, skip_serializing_if = "serde_lsa_age_filter")
    )]
    pub age: u16,
    pub options: Options,
    pub lsa_type: LsaType,
    pub lsa_id: Ipv4Addr,
    pub adv_rtr: Ipv4Addr,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub seq_no: u32,
    #[cfg_attr(feature = "testing", serde(default, skip_serializing))]
    pub cksum: u16,
    pub length: u16,
}

//
// OSPFv2 Router-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    0    |V|E|B|        0      |            # links            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Link ID                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Link Data                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     # TOS     |            metric             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      TOS      |        0      |          TOS  metric          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Link ID                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Link Data                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouter {
    pub flags: LsaRouterFlags,
    pub links: Vec<LsaRouterLink>,
}

// OSPFv2 Router Properties Registry.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-11
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LsaRouterFlags: u8 {
        const B = 0x01;
        const E = 0x02;
        const V = 0x04;
        const NT = 0x10;
    }
}

// OSPFv2 Router LSA Link Type.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-7
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaRouterLinkType {
    PointToPoint = 0x01,
    TransitNetwork = 0x02,
    StubNetwork = 0x03,
    VirtualLink = 0x04,
}

#[derive(Clone, Debug, Eq, PartialEq, new)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouterLink {
    pub link_type: LsaRouterLinkType,
    pub link_id: Ipv4Addr,
    // TODO: might be an ifindex for unnumbered point-to-point connections.
    pub link_data: Ipv4Addr,
    pub metric: u16,
}

//
// OSPFv2 Network-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Network Mask                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Attached Router                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaNetwork {
    pub mask: Ipv4Addr,
    pub attached_rtrs: BTreeSet<Ipv4Addr>,
}

//
// OSPFv2 Summary-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Network Mask                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                  metric                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     TOS       |                TOS  metric                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaSummary {
    pub mask: Ipv4Addr,
    pub metric: u32,
}

//
// OSPFv2 AS-External-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Network Mask                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |E|     0       |                  metric                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Forwarding address                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      External Route Tag                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |E|    TOS      |                TOS  metric                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Forwarding address                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      External Route Tag                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaAsExternal {
    pub mask: Ipv4Addr,
    pub flags: LsaAsExternalFlags,
    pub metric: u32,
    pub fwd_addr: Option<Ipv4Addr>,
    pub tag: u32,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LsaAsExternalFlags: u8 {
        const E = 0x80;
    }
}

//
// OSPFv2 Unknown LSA.
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaUnknown {}

// ===== impl PrefixOptions =====

impl PrefixOptionsVersion for PrefixOptions {}

// ===== impl LsaType =====

impl LsaType {
    pub(crate) fn type_code(&self) -> Option<LsaTypeCode> {
        LsaTypeCode::from_u8(self.0)
    }

    pub(crate) fn is_opaque(&self) -> bool {
        matches!(
            self.type_code(),
            Some(
                LsaTypeCode::OpaqueLink
                    | LsaTypeCode::OpaqueArea
                    | LsaTypeCode::OpaqueAs
            )
        )
    }
}

impl LsaTypeVersion for LsaType {
    fn scope(&self) -> LsaScope {
        match self.type_code() {
            Some(LsaTypeCode::OpaqueLink) => LsaScope::Link,
            Some(
                LsaTypeCode::Router
                | LsaTypeCode::Network
                | LsaTypeCode::SummaryNetwork
                | LsaTypeCode::SummaryRouter
                | LsaTypeCode::OpaqueArea,
            ) => LsaScope::Area,
            Some(LsaTypeCode::AsExternal | LsaTypeCode::OpaqueAs) => {
                LsaScope::As
            }
            None => LsaScope::Unknown,
        }
    }

    fn is_gr_topology_info(&self) -> bool {
        matches!(
            self.type_code(),
            Some(
                LsaTypeCode::Router
                    | LsaTypeCode::Network
                    | LsaTypeCode::SummaryNetwork
                    | LsaTypeCode::SummaryRouter
                    | LsaTypeCode::AsExternal
            )
        )
    }
}

impl std::fmt::Display for LsaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<LsaTypeCode> for LsaType {
    fn from(code: LsaTypeCode) -> LsaType {
        LsaType(code as u8)
    }
}

impl From<LsaType> for u16 {
    fn from(lsa_type: LsaType) -> u16 {
        lsa_type.0.into()
    }
}

// ===== impl LsaHdr =====

impl LsaHdrVersion<Ospfv2> for LsaHdr {
    const LENGTH: u16 = 20;

    fn new(
        age: u16,
        options: Option<Options>,
        lsa_type: LsaType,
        lsa_id: Ipv4Addr,
        adv_rtr: Ipv4Addr,
        seq_no: u32,
    ) -> Self {
        LsaHdr {
            age,
            options: options.unwrap(),
            lsa_type,
            lsa_id,
            adv_rtr,
            seq_no,
            cksum: 0,
            length: 0,
        }
    }

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let age = buf.get_u16();
        let options = Options::from_bits_truncate(buf.get_u8());
        let lsa_type = LsaType(buf.get_u8());
        let lsa_id = buf.get_ipv4();
        let adv_rtr = buf.get_ipv4();
        let seq_no = buf.get_u32();
        let cksum = buf.get_u16();
        let length = buf.get_u16();

        Ok(LsaHdr {
            age,
            options,
            lsa_type,
            lsa_id,
            adv_rtr,
            seq_no,
            cksum,
            length,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.age);
        buf.put_u8(self.options.bits());
        buf.put_u8(self.lsa_type.0);
        buf.put_ipv4(&self.lsa_id);
        buf.put_ipv4(&self.adv_rtr);
        buf.put_u32(self.seq_no);
        buf.put_u16(self.cksum);
        buf.put_u16(self.length);
    }

    fn age(&self) -> u16 {
        self.age
    }

    fn set_age(&mut self, age: u16) {
        self.age = age;
    }

    fn options(&self) -> Option<Options> {
        Some(self.options)
    }

    fn lsa_type(&self) -> LsaType {
        self.lsa_type
    }

    fn lsa_id(&self) -> Ipv4Addr {
        self.lsa_id
    }

    fn adv_rtr(&self) -> Ipv4Addr {
        self.adv_rtr
    }

    fn seq_no(&self) -> u32 {
        self.seq_no
    }

    fn set_cksum(&mut self, value: u16) {
        self.cksum = value;
    }

    fn cksum(&self) -> u16 {
        self.cksum
    }

    fn length(&self) -> u16 {
        self.length
    }

    fn set_length(&mut self, length: u16) {
        self.length = length;
    }
}

// ===== impl LsaBody =====

impl LsaBody {
    pub(crate) fn as_summary(&self) -> Option<&LsaSummary> {
        match self {
            LsaBody::SummaryNetwork(summary)
            | LsaBody::SummaryRouter(summary) => Some(summary),
            _ => None,
        }
    }
}

impl LsaBodyVersion<Ospfv2> for LsaBody {
    fn decode(
        _af: AddressFamily,
        lsa_type: LsaType,
        lsa_id: Ipv4Addr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        let lsa = match lsa_type.type_code() {
            Some(LsaTypeCode::Router) => {
                LsaBody::Router(LsaRouter::decode(buf)?)
            }
            Some(LsaTypeCode::Network) => {
                LsaBody::Network(LsaNetwork::decode(buf)?)
            }
            Some(LsaTypeCode::SummaryNetwork) => {
                LsaBody::SummaryNetwork(LsaSummary::decode(buf)?)
            }
            Some(LsaTypeCode::SummaryRouter) => {
                LsaBody::SummaryRouter(LsaSummary::decode(buf)?)
            }
            Some(LsaTypeCode::AsExternal) => {
                LsaBody::AsExternal(LsaAsExternal::decode(buf)?)
            }
            Some(LsaTypeCode::OpaqueLink) => {
                LsaBody::OpaqueLink(LsaOpaque::decode(lsa_id, buf)?)
            }
            Some(LsaTypeCode::OpaqueArea) => {
                LsaBody::OpaqueArea(LsaOpaque::decode(lsa_id, buf)?)
            }
            Some(LsaTypeCode::OpaqueAs) => {
                LsaBody::OpaqueAs(LsaOpaque::decode(lsa_id, buf)?)
            }
            None => LsaBody::Unknown(LsaUnknown::decode(buf)?),
        };

        Ok(lsa)
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            LsaBody::Router(lsa) => lsa.encode(buf),
            LsaBody::Network(lsa) => lsa.encode(buf),
            LsaBody::SummaryNetwork(lsa) => lsa.encode(buf),
            LsaBody::SummaryRouter(lsa) => lsa.encode(buf),
            LsaBody::AsExternal(lsa) => lsa.encode(buf),
            LsaBody::OpaqueLink(lsa) => lsa.encode(buf),
            LsaBody::OpaqueArea(lsa) => lsa.encode(buf),
            LsaBody::OpaqueAs(lsa) => lsa.encode(buf),
            LsaBody::Unknown(lsa) => lsa.encode(buf),
        }
    }

    fn lsa_type(&self) -> LsaType {
        match self {
            LsaBody::Router(_lsa) => LsaTypeCode::Router.into(),
            LsaBody::Network(_lsa) => LsaTypeCode::Network.into(),
            LsaBody::SummaryNetwork(_lsa) => LsaTypeCode::SummaryNetwork.into(),
            LsaBody::SummaryRouter(_lsa) => LsaTypeCode::SummaryRouter.into(),
            LsaBody::AsExternal(_lsa) => LsaTypeCode::AsExternal.into(),
            LsaBody::OpaqueLink(_lsa) => LsaTypeCode::OpaqueLink.into(),
            LsaBody::OpaqueArea(_lsa) => LsaTypeCode::OpaqueArea.into(),
            LsaBody::OpaqueAs(_lsa) => LsaTypeCode::OpaqueAs.into(),
            LsaBody::Unknown(_lsa) => unreachable!(),
        }
    }

    fn is_unknown(&self) -> bool {
        matches!(
            self,
            LsaBody::Unknown(_)
                | LsaBody::OpaqueLink(LsaOpaque::Unknown(_))
                | LsaBody::OpaqueArea(LsaOpaque::Unknown(_))
                | LsaBody::OpaqueAs(LsaOpaque::Unknown(_))
        )
    }

    fn validate(&self, hdr: &LsaHdr) -> Result<(), LsaValidationError> {
        match self {
            LsaBody::Router(lsa) => lsa.validate(hdr),
            _ => Ok(()),
        }
    }

    fn as_grace(&self) -> Option<(u32, GrReason, Option<Ipv4Addr>)> {
        let grace = self.as_opaque_link()?.as_grace()?;
        let grace_period = grace.grace_period?.get();
        let gr_reason = grace.gr_reason?.get();
        let gr_reason =
            GrReason::from_u8(gr_reason).unwrap_or(GrReason::Unknown);
        let addr = grace.addr.map(|addr| addr.get());
        Some((grace_period, gr_reason, addr))
    }
}

// ===== impl LsaRouter =====

impl LsaRouter {
    pub const BASE_LENGTH: u16 = 4;

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum LSA length.
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLsaLength);
        }
        let flags = LsaRouterFlags::from_bits_truncate(buf.get_u8());
        let _ = buf.get_u8();
        let links_cnt = buf.get_u16();

        let mut links = vec![];
        for _ in 0..links_cnt {
            let link_id = buf.get_ipv4();
            let link_data = buf.get_ipv4();
            let link_type = buf.get_u8();
            let link_type = LsaRouterLinkType::from_u8(link_type)
                .ok_or(DecodeError::UnknownRouterLinkType(link_type))?;
            let num_tos = buf.get_u8();
            let metric = buf.get_u16();

            // Ignore deprecated TOS metrics.
            for _ in 0..num_tos {
                let _ = buf.get_u32();
            }

            let link =
                LsaRouterLink::new(link_type, link_id, link_data, metric);
            links.push(link);
        }

        Ok(LsaRouter { flags, links })
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.bits());
        buf.put_u8(0);
        buf.put_u16(self.links.len() as u16);
        for link in &self.links {
            buf.put_ipv4(&link.link_id);
            buf.put_ipv4(&link.link_data);
            buf.put_u8(link.link_type as u8);
            buf.put_u8(0);
            buf.put_u16(link.metric);
        }
    }

    fn validate(&self, hdr: &LsaHdr) -> Result<(), LsaValidationError> {
        // The Router-LSA's advertising router and LSA-ID must be equal.
        if hdr.adv_rtr != hdr.lsa_id {
            return Err(LsaValidationError::Ospfv2RouterLsaIdMismatch);
        }

        Ok(())
    }
}

// ===== impl LsaRouterFlags =====

impl LsaRouterFlagsVersion for LsaRouterFlags {
    fn is_abr(&self) -> bool {
        self.contains(LsaRouterFlags::B)
    }

    fn is_asbr(&self) -> bool {
        self.contains(LsaRouterFlags::E)
    }
}

// ===== impl LsaNetwork =====

impl LsaNetwork {
    pub const BASE_LENGTH: u16 = 4;

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum LSA length.
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLsaLength);
        }
        let mask = buf.get_ipv4();

        let mut attached_rtrs = BTreeSet::new();
        let rtrs_cnt = buf.remaining() / 4;
        for _ in 0..rtrs_cnt {
            let rtr = buf.get_ipv4();
            attached_rtrs.insert(rtr);
        }

        Ok(LsaNetwork {
            mask,
            attached_rtrs,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_ipv4(&self.mask);
        for rtr in &self.attached_rtrs {
            buf.put_ipv4(rtr);
        }
    }
}

// ===== impl LsaSummary =====

impl LsaSummary {
    pub const BASE_LENGTH: u16 = 8;

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum LSA length.
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLsaLength);
        }
        let mask = buf.get_ipv4();
        let _ = buf.get_u8();
        let metric = buf.get_u24();
        // Ignore deprecated TOS metrics.

        Ok(LsaSummary { mask, metric })
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_ipv4(&self.mask);
        buf.put_u8(0);
        buf.put_u24(self.metric);
    }
}

// ===== impl LsaAsExternal =====

impl LsaAsExternal {
    pub const BASE_LENGTH: u16 = 16;

    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate minimum LSA length.
        if buf.remaining() < Self::BASE_LENGTH as usize {
            return Err(DecodeError::InvalidLsaLength);
        }
        let mask = buf.get_ipv4();
        let flags = LsaAsExternalFlags::from_bits_truncate(buf.get_u8());
        let metric = buf.get_u24();
        let fwd_addr = buf.get_opt_ipv4();
        let tag = buf.get_u32();
        // Ignore deprecated TOS-specific information.

        Ok(LsaAsExternal {
            mask,
            flags,
            metric,
            fwd_addr,
            tag,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_ipv4(&self.mask);
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.metric);
        buf.put_ipv4(&self.fwd_addr.unwrap_or(Ipv4Addr::UNSPECIFIED));
        buf.put_u32(self.tag);
    }
}

// ===== impl LsaUnknown =====

impl LsaUnknown {
    pub(crate) fn decode(_buf: &mut Bytes) -> DecodeResult<Self> {
        Ok(LsaUnknown {})
    }

    pub(crate) fn encode(&self, _buf: &mut BytesMut) {
        #[cfg(not(feature = "testing"))]
        unreachable!()
    }
}

// ===== impl Ospfv2 =====

impl LsaVersion<Self> for Ospfv2 {
    type LsaType = LsaType;
    type LsaHdr = LsaHdr;
    type LsaBody = LsaBody;
    type LsaRouterFlags = LsaRouterFlags;
    type LsaRouterLink = LsaRouterLink;
    type PrefixOptions = PrefixOptions;
    type PrefixSid = PrefixSid;
    type AdjSid = AdjSid;

    fn type3_summary(_extended_lsa: bool) -> LsaType {
        LsaTypeCode::SummaryNetwork.into()
    }

    fn type4_summary(_extended_lsa: bool) -> LsaType {
        LsaTypeCode::SummaryRouter.into()
    }
}
