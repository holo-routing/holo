//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::{AddressFamily, IpAddrExt, Ipv4AddrExt, Ipv6AddrExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use ipnetwork::IpNetwork;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::ospfv3::packet::Options;
use crate::packet::error::{DecodeError, DecodeResult, LsaValidationError};
#[cfg(feature = "testing")]
use crate::packet::lsa::serde_lsa_age_filter;
use crate::packet::lsa::{
    AdjSidVersion, LsaBodyVersion, LsaHdrVersion, LsaRouterFlagsVersion,
    LsaScope, LsaTypeVersion, LsaVersion, PrefixOptionsVersion,
    PrefixSidVersion,
};
use crate::packet::tlv::{
    tlv_encode_end, tlv_encode_start, tlv_wire_len, AdjSidFlags, BierSubTlv,
    DynamicHostnameTlv, GrReason, GrReasonTlv, GracePeriodTlv, MsdTlv,
    PrefixSidFlags, RouterFuncCapsTlv, RouterInfoCapsTlv, RouterInfoTlvType,
    SidLabelRangeTlv, SrAlgoTlv, SrLocalBlockTlv, SrmsPrefTlv, UnknownTlv,
    TLV_HDR_SIZE,
};
use crate::version::Ospfv3;

// The PrefixOptions Field.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-4
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct PrefixOptions: u8 {
        const NU = 0x01;
        const LA = 0x02;
        const P = 0x08;
        const DN = 0x10;
        const N = 0x20;
    }
}

// OSPFv3 LSA type.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LsaType(pub u16);

// The U-bit indicates how the LSA should be handled by a router that does not
// recognize the LSA's function code.
const U_BIT: u16 = 1 << 15;

// OSPFv3 LSA scope.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum LsaScopeCode {
    Link = 0x0000,
    Area = 0x2000,
    As = 0x4000,
    Reserved = 0x6000,
}

// OSPFv3 LSA function code.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-3
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum LsaFunctionCode {
    // Legacy LSA Types
    Router = 1,
    Network = 2,
    InterAreaPrefix = 3,
    InterAreaRouter = 4,
    AsExternal = 5,
    Link = 8,
    IntraAreaPrefix = 9,
    // Extended LSA Types
    ExtRouter = 33,
    ExtNetwork = 34,
    ExtInterAreaPrefix = 35,
    ExtInterAreaRouter = 36,
    ExtAsExternal = 37,
    ExtLink = 40,
    ExtIntraAreaPrefix = 41,
    // Other LSA types
    Grace = 11,
    RouterInfo = 12,
}

//
// OSPFv3 LSA header.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           LS Age              |           LS Type             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Link State ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Advertising Router                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    LS Sequence Number                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        LS Checksum            |             Length            |
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
    pub lsa_type: LsaType,
    pub lsa_id: Ipv4Addr,
    pub adv_rtr: Ipv4Addr,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub seq_no: u32,
    #[cfg_attr(feature = "testing", serde(default, skip_serializing))]
    pub cksum: u16,
    pub length: u16,
}

// OSPFv3 LSA.
#[derive(Clone, Debug, Eq, PartialEq, EnumAsInner)]
#[derive(Deserialize, Serialize)]
pub enum LsaBody {
    Router(LsaRouter),
    Network(LsaNetwork),
    InterAreaPrefix(LsaInterAreaPrefix),
    InterAreaRouter(LsaInterAreaRouter),
    AsExternal(LsaAsExternal),
    Link(LsaLink),
    IntraAreaPrefix(LsaIntraAreaPrefix),
    Grace(LsaGrace),
    RouterInfo(LsaRouterInfo),
    Unknown(LsaUnknown),
}

// OSPFv3 Extended-LSA TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#extended-lsa-tlvs
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtLsaTlv {
    RouterLink = 1,
    AttachedRouters = 2,
    InterAreaPrefix = 3,
    InterAreaRouter = 4,
    ExternalPrefix = 5,
    IntraAreaPrefix = 6,
    Ipv6LinkLocalAddr = 7,
    Ipv4LinkLocalAddr = 8,
}

// OSPFv3 Extended-LSA Sub-TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#extended-lsa-sub-tlvs
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtLsaSubTlv {
    Ipv6FwdAddr = 1,
    Ipv4FwdAddr = 2,
    RouteTag = 3,
    PrefixSid = 4,
    AdjSid = 5,
    LanAdjSid = 6,
    SidLabel = 7,
    LinkMsd = 9,
    Bier = 42,
}

// OSPFv3 Extended-LSA Sub-TLVs.
//
// IPv6-Forwarding-Address Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       1 - Forwarding Address  |          sub-TLV Length       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                    Forwarding Address                       -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// IPv4-Forwarding-Address Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       2 - Forwarding Address  |          sub-TLV Length       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Forwarding Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Route-Tag Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       3 - Route Tag           |          sub-TLV Length       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Route Tag                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtLsaSubTlvs {
    pub ipv6_fwd_addr: Option<Ipv6Addr>,
    pub ipv4_fwd_addr: Option<Ipv4Addr>,
    pub route_tag: Option<u32>,
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSid>,
    pub adj_sids: Vec<AdjSid>,
    pub bier: Vec<BierSubTlv>,
    pub unknown: Vec<UnknownTlv>,
}

//
// Prefix-SID Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Type            |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Flags     |  Algorithm    |           Reserved            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       SID/Index/Label (variable)              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Copy, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PrefixSid {
    pub flags: PrefixSidFlags,
    pub algo: IgpAlgoType,
    pub sid: Sid,
}

//
// Adj-SID Sub-TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Type            |              Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Flags         |     Weight    |             Reserved          |
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
// |     Flags     |     Weight    |            Reserved           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Neighbor ID                         |
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

//
// OSPFv3 Router-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  0  |Nt|x|V|E|B|            Options                            |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type       |       0       |          Metric               |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Interface ID                              |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Neighbor Interface ID                        |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Neighbor Router ID                          |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                                |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type       |       0       |          Metric               |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Interface ID                              |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Neighbor Interface ID                        |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Neighbor Router ID                          |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                                |
//
// OSPFv3 E-Router-LSA.
//
// Encoding format (LSA body):
//
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  0  |Nt|x|V|E|B|            Options                            |
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                                .
// .                            TLVs                                .
// .                                                                .
// +-+-+-+--+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Router-Link TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          1 (Router-Link)      |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |       0       |           Metric              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Interface ID                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Neighbor Interface ID                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Neighbor Router ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouter {
    pub extended: bool,
    pub flags: LsaRouterFlags,
    pub options: Options,
    pub links: Vec<LsaRouterLink>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// OSPFv3 Router Properties Registry.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-7
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

// OSPFv3 Router LSA Link Types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-6
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaRouterLinkType {
    PointToPoint = 0x01,
    TransitNetwork = 0x02,
    VirtualLink = 0x04,
}

#[derive(Clone, Debug, Eq, PartialEq, new)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouterLink {
    pub link_type: LsaRouterLinkType,
    pub metric: u16,
    pub iface_id: u32,
    pub nbr_iface_id: u32,
    pub nbr_router_id: Ipv4Addr,
    pub adj_sids: Vec<AdjSid>,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Network-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |              Options                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Attached Router                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                               |
//
// OSPFv3 E-Network-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       0       |            Options                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                           TLVs                                .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Attached-Routers TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        2 (Attached-Routers)   |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Adjacent Neighbor Router ID                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .              Additional Adjacent Neighbors                    .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaNetwork {
    pub extended: bool,
    pub options: Options,
    pub attached_rtrs: BTreeSet<Ipv4Addr>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Inter-Area-Prefix LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                  Metric                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | PrefixLength  | PrefixOptions |              0                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// OSPFv3 E-Inter-Area-Prefix-LSA:
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                           TLVs                                .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Inter-Area-Prefix TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       3 (Inter-Area Prefix)   |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                  Metric                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | PrefixLength  | PrefixOptions |              0                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaInterAreaPrefix {
    pub extended: bool,
    pub metric: u32,
    pub prefix_options: PrefixOptions,
    pub prefix: IpNetwork,
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSid>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Inter-Area-Router LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                 Options                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                 Metric                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Router ID                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// OSPFv3 E-Inter-Area-Router-LSA:
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                           TLVs                                .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Inter-Area-Router TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       4 (Inter-Area Router)   |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                Options                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                Metric                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Destination Router ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaInterAreaRouter {
    pub extended: bool,
    pub options: Options,
    pub metric: u32,
    pub router_id: Ipv4Addr,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 AS-External-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         |E|F|T|                Metric                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | PrefixLength  | PrefixOptions |     Referenced LS Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                Forwarding Address (Optional)                -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              External Route Tag (Optional)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Referenced Link State ID (Optional)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// OSPFv3 E-AS-External-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                           TLVs                                .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// External-Prefix TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       5 (External Prefix)     |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         |E| | |                Metric                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | PrefixLength  | PrefixOptions |              0                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaAsExternal {
    pub extended: bool,
    pub flags: LsaAsExternalFlags,
    pub metric: u32,
    pub prefix_options: PrefixOptions,
    pub prefix: IpNetwork,
    pub fwd_addr: Option<IpAddr>,
    pub tag: Option<u32>,
    pub ref_lsa_type: Option<LsaType>,
    pub ref_lsa_id: Option<Ipv4Addr>,
    #[new(default)]
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSid>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LsaAsExternalFlags: u8 {
        const T = 0x01;
        const F = 0x02;
        const E = 0x04;
    }
}

//
// OSPFv3 Link LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Rtr Priority  |                Options                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-                Link-local Interface Address                 -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         # prefixes                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  PrefixLength | PrefixOptions |             0                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  PrefixLength | PrefixOptions |             0                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// OSPFv3 E-Link-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Rtr Priority  |                Options                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                           TLVs                                .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// IPv6 Link-Local Address TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  7 (IPv6 Local-Local Address) |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-            IPv6 Link-Local Interface Address                -+
// |                                                               |
// +-                                                             -+
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// IPv4 Link-Local Address TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  8 (IPv4 Local-Local Address) |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             IPv4 Link-Local Interface Address                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaLink {
    pub extended: bool,
    pub priority: u8,
    pub options: Options,
    pub linklocal: IpAddr,
    pub prefixes: Vec<LsaLinkPrefix>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaLinkPrefix {
    pub options: PrefixOptions,
    pub value: IpNetwork,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Intra-Area-Prefix LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         # Prefixes            |     Referenced LS Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Referenced Link State ID                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Referenced Advertising Router                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  PrefixLength | PrefixOptions |          Metric               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Address Prefix                          |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  PrefixLength | PrefixOptions |          Metric               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Address Prefix                          |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// OSPFv3 E-Intra-Area-Prefix-LSA.
//
// Encoding format (LSA body):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       0                       |     Referenced LS Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Referenced Link State ID                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Referenced Advertising Router                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            TLVs                               .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Intra-Area-Prefix TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       6 (Intra-Area Prefix)   |       TLV Length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      0        |                  Metric                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | PrefixLength  | PrefixOptions |              0                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Address Prefix                         |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                            Sub-TLVs                           .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaIntraAreaPrefix {
    pub extended: bool,
    pub ref_lsa_type: LsaType,
    pub ref_lsa_id: Ipv4Addr,
    pub ref_adv_rtr: Ipv4Addr,
    pub prefixes: Vec<LsaIntraAreaPrefixEntry>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaIntraAreaPrefixEntry {
    pub options: PrefixOptions,
    pub value: IpNetwork,
    pub metric: u16,
    #[new(default)]
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSid>,
    #[new(default)]
    pub bier: Vec<BierSubTlv>,
    #[new(default)]
    pub unknown_stlvs: Vec<UnknownTlv>,
}

// OSPFv3 Grace LSA Top Level TLV types.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum GraceTlvType {
    GracePeriod = 1,
    GrReason = 2,
}

//
// OSPFv3 Grace Opaque LSA.
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
    pub unknown_tlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Router Information (RI) Opaque LSA.
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
#[derive(Clone, Debug, Eq, PartialEq, new)]
#[derive(Deserialize, Serialize)]
pub struct LsaRouterInfo {
    pub scope: LsaScopeCode,
    #[new(default)]
    pub info_caps: Option<RouterInfoCapsTlv>,
    #[new(default)]
    pub func_caps: Option<RouterFuncCapsTlv>,
    #[new(default)]
    pub sr_algo: Option<SrAlgoTlv>,
    #[new(default)]
    pub srgb: Vec<SidLabelRangeTlv>,
    #[new(default)]
    pub srlb: Vec<SrLocalBlockTlv>,
    #[new(default)]
    pub msds: Option<MsdTlv>,
    #[new(default)]
    pub srms_pref: Option<SrmsPrefTlv>,
    #[new(default)]
    #[serde(skip)]
    pub info_hostname: Option<DynamicHostnameTlv>,
    #[new(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

//
// OSPFv3 Unknown LSA.
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LsaUnknown {}

// ===== impl PrefixOptions =====

impl PrefixOptionsVersion for PrefixOptions {}

// ===== impl LsaType =====

impl LsaType {
    pub const U_BIT_MASK: u16 = 0x8000;
    pub const SCOPE_MASK: u16 = 0x6000;
    pub const FUNCTION_CODE_MASK: u16 = 0x1fff;

    pub(crate) fn u_bit(&self) -> bool {
        self.0 & Self::U_BIT_MASK != 0
    }

    pub(crate) fn scope_code(&self) -> LsaScopeCode {
        LsaScopeCode::from_u16(self.0 & Self::SCOPE_MASK).unwrap()
    }

    pub(crate) fn function_code(&self) -> Option<LsaFunctionCode> {
        LsaFunctionCode::from_u16(self.0 & Self::FUNCTION_CODE_MASK)
    }

    pub(crate) fn function_code_normalized(&self) -> Option<LsaFunctionCode> {
        self.function_code().map(|c| c.normalized())
    }
}

impl LsaTypeVersion for LsaType {
    fn scope(&self) -> LsaScope {
        match self.scope_code() {
            LsaScopeCode::Link => LsaScope::Link,
            LsaScopeCode::Area => LsaScope::Area,
            LsaScopeCode::As => LsaScope::As,
            LsaScopeCode::Reserved => LsaScope::Unknown,
        }
    }

    fn is_gr_topology_info(&self) -> bool {
        matches!(
            self.function_code_normalized(),
            Some(
                LsaFunctionCode::Router
                    | LsaFunctionCode::Network
                    | LsaFunctionCode::InterAreaPrefix
                    | LsaFunctionCode::InterAreaRouter
                    | LsaFunctionCode::AsExternal
            )
        )
    }
}

impl std::fmt::Display for LsaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<LsaType> for u16 {
    fn from(lsa_type: LsaType) -> u16 {
        lsa_type.0
    }
}

// ===== impl LsaFunctionCode =====

impl LsaFunctionCode {
    pub(crate) fn normalized(&self) -> LsaFunctionCode {
        match self {
            LsaFunctionCode::ExtRouter => LsaFunctionCode::Router,
            LsaFunctionCode::ExtNetwork => LsaFunctionCode::Network,
            LsaFunctionCode::ExtInterAreaPrefix => {
                LsaFunctionCode::InterAreaPrefix
            }
            LsaFunctionCode::ExtInterAreaRouter => {
                LsaFunctionCode::InterAreaRouter
            }
            LsaFunctionCode::ExtAsExternal => LsaFunctionCode::AsExternal,
            LsaFunctionCode::ExtLink => LsaFunctionCode::Link,
            LsaFunctionCode::ExtIntraAreaPrefix => {
                LsaFunctionCode::IntraAreaPrefix
            }
            _ => *self,
        }
    }
}

// ===== impl LsaHdr =====

impl LsaHdrVersion<Ospfv3> for LsaHdr {
    const LENGTH: u16 = 20;

    fn new(
        age: u16,
        _options: Option<Options>,
        lsa_type: LsaType,
        lsa_id: Ipv4Addr,
        adv_rtr: Ipv4Addr,
        seq_no: u32,
    ) -> Self {
        LsaHdr {
            age,
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
        let lsa_type = LsaType(buf.get_u16());
        let lsa_id = buf.get_ipv4();
        let adv_rtr = buf.get_ipv4();
        let seq_no = buf.get_u32();
        let cksum = buf.get_u16();
        let length = buf.get_u16();

        Ok(LsaHdr {
            age,
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
        buf.put_u16(self.lsa_type.0);
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
        None
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
    pub(crate) fn as_std_router(&self) -> Option<&LsaRouter> {
        self.as_router().filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_router(&self) -> Option<&LsaRouter> {
        self.as_router().filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_network(&self) -> Option<&LsaNetwork> {
        self.as_network().filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_network(&self) -> Option<&LsaNetwork> {
        self.as_network().filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_inter_area_prefix(
        &self,
    ) -> Option<&LsaInterAreaPrefix> {
        self.as_inter_area_prefix()
            .filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_inter_area_prefix(
        &self,
    ) -> Option<&LsaInterAreaPrefix> {
        self.as_inter_area_prefix()
            .filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_inter_area_router(
        &self,
    ) -> Option<&LsaInterAreaRouter> {
        self.as_inter_area_router()
            .filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_inter_area_router(
        &self,
    ) -> Option<&LsaInterAreaRouter> {
        self.as_inter_area_router()
            .filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_as_external(&self) -> Option<&LsaAsExternal> {
        self.as_as_external().filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_as_external(&self) -> Option<&LsaAsExternal> {
        self.as_as_external().filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_link(&self) -> Option<&LsaLink> {
        self.as_link().filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_link(&self) -> Option<&LsaLink> {
        self.as_link().filter(|lsa_body| lsa_body.extended)
    }

    pub(crate) fn as_std_intra_area_prefix(
        &self,
    ) -> Option<&LsaIntraAreaPrefix> {
        self.as_intra_area_prefix()
            .filter(|lsa_body| !lsa_body.extended)
    }

    pub(crate) fn as_ext_intra_area_prefix(
        &self,
    ) -> Option<&LsaIntraAreaPrefix> {
        self.as_intra_area_prefix()
            .filter(|lsa_body| lsa_body.extended)
    }
}

impl LsaBodyVersion<Ospfv3> for LsaBody {
    fn decode(
        af: AddressFamily,
        lsa_type: LsaType,
        _lsa_id: Ipv4Addr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        let lsa_scope = lsa_type.scope_code();
        let lsa = match lsa_type.function_code() {
            // Legacy LSA Types
            Some(LsaFunctionCode::Router) => {
                LsaBody::Router(LsaRouter::decode_legacy(buf)?)
            }
            Some(LsaFunctionCode::Network) => {
                LsaBody::Network(LsaNetwork::decode_legacy(buf)?)
            }
            Some(LsaFunctionCode::InterAreaPrefix) => LsaBody::InterAreaPrefix(
                LsaInterAreaPrefix::decode_legacy(af, buf)?,
            ),
            Some(LsaFunctionCode::InterAreaRouter) => LsaBody::InterAreaRouter(
                LsaInterAreaRouter::decode_legacy(buf)?,
            ),
            Some(LsaFunctionCode::AsExternal) => {
                LsaBody::AsExternal(LsaAsExternal::decode_legacy(af, buf)?)
            }
            Some(LsaFunctionCode::Link) => {
                LsaBody::Link(LsaLink::decode_legacy(af, buf)?)
            }
            Some(LsaFunctionCode::IntraAreaPrefix) => LsaBody::IntraAreaPrefix(
                LsaIntraAreaPrefix::decode_legacy(af, buf)?,
            ),
            // Extended LSA Types
            Some(LsaFunctionCode::ExtRouter) => {
                LsaBody::Router(LsaRouter::decode_extended(buf)?)
            }
            Some(LsaFunctionCode::ExtNetwork) => {
                LsaBody::Network(LsaNetwork::decode_extended(buf)?)
            }
            Some(LsaFunctionCode::ExtInterAreaPrefix) => {
                LsaBody::InterAreaPrefix(LsaInterAreaPrefix::decode_extended(
                    af, buf,
                )?)
            }
            Some(LsaFunctionCode::ExtInterAreaRouter) => {
                LsaBody::InterAreaRouter(LsaInterAreaRouter::decode_extended(
                    buf,
                )?)
            }
            Some(LsaFunctionCode::ExtAsExternal) => {
                LsaBody::AsExternal(LsaAsExternal::decode_extended(af, buf)?)
            }
            Some(LsaFunctionCode::ExtLink) => {
                LsaBody::Link(LsaLink::decode_extended(af, buf)?)
            }
            Some(LsaFunctionCode::ExtIntraAreaPrefix) => {
                LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix::decode_extended(
                    af, buf,
                )?)
            }
            // Other LSA types
            Some(LsaFunctionCode::Grace) => {
                LsaBody::Grace(LsaGrace::decode(buf)?)
            }
            Some(LsaFunctionCode::RouterInfo) => {
                LsaBody::RouterInfo(LsaRouterInfo::decode(lsa_scope, buf)?)
            }
            None => LsaBody::Unknown(LsaUnknown::decode(buf)?),
        };

        Ok(lsa)
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            LsaBody::Router(lsa) => lsa.encode(buf),
            LsaBody::Network(lsa) => lsa.encode(buf),
            LsaBody::InterAreaPrefix(lsa) => lsa.encode(buf),
            LsaBody::InterAreaRouter(lsa) => lsa.encode(buf),
            LsaBody::AsExternal(lsa) => lsa.encode(buf),
            LsaBody::Link(lsa) => lsa.encode(buf),
            LsaBody::IntraAreaPrefix(lsa) => lsa.encode(buf),
            LsaBody::Grace(lsa) => lsa.encode(buf),
            LsaBody::RouterInfo(lsa) => lsa.encode(buf),
            LsaBody::Unknown(lsa) => lsa.encode(buf),
        }
    }

    fn lsa_type(&self) -> LsaType {
        match self {
            LsaBody::Router(lsa) => LsaRouter::lsa_type(lsa.extended),
            LsaBody::Network(lsa) => LsaNetwork::lsa_type(lsa.extended),
            LsaBody::InterAreaPrefix(lsa) => {
                LsaInterAreaPrefix::lsa_type(lsa.extended)
            }
            LsaBody::InterAreaRouter(lsa) => {
                LsaInterAreaRouter::lsa_type(lsa.extended)
            }
            LsaBody::AsExternal(lsa) => LsaAsExternal::lsa_type(lsa.extended),
            LsaBody::Link(lsa) => LsaLink::lsa_type(lsa.extended),
            LsaBody::IntraAreaPrefix(lsa) => {
                LsaIntraAreaPrefix::lsa_type(lsa.extended)
            }
            LsaBody::Grace(_) => LsaGrace::lsa_type(),
            LsaBody::RouterInfo(lsa) => lsa.lsa_type(),
            LsaBody::Unknown(_) => LsaUnknown::lsa_type(),
        }
    }

    fn is_unknown(&self) -> bool {
        matches!(self, LsaBody::Unknown(_))
    }

    fn validate(&self, _hdr: &LsaHdr) -> Result<(), LsaValidationError> {
        Ok(())
    }

    fn as_grace(&self) -> Option<(u32, GrReason, Option<Ipv6Addr>)> {
        let grace = self.as_grace()?;
        let grace_period = grace.grace_period?.get();
        let gr_reason = grace.gr_reason?.get();
        let gr_reason =
            GrReason::from_u8(gr_reason).unwrap_or(GrReason::Unknown);
        Some((grace_period, gr_reason, None))
    }
}

// ===== impl LsaRouter =====

impl LsaRouter {
    pub const BASE_LENGTH: u16 = 4;

    fn decode_legacy(buf: &mut Bytes) -> DecodeResult<Self> {
        let flags = LsaRouterFlags::from_bits_truncate(buf.get_u8());
        let options = Options::decode(buf);

        let mut links = vec![];
        let links_cnt = buf.remaining() / LsaRouterLink::LENGTH_LEGACY as usize;
        for _ in 0..links_cnt {
            let link = LsaRouterLink::decode(buf, false)?;
            links.push(link);
        }

        Ok(LsaRouter::new(false, flags, options, links))
    }

    fn decode_extended(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut unknown_tlvs = vec![];

        // Parse fixed-format fields.
        let flags = LsaRouterFlags::from_bits_truncate(buf.get_u8());
        let options = Options::decode(buf);

        // Parse top-level TLVs.
        let mut links = vec![];
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::RouterLink) => {
                    let link = LsaRouterLink::decode(&mut buf_tlv, true)?;
                    links.push(link);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(LsaRouter {
            extended: true,
            flags,
            options,
            links,
            unknown_tlvs,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.bits());
        self.options.encode(buf);
        for link in &self.links {
            link.encode(buf, false);
        }
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode fixed-format fields.
        buf.put_u8(self.flags.bits());
        self.options.encode(buf);

        // Encode Router-Link TLVs.
        for link in &self.links {
            let start_pos = tlv_encode_start(buf, ExtLsaTlv::RouterLink);
            link.encode(buf, true);
            tlv_encode_end(buf, start_pos);
        }
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Area;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtRouter;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::Router;
                LsaType(scope as u16 | function_code as u16)
            }
        }
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

// ===== impl LsaRouterLink =====

impl LsaRouterLink {
    pub const LENGTH_LEGACY: u16 = 16;
    pub const MAX_LENGTH_EXT: u16 = 20;

    fn decode(buf: &mut Bytes, extended: bool) -> DecodeResult<Self> {
        let link_type = buf.get_u8();
        let link_type = match LsaRouterLinkType::from_u8(link_type) {
            Some(link_type) => link_type,
            None => return Err(DecodeError::UnknownRouterLinkType(link_type)),
        };
        let _ = buf.get_u8();
        let metric = buf.get_u16();
        let iface_id = buf.get_u32();
        let nbr_iface_id = buf.get_u32();
        let nbr_router_id = buf.get_ipv4();

        let mut link = LsaRouterLink::new(
            link_type,
            metric,
            iface_id,
            nbr_iface_id,
            nbr_router_id,
            Default::default(),
        );

        // Parse Sub-TLVs.
        if extended {
            let stlvs = ExtLsaSubTlvs::decode(buf)?;
            link.adj_sids = stlvs.adj_sids;
            link.unknown_stlvs = stlvs.unknown;
        }

        Ok(link)
    }

    fn encode(&self, buf: &mut BytesMut, extended: bool) {
        buf.put_u8(self.link_type as u8);
        buf.put_u8(0);
        buf.put_u16(self.metric);
        buf.put_u32(self.iface_id);
        buf.put_u32(self.nbr_iface_id);
        buf.put_ipv4(&self.nbr_router_id);
        if extended {
            self.sub_tlvs().encode(buf);
        }
    }

    fn sub_tlvs(&self) -> ExtLsaSubTlvs {
        ExtLsaSubTlvs {
            adj_sids: self.adj_sids.clone(),
            ..Default::default()
        }
    }

    pub(crate) const fn max_length(extended: bool) -> usize {
        match extended {
            true => Self::MAX_LENGTH_EXT as usize,
            false => Self::LENGTH_LEGACY as usize,
        }
    }
}

// ===== impl LsaNetwork =====

impl LsaNetwork {
    fn decode_legacy(buf: &mut Bytes) -> DecodeResult<Self> {
        let _ = buf.get_u8();
        let options = Options::decode(buf);

        let mut attached_rtrs = BTreeSet::new();
        let rtrs_cnt = buf.remaining() / 4;
        for _ in 0..rtrs_cnt {
            let rtr = buf.get_ipv4();
            attached_rtrs.insert(rtr);
        }

        Ok(LsaNetwork::new(false, options, attached_rtrs))
    }

    fn decode_extended(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut attached_rtrs = BTreeSet::new();
        let mut unknown_tlvs = vec![];

        // Parse fixed-format fields.
        let _ = buf.get_u8();
        let options = Options::decode(buf);

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::AttachedRouters) => {
                    // Instances of the Attached-Router TLV subsequent to the
                    // first MUST be ignored.
                    if !attached_rtrs.is_empty() {
                        continue;
                    }

                    // Further validate TLV length.
                    if tlv_len < 4 || tlv_len % 4 != 0 {
                        return Err(DecodeError::InvalidTlvLength(tlv_len));
                    }

                    let rtrs_cnt = buf_tlv.remaining() / 4;
                    for _ in 0..rtrs_cnt {
                        let rtr = buf_tlv.get_ipv4();
                        attached_rtrs.insert(rtr);
                    }

                    // NOTE: this TLV doesn't support Sub-TLVs.
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        // If the Attached-Router TLV is not included in the E-Network-LSA, it
        // is treated as malformed.
        if attached_rtrs.is_empty() {
            return Err(DecodeError::MissingRequiredTlv(
                ExtLsaTlv::AttachedRouters as u16,
            ));
        }

        Ok(LsaNetwork {
            extended: true,
            options,
            attached_rtrs,
            unknown_tlvs,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(0);
        self.options.encode(buf);
        for rtr in &self.attached_rtrs {
            buf.put_ipv4(rtr);
        }
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode fixed-format fields.
        buf.put_u8(0);
        self.options.encode(buf);

        // Encode top-level TLV.
        let start_pos = tlv_encode_start(buf, ExtLsaTlv::AttachedRouters);
        for rtr in &self.attached_rtrs {
            buf.put_ipv4(rtr);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Area;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtNetwork;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::Network;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaInterAreaPrefix =====

impl LsaInterAreaPrefix {
    fn decode_legacy(af: AddressFamily, buf: &mut Bytes) -> DecodeResult<Self> {
        let _ = buf.get_u8();
        let metric = buf.get_u24();
        let plen = buf.get_u8();
        let prefix_options = PrefixOptions::from_bits_truncate(buf.get_u8());
        let _ = buf.get_u16();
        let prefix = decode_prefix(af, plen, buf)?;

        Ok(LsaInterAreaPrefix::new(
            false,
            metric,
            prefix_options,
            prefix,
            Default::default(),
        ))
    }

    fn decode_extended(
        af: AddressFamily,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        let mut iap = None;
        let mut unknown_tlvs = vec![];

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::InterAreaPrefix) => {
                    // Instances of the Inter-Area-Prefix TLV subsequent to the
                    // first MUST be ignored.
                    if iap.is_some() {
                        continue;
                    }

                    // Take advantage of the fact that the TLV fields are
                    // identical to the ones of the legacy LSA.
                    let mut tlv = Self::decode_legacy(af, &mut buf_tlv)?;
                    tlv.extended = true;

                    // Parse Sub-TLVs.
                    let stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;
                    tlv.prefix_sids = stlvs.prefix_sids;
                    tlv.unknown_stlvs = stlvs.unknown;

                    iap = Some(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        // If the Inter-Area-Prefix TLV is not included in the
        // E-Inter-Area-Prefix-LSA, it is treated as malformed.
        match iap {
            Some(mut iap) => {
                iap.unknown_tlvs = unknown_tlvs;
                Ok(iap)
            }
            None => Err(DecodeError::MissingRequiredTlv(
                ExtLsaTlv::InterAreaPrefix as u16,
            )),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(0);
        buf.put_u24(self.metric);
        buf.put_u8(self.prefix.prefix());
        buf.put_u8(self.prefix_options.bits());
        buf.put_u16(0);
        encode_prefix(&self.prefix, buf);
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode top-level TLV.
        let start_pos = tlv_encode_start(buf, ExtLsaTlv::InterAreaPrefix);
        // Take advantage of the fact that the TLV fields are identical to the
        // ones of the legacy LSA.
        self.encode_legacy(buf);
        self.sub_tlvs().encode(buf);
        tlv_encode_end(buf, start_pos);
    }

    fn sub_tlvs(&self) -> ExtLsaSubTlvs {
        ExtLsaSubTlvs {
            prefix_sids: self.prefix_sids.clone(),
            ..Default::default()
        }
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Area;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtInterAreaPrefix;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::InterAreaPrefix;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaInterAreaRouter =====

impl LsaInterAreaRouter {
    fn decode_legacy(buf: &mut Bytes) -> DecodeResult<Self> {
        let _ = buf.get_u8();
        let options = Options::decode(buf);
        let _ = buf.get_u8();
        let metric = buf.get_u24();
        let router_id = buf.get_ipv4();

        Ok(LsaInterAreaRouter::new(false, options, metric, router_id))
    }

    fn decode_extended(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut iar = None;
        let mut unknown_tlvs = vec![];

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::InterAreaRouter) => {
                    // Instances of the Inter-Area-Router TLV subsequent to the
                    // first MUST be ignored.
                    if iar.is_some() {
                        continue;
                    }

                    // Take advantage of the fact that the TLV fields are
                    // identical to the ones of the legacy LSA.
                    let mut tlv = Self::decode_legacy(&mut buf_tlv)?;
                    tlv.extended = true;

                    // Parse Sub-TLVs.
                    let stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;
                    tlv.unknown_stlvs = stlvs.unknown;

                    iar = Some(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        // If the Inter-Area-Router TLV is not included in the
        // E-Inter-Area-Router-LSA, it is treated as malformed.
        match iar {
            Some(mut iar) => {
                iar.unknown_tlvs = unknown_tlvs;
                Ok(iar)
            }
            None => Err(DecodeError::MissingRequiredTlv(
                ExtLsaTlv::InterAreaRouter as u16,
            )),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(0);
        self.options.encode(buf);
        buf.put_u8(0);
        buf.put_u24(self.metric);
        buf.put_ipv4(&self.router_id);
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode top-level TLV.
        let start_pos = tlv_encode_start(buf, ExtLsaTlv::InterAreaRouter);
        // Take advantage of the fact that the TLV fields are identical to the
        // ones of the legacy LSA.
        self.encode_legacy(buf);
        // Encode Sub-TLVs.
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Area;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtInterAreaRouter;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::InterAreaRouter;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaAsExternal =====

impl LsaAsExternal {
    fn decode_legacy(af: AddressFamily, buf: &mut Bytes) -> DecodeResult<Self> {
        let flags = LsaAsExternalFlags::from_bits_truncate(buf.get_u8());
        let metric = buf.get_u24();
        let plen = buf.get_u8();
        let prefix_options = PrefixOptions::from_bits_truncate(buf.get_u8());
        let ref_lsa_type = buf.get_u16();
        let ref_lsa_type = if ref_lsa_type != 0 {
            Some(LsaType(ref_lsa_type))
        } else {
            None
        };
        let prefix = decode_prefix(af, plen, buf)?;
        let fwd_addr = if flags.contains(LsaAsExternalFlags::F) {
            Some(decode_16bit_addr(af, buf))
        } else {
            None
        };
        let tag = if flags.contains(LsaAsExternalFlags::T) {
            Some(buf.get_u32())
        } else {
            None
        };
        let ref_lsa_id = if ref_lsa_type.is_some() {
            Some(buf.get_ipv4())
        } else {
            None
        };

        Ok(LsaAsExternal::new(
            false,
            flags,
            metric,
            prefix_options,
            prefix,
            fwd_addr,
            tag,
            ref_lsa_type,
            ref_lsa_id,
        ))
    }

    fn decode_extended(
        af: AddressFamily,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        let mut ext = None;
        let mut unknown_tlvs = vec![];

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::ExternalPrefix) => {
                    // Instances of the External-Prefix TLV subsequent to the
                    // first MUST be ignored.
                    if ext.is_some() {
                        continue;
                    }

                    let flags = LsaAsExternalFlags::from_bits_truncate(
                        buf_tlv.get_u8(),
                    );
                    let metric = buf_tlv.get_u24();
                    let plen = buf_tlv.get_u8();
                    let prefix_options =
                        PrefixOptions::from_bits_truncate(buf_tlv.get_u8());
                    let _ = buf_tlv.get_u16();
                    let prefix = decode_prefix(af, plen, &mut buf_tlv)?;
                    let mut tlv = LsaAsExternal::new(
                        true,
                        flags,
                        metric,
                        prefix_options,
                        prefix,
                        None,
                        None,
                        None,
                        None,
                    );

                    // Parse Sub-TLVs.
                    let stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;
                    tlv.fwd_addr = match af {
                        AddressFamily::Ipv6 => {
                            stlvs.ipv6_fwd_addr.map(std::convert::Into::into)
                        }
                        AddressFamily::Ipv4 => {
                            stlvs.ipv4_fwd_addr.map(std::convert::Into::into)
                        }
                    };
                    tlv.tag = stlvs.route_tag;
                    tlv.prefix_sids = stlvs.prefix_sids;
                    tlv.unknown_stlvs = stlvs.unknown;

                    ext = Some(tlv);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        // If the External-Prefix TLV is not included in the E-External-AS-LSA,
        // it is treated as malformed.
        match ext {
            Some(mut ext) => {
                ext.unknown_tlvs = unknown_tlvs;
                Ok(ext)
            }
            None => Err(DecodeError::MissingRequiredTlv(
                ExtLsaTlv::ExternalPrefix as u16,
            )),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.metric);
        buf.put_u8(self.prefix.prefix());
        buf.put_u8(self.prefix_options.bits());
        if let Some(ref_lsa_type) = self.ref_lsa_type {
            buf.put_u16(ref_lsa_type.0);
        } else {
            buf.put_u16(0);
        }
        encode_prefix(&self.prefix, buf);
        if let Some(fwd_addr) = &self.fwd_addr {
            encode_16bit_addr(fwd_addr, buf);
        }
        if let Some(tag) = self.tag {
            buf.put_u32(tag);
        }
        if let Some(ref_lsa_id) = &self.ref_lsa_id {
            buf.put_ipv4(ref_lsa_id);
        }
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode top-level TLV.
        let start_pos = tlv_encode_start(buf, ExtLsaTlv::ExternalPrefix);
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.metric);
        buf.put_u8(self.prefix.prefix());
        buf.put_u8(self.prefix_options.bits());
        buf.put_u16(0);
        encode_prefix(&self.prefix, buf);
        self.sub_tlvs().encode(buf);
        tlv_encode_end(buf, start_pos);
    }

    fn sub_tlvs(&self) -> ExtLsaSubTlvs {
        let mut sub_tlvs = ExtLsaSubTlvs::default();
        if let Some(fwd_addr) = &self.fwd_addr {
            match fwd_addr {
                IpAddr::V6(addr) => sub_tlvs.ipv6_fwd_addr = Some(*addr),
                IpAddr::V4(addr) => sub_tlvs.ipv4_fwd_addr = Some(*addr),
            }
        }
        sub_tlvs.route_tag = self.tag;
        sub_tlvs.prefix_sids = self.prefix_sids.clone();
        sub_tlvs
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::As;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtAsExternal;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::AsExternal;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaLink =====

impl LsaLink {
    fn decode_legacy(af: AddressFamily, buf: &mut Bytes) -> DecodeResult<Self> {
        let priority = buf.get_u8();
        let options = Options::decode(buf);
        let linklocal = decode_16bit_addr(af, buf);

        let mut prefixes = vec![];
        let prefixes_cnt = buf.get_u32();
        for _ in 0..prefixes_cnt {
            let plen = buf.get_u8();
            let prefix_options =
                PrefixOptions::from_bits_truncate(buf.get_u8());
            let _ = buf.get_u16();
            let prefix = decode_prefix(af, plen, buf)?;
            let prefix = LsaLinkPrefix::new(prefix_options, prefix);
            prefixes.push(prefix);
        }

        Ok(LsaLink::new(false, priority, options, linklocal, prefixes))
    }

    fn decode_extended(
        af: AddressFamily,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse fixed-format fields.
        let priority = buf.get_u8();
        let options = Options::decode(buf);
        let mut linklocal = None;
        let mut prefixes = vec![];
        let mut unknown_tlvs = vec![];

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::IntraAreaPrefix) => {
                    let _ = buf_tlv.get_u16();
                    let _metric = buf_tlv.get_u16();
                    let plen = buf_tlv.get_u8();
                    let prefix_options =
                        PrefixOptions::from_bits_truncate(buf_tlv.get_u8());
                    let _ = buf_tlv.get_u16();
                    let prefix = decode_prefix(af, plen, &mut buf_tlv)?;
                    let mut prefix = LsaLinkPrefix::new(prefix_options, prefix);

                    // Parse Sub-TLVs.
                    let stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;
                    prefix.unknown_stlvs = stlvs.unknown;

                    prefixes.push(prefix);
                }
                Some(ExtLsaTlv::Ipv6LinkLocalAddr) => {
                    let addr = buf_tlv.get_ipv6();
                    let _stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;

                    if af == AddressFamily::Ipv6 {
                        linklocal = Some(addr.into());
                    }
                }
                Some(ExtLsaTlv::Ipv4LinkLocalAddr) => {
                    let addr = buf_tlv.get_ipv4();
                    let _stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;

                    if af == AddressFamily::Ipv4 {
                        linklocal = Some(addr.into());
                    }
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        // If the IPv4/IPv6 Link-Local Address TLV corresponding to the OSPFv3
        // Address Family is not included in the E-Link-LSA, it is treated as
        // malformed.
        match linklocal {
            Some(linklocal) => Ok(LsaLink {
                extended: true,
                priority,
                options,
                linklocal,
                prefixes,
                unknown_tlvs,
            }),
            None => {
                let tlv_type = match af {
                    AddressFamily::Ipv6 => ExtLsaTlv::Ipv6LinkLocalAddr,
                    AddressFamily::Ipv4 => ExtLsaTlv::Ipv4LinkLocalAddr,
                };
                Err(DecodeError::MissingRequiredTlv(tlv_type as u16))
            }
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u8(self.priority);
        self.options.encode(buf);
        encode_16bit_addr(&self.linklocal, buf);
        buf.put_u32(self.prefixes.len() as u32);
        for prefix in &self.prefixes {
            buf.put_u8(prefix.value.prefix());
            buf.put_u8(prefix.options.bits());
            buf.put_u16(0);
            encode_prefix(&prefix.value, buf);
        }
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode fixed-format fields.
        buf.put_u8(self.priority);
        self.options.encode(buf);

        // Encode IPv6/IPv4 Link-Local Address TLV.
        let tlv_type = match &self.linklocal {
            IpAddr::V6(_) => ExtLsaTlv::Ipv6LinkLocalAddr,
            IpAddr::V4(_) => ExtLsaTlv::Ipv4LinkLocalAddr,
        };
        let start_pos = tlv_encode_start(buf, tlv_type);
        buf.put_ip(&self.linklocal);
        tlv_encode_end(buf, start_pos);

        // Encode Intra-Area-Prefix TLVs.
        for prefix in &self.prefixes {
            let start_pos = tlv_encode_start(buf, ExtLsaTlv::IntraAreaPrefix);
            buf.put_u16(0);
            buf.put_u16(0);
            buf.put_u8(prefix.value.prefix());
            buf.put_u8(prefix.options.bits());
            buf.put_u16(0);
            encode_prefix(&prefix.value, buf);
            // Encode Sub-TLVs.
            tlv_encode_end(buf, start_pos);
        }
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Link;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtLink;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::Link;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaIntraAreaPrefix =====

impl LsaIntraAreaPrefix {
    pub const BASE_LENGTH: u16 = 12;

    fn decode_legacy(af: AddressFamily, buf: &mut Bytes) -> DecodeResult<Self> {
        let prefixes_cnt = buf.get_u16();
        let ref_lsa_type = LsaType(buf.get_u16());
        let ref_lsa_id = buf.get_ipv4();
        let ref_adv_rtr = buf.get_ipv4();

        let mut prefixes = vec![];
        for _ in 0..prefixes_cnt {
            let plen = buf.get_u8();
            let prefix_options =
                PrefixOptions::from_bits_truncate(buf.get_u8());
            let metric = buf.get_u16();
            let prefix = decode_prefix(af, plen, buf)?;
            let prefix =
                LsaIntraAreaPrefixEntry::new(prefix_options, prefix, metric);
            prefixes.push(prefix);
        }

        Ok(LsaIntraAreaPrefix::new(
            false,
            ref_lsa_type,
            ref_lsa_id,
            ref_adv_rtr,
            prefixes,
        ))
    }

    fn decode_extended(
        af: AddressFamily,
        buf: &mut Bytes,
    ) -> DecodeResult<Self> {
        // Parse fixed-format fields.
        let _ = buf.get_u16();
        let ref_lsa_type = LsaType(buf.get_u16());
        let ref_lsa_id = buf.get_ipv4();
        let ref_adv_rtr = buf.get_ipv4();
        let mut iap = LsaIntraAreaPrefix::new(
            true,
            ref_lsa_type,
            ref_lsa_id,
            ref_adv_rtr,
            Default::default(),
        );

        // Parse top-level TLVs.
        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaTlv::from_u16(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let mut buf_tlv = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaTlv::IntraAreaPrefix) => {
                    let _ = buf_tlv.get_u16();
                    let metric = buf_tlv.get_u16();
                    let plen = buf_tlv.get_u8();
                    let prefix_options =
                        PrefixOptions::from_bits_truncate(buf_tlv.get_u8());
                    let _ = buf_tlv.get_u16();
                    let prefix = decode_prefix(af, plen, &mut buf_tlv)?;
                    let mut prefix = LsaIntraAreaPrefixEntry::new(
                        prefix_options,
                        prefix,
                        metric,
                    );

                    // Parse Sub-TLVs.
                    let stlvs = ExtLsaSubTlvs::decode(&mut buf_tlv)?;
                    prefix.prefix_sids = stlvs.prefix_sids;
                    prefix.bier = stlvs.bier;
                    prefix.unknown_stlvs = stlvs.unknown;

                    iap.prefixes.push(prefix);
                }
                _ => {
                    // Save unknown top-level TLV.
                    let value = buf_tlv.copy_to_bytes(tlv_len as usize);
                    iap.unknown_tlvs
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(iap)
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self.extended {
            true => self.encode_extended(buf),
            false => self.encode_legacy(buf),
        }
    }

    fn encode_legacy(&self, buf: &mut BytesMut) {
        buf.put_u16(self.prefixes.len() as u16);
        buf.put_u16(self.ref_lsa_type.0);
        buf.put_ipv4(&self.ref_lsa_id);
        buf.put_ipv4(&self.ref_adv_rtr);
        for prefix in &self.prefixes {
            buf.put_u8(prefix.value.prefix());
            buf.put_u8(prefix.options.bits());
            buf.put_u16(prefix.metric);
            encode_prefix(&prefix.value, buf);
        }
    }

    fn encode_extended(&self, buf: &mut BytesMut) {
        // Encode fixed-format fields.
        buf.put_u16(0);
        buf.put_u16(self.ref_lsa_type.0);
        buf.put_ipv4(&self.ref_lsa_id);
        buf.put_ipv4(&self.ref_adv_rtr);

        // Encode top-level TLVs.
        for prefix in &self.prefixes {
            let start_pos = tlv_encode_start(buf, ExtLsaTlv::IntraAreaPrefix);
            buf.put_u16(0);
            buf.put_u16(prefix.metric);
            buf.put_u8(prefix.value.prefix());
            buf.put_u8(prefix.options.bits());
            buf.put_u16(0);
            encode_prefix(&prefix.value, buf);
            prefix.sub_tlvs().encode(buf);
            tlv_encode_end(buf, start_pos);
        }
    }

    pub(crate) const fn lsa_type(extended: bool) -> LsaType {
        let scope = LsaScopeCode::Area;
        match extended {
            true => {
                let function_code = LsaFunctionCode::ExtIntraAreaPrefix;
                LsaType(U_BIT | scope as u16 | function_code as u16)
            }
            false => {
                let function_code = LsaFunctionCode::IntraAreaPrefix;
                LsaType(scope as u16 | function_code as u16)
            }
        }
    }
}

// ===== impl LsaIntraAreaPrefixEntry =====

impl LsaIntraAreaPrefixEntry {
    pub const MAX_LENGTH_LEGACY: usize = 20;
    pub const MAX_LENGTH_EXT: usize = 28;

    fn sub_tlvs(&self) -> ExtLsaSubTlvs {
        ExtLsaSubTlvs {
            prefix_sids: self.prefix_sids.clone(),
            bier: self.bier.clone(),
            ..Default::default()
        }
    }

    pub(crate) const fn max_length(extended: bool) -> usize {
        match extended {
            true => Self::MAX_LENGTH_EXT,
            false => Self::MAX_LENGTH_LEGACY,
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
    }

    pub(crate) const fn lsa_type() -> LsaType {
        let scope = LsaScopeCode::Link;
        let function_code = LsaFunctionCode::Grace;
        LsaType(scope as u16 | function_code as u16)
    }
}

// ===== impl LsaRouterInfo =====

impl LsaRouterInfo {
    fn decode(lsa_scope: LsaScopeCode, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut router_info = LsaRouterInfo::new(lsa_scope);

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

    pub(crate) const fn lsa_type(&self) -> LsaType {
        let function_code = LsaFunctionCode::RouterInfo;
        LsaType(U_BIT | self.scope as u16 | function_code as u16)
    }

    pub(crate) const fn lsa_type_scope(scope: LsaScopeCode) -> LsaType {
        let function_code = LsaFunctionCode::RouterInfo;
        LsaType(U_BIT | scope as u16 | function_code as u16)
    }
}

// ===== impl LsaUnknown =====

impl LsaUnknown {
    fn decode(_buf: &mut Bytes) -> DecodeResult<Self> {
        Ok(LsaUnknown {})
    }

    // Unknown LSAs are never originated locally.
    fn encode(&self, _buf: &mut BytesMut) {
        #[cfg(not(feature = "testing"))]
        unreachable!()
    }

    // Unknown LSAs are never originated locally.
    const fn lsa_type() -> LsaType {
        unreachable!()
    }
}

// ===== impl ExtLsaSubTlvs =====

impl ExtLsaSubTlvs {
    fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let mut stlvs = ExtLsaSubTlvs::default();

        while buf.remaining() >= TLV_HDR_SIZE as usize {
            // Parse Sub-TLV type.
            let tlv_type = buf.get_u16();
            let tlv_etype = ExtLsaSubTlv::from_u16(tlv_type);

            // Parse and validate Sub-TLV length.
            let tlv_len = buf.get_u16();
            let tlv_wlen = tlv_wire_len(tlv_len);
            if tlv_wlen as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_value = buf.copy_to_bytes(tlv_wlen as usize);
            match tlv_etype {
                Some(ExtLsaSubTlv::Ipv6FwdAddr) => {
                    let addr = buf_value.get_ipv6();
                    stlvs.ipv6_fwd_addr.get_or_insert(addr);
                }
                Some(ExtLsaSubTlv::Ipv4FwdAddr) => {
                    let addr = buf_value.get_ipv4();
                    stlvs.ipv4_fwd_addr.get_or_insert(addr);
                }
                Some(ExtLsaSubTlv::RouteTag) => {
                    let tag = buf_value.get_u32();
                    stlvs.route_tag.get_or_insert(tag);
                }
                Some(ExtLsaSubTlv::PrefixSid) => {
                    let flags = buf_value.get_u8();
                    let flags = PrefixSidFlags::from_bits_truncate(flags);
                    let algo = buf_value.get_u8();
                    let algo = match IgpAlgoType::from_u8(algo) {
                        Some(algo) => algo,
                        None => {
                            // Unsupported algorithm - ignore.
                            continue;
                        }
                    };

                    let _reserved = buf_value.get_u16();

                    // Parse SID (variable length).
                    let sid = if !flags
                        .intersects(PrefixSidFlags::V | PrefixSidFlags::L)
                    {
                        Sid::Index(buf_value.get_u32())
                    } else if flags
                        .contains(PrefixSidFlags::V | PrefixSidFlags::L)
                    {
                        let label = buf_value.get_u24() & Label::VALUE_MASK;
                        Sid::Label(Label::new(label))
                    } else {
                        // Invalid V-Flag and L-Flag combination - ignore.
                        continue;
                    };

                    let prefix_sid = PrefixSid::new(flags, algo, sid);
                    // TODO: in case there are multiple Prefix-SIDs for the same
                    // algorithm, all of them need to be ignored.
                    stlvs.prefix_sids.insert(algo, prefix_sid);
                }
                Some(ExtLsaSubTlv::AdjSid | ExtLsaSubTlv::LanAdjSid) => {
                    let flags =
                        AdjSidFlags::from_bits_truncate(buf_value.get_u8());
                    let weight = buf_value.get_u8();
                    let _reserved = buf_value.get_u16();

                    // Parse Neighbor ID (LAN Adj-SID only).
                    let nbr_router_id = (tlv_etype
                        == Some(ExtLsaSubTlv::LanAdjSid))
                    .then(|| buf_value.get_ipv4());

                    // Parse SID (variable length).
                    let sid = if !flags
                        .intersects(AdjSidFlags::V | AdjSidFlags::L)
                    {
                        Sid::Index(buf_value.get_u32())
                    } else if flags.contains(AdjSidFlags::V | AdjSidFlags::L) {
                        let label = buf_value.get_u24() & Label::VALUE_MASK;
                        Sid::Label(Label::new(label))
                    } else {
                        // Invalid V-Flag and L-Flag combination - ignore.
                        continue;
                    };

                    let adj_sid =
                        AdjSid::new(flags, weight, nbr_router_id, sid);
                    stlvs.adj_sids.push(adj_sid);
                }
                Some(ExtLsaSubTlv::Bier) => {
                    let bier = BierSubTlv::decode(tlv_len, &mut buf_value)?;
                    stlvs.bier.push(bier);
                }
                _ => {
                    // Save unknown Sub-TLV.
                    let value = buf_value.copy_to_bytes(tlv_len as usize);
                    stlvs
                        .unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, value));
                }
            }
        }

        Ok(stlvs)
    }

    fn encode(&self, buf: &mut BytesMut) {
        if let Some(ipv6_fwd_addr) = &self.ipv6_fwd_addr {
            let start_pos = tlv_encode_start(buf, ExtLsaSubTlv::Ipv6FwdAddr);
            buf.put_ipv6(ipv6_fwd_addr);
            tlv_encode_end(buf, start_pos);
        }
        if let Some(ipv4_fwd_addr) = &self.ipv4_fwd_addr {
            let start_pos = tlv_encode_start(buf, ExtLsaSubTlv::Ipv4FwdAddr);
            buf.put_ipv4(ipv4_fwd_addr);
            tlv_encode_end(buf, start_pos);
        }
        if let Some(route_tag) = &self.route_tag {
            let start_pos = tlv_encode_start(buf, ExtLsaSubTlv::RouteTag);
            buf.put_u32(*route_tag);
            tlv_encode_end(buf, start_pos);
        }
        for (algo, prefix_sid) in &self.prefix_sids {
            let start_pos = tlv_encode_start(buf, ExtLsaSubTlv::PrefixSid);
            buf.put_u8(prefix_sid.flags.bits());
            buf.put_u8(*algo as u8);
            buf.put_u16(0);
            match prefix_sid.sid {
                Sid::Index(index) => buf.put_u32(index),
                Sid::Label(label) => buf.put_u24(label.get()),
            }
            tlv_encode_end(buf, start_pos);
        }
        for adj_sid in &self.adj_sids {
            let stlv_type = match adj_sid.nbr_router_id.is_some() {
                true => ExtLsaSubTlv::LanAdjSid,
                false => ExtLsaSubTlv::AdjSid,
            };
            let start_pos = tlv_encode_start(buf, stlv_type);
            buf.put_u8(adj_sid.flags.bits());
            buf.put_u8(adj_sid.weight);
            buf.put_u16(0);
            if let Some(nbr_router_id) = &adj_sid.nbr_router_id {
                buf.put_ipv4(nbr_router_id);
            }
            match adj_sid.sid {
                Sid::Index(index) => buf.put_u32(index),
                Sid::Label(label) => buf.put_u24(label.get()),
            }
            tlv_encode_end(buf, start_pos);
        }
        for bier in &self.bier {
            BierSubTlv::encode(bier, buf, ExtLsaSubTlv::Bier);
        }
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

// ===== impl Ospfv3 =====

impl LsaVersion<Self> for Ospfv3 {
    type LsaType = LsaType;
    type LsaHdr = LsaHdr;
    type LsaBody = LsaBody;
    type LsaRouterFlags = LsaRouterFlags;
    type LsaRouterLink = LsaRouterLink;
    type PrefixOptions = PrefixOptions;
    type PrefixSid = PrefixSid;
    type AdjSid = AdjSid;

    fn type3_summary(extended_lsa: bool) -> LsaType {
        LsaInterAreaPrefix::lsa_type(extended_lsa)
    }

    fn type4_summary(extended_lsa: bool) -> LsaType {
        LsaInterAreaRouter::lsa_type(extended_lsa)
    }
}

// ===== global functions =====

// Calculate the number of bytes required to encode a prefix.
fn prefix_wire_len(len: u8) -> usize {
    ((len as usize + 31) / 32) * 4
}

fn decode_16bit_addr(af: AddressFamily, buf: &mut Bytes) -> IpAddr {
    match af {
        AddressFamily::Ipv4 => {
            // As per RFC5838, fetch the address from the first four bytes and
            // ignore the rest.
            let addr = IpAddr::V4(buf.get_ipv4());
            buf.advance(12);
            addr
        }
        AddressFamily::Ipv6 => IpAddr::V6(buf.get_ipv6()),
    }
}

fn encode_16bit_addr(addr: &IpAddr, buf: &mut BytesMut) {
    match addr {
        IpAddr::V4(addr) => {
            // As per RFC5838, place the address in the first four bytes and
            // fill the remaining with zeroes.
            buf.put_ipv4(addr);
            buf.put_slice(&[0; 12]);
        }
        IpAddr::V6(addr) => {
            buf.put_ipv6(addr);
        }
    }
}

fn decode_prefix(
    af: AddressFamily,
    plen: u8,
    buf: &mut Bytes,
) -> DecodeResult<IpNetwork> {
    let plen_wire = prefix_wire_len(plen);
    let prefix = match af {
        AddressFamily::Ipv4 => {
            let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
            buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
            Ipv4Addr::from(prefix_bytes).into()
        }
        AddressFamily::Ipv6 => {
            let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
            buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
            Ipv6Addr::from(prefix_bytes).into()
        }
    };
    IpNetwork::new(prefix, plen).map_err(|_| DecodeError::InvalidIpPrefix)
}

fn encode_prefix(prefix: &IpNetwork, buf: &mut BytesMut) {
    let prefix_bytes = prefix.ip().bytes();
    let plen_wire = prefix_wire_len(prefix.prefix());
    buf.put(&prefix_bytes[0..plen_wire]);
}
