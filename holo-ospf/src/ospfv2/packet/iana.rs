//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

// OSPFv2 Options field.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-1
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Options: u8 {
        const E = 0x02;
        const MC = 0x04;
        const NP = 0x08;
        const L = 0x10;
        const DC = 0x20;
        const O = 0x40;
    }
}

// OSPFv2 authentication type.
//
// IANA registry:
// https://www.iana.org/assignments/ospf-authentication-codes/ospf-authentication-codes.xhtml
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AuthType {
    Null = 0x00,
    Simple = 0x01,
    Cryptographic = 0x02,
}

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
        const AC = 0x10;
    }
}

// OSPFv2 Extended Prefix TLV Sub-TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-prefix-tlv-sub-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtPrefixStlvType {
    SidLabel = 1,
    PrefixSid = 2,
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

// OSPFv2 Extended Link TLV Sub-TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#extended-link-tlv-sub-tlvs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ExtLinkStlvType {
    SidLabel = 1,
    AdjSid = 2,
    LanAdjSid = 3,
    LinkMsd = 6,
}
