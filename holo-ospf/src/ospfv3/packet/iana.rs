//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

// OSPFv3 Options field.
//
// IANA registry:
// https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-1
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Options: u16 {
        const V6 = 0x0001;
        const E = 0x0002;
        const N = 0x0008;
        const R = 0x0010;
        const DC = 0x0020;
        const AF = 0x0100;
        const L = 0x0200;
        const AT = 0x0400;
    }
}

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
pub enum ExtLsaStlv {
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
