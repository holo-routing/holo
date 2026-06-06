//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

// OSPF Packet Type (both v2 and v3).
//
// IANA registry:
// https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3
#[derive(Clone, Copy, Debug, Eq, Hash, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PacketType {
    Hello = 0x01,
    DbDesc = 0x02,
    LsRequest = 0x03,
    LsUpdate = 0x04,
    LsAck = 0x05,
}

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
    NodeAdminTag = 10,
    NodeMsd = 12,
    SrLocalBlock = 14,
    SrmsPref = 15,
}

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
