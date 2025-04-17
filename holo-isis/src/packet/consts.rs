//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

pub const IDRP_DISCRIMINATOR: u8 = 0x83;
pub const VERSION_PROTO_EXT: u8 = 1;
pub const VERSION: u8 = 1;
pub const SYSTEM_ID_LEN: u8 = 6;

// IS-IS PDU types.
//
// IANA registry:
// https://www.iana.org/assignments/isis-pdu/isis-pdu.xhtml#pdu
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum PduType {
    HelloLanL1 = 15,
    HelloLanL2 = 16,
    HelloP2P = 17,
    LspL1 = 18,
    LspL2 = 20,
    CsnpL1 = 24,
    CsnpL2 = 25,
    PsnpL1 = 26,
    PsnpL2 = 27,
}

// IS-IS top-level TLV types.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#tlv-codepoints
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum TlvType {
    AreaAddresses = 1,
    IsReach = 2,
    Neighbors = 6,
    Padding = 8,
    LspEntries = 9,
    Authentication = 10,
    LspBufferSize = 14,
    ExtIsReach = 22,
    Ipv4InternalReach = 128,
    ProtocolsSupported = 129,
    Ipv4ExternalReach = 130,
    Ipv4Addresses = 132,
    Ipv4RouterId = 134,
    ExtIpv4Reach = 135,
    DynamicHostname = 137,
    Ipv6RouterId = 140,
    Ipv6Addresses = 232,
    Ipv6Reach = 236,
    RouterCapability = 242,
}

// IS-IS Authentication Type Codes.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-10
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AuthenticationType {
    ClearText = 1,
    HmacMd5 = 54,
}

// IS-IS Sub-TLVs for TLVs Advertising Neighbor Information.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-advertising-neighbor-information
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum NeighborStlvType {
    AdminGroup = 3,
    Ipv4InterfaceAddress = 6,
    Ipv4NeighborAddress = 8,
    MaxLinkBandwidth = 9,
    MaxResvLinkBandwidth = 10,
    UnreservedBandwidth = 11,
    TeDefaultMetric = 18,
    AdjacencySid = 31,
    LanAdjacencySid = 32,
}

// IS-IS Sub-TLVs for TLVs Advertising Prefix Reachability.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-advertising-prefix-reachability
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum PrefixStlvType {
    PrefixSid = 3,
    PrefixAttributeFlags = 4,
    Ipv4SourceRouterId = 11,
    Ipv6SourceRouterId = 12,
    BierInfo = 32,
}

// IS-IS Sub-TLVs for the Router Capability TLV.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-242
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum RouterCapStlvType {
    SrCapability = 2,
    SrAlgorithm = 19,
    SrLocalBlock = 22,
}

// IS-IS Sub-TLVs for Segment Identifier/Label Binding TLVs.
//
// IANA registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#tlv-149-150
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum LabelBindingStlvType {
    SidLabel = 1,
}

// IS-IS Sub-Sub-TLVs for BIER Info Sub-TLV.
//
// IANA Registry:
// https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#bier-info-sub-tlv
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum BierSubStlvType {
    MplsEncap = 1,
    // FIXME: TBD1 in https://datatracker.ietf.org/doc/html/draft-ietf-bier-lsr-non-mpls-extensions-03#name-is-is-bier-non-mpls-encapsu
    NonMplsEncap = 42,
}

// IS-IS LSP flags field.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LspFlags: u8 {
        const P = 0x80;
        const ATT = 0x40;
        const OL = 0x04;
        const IS_TYPE2 = 0x02;
        const IS_TYPE1 = 0x01;
    }
}
