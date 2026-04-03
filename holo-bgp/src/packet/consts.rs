//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use arbitrary::Arbitrary;
use bitflags::bitflags;
use holo_utils::ip::AddressFamily;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

pub const BGP_VERSION: u8 = 4;
pub const AS_TRANS: u16 = 23456;

// BGP Message Types.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    // RFC 2918
    RouteRefresh = 5,
}

// BGP OPEN Optional Parameter Types.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum OpenParamType {
    // RFC5492
    Capabilities = 2,
}

// Capability Codes.
//
// IANA registry:
// https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum CapabilityCode {
    // RFC 2858
    MultiProtocol = 1,
    // RFC 2918
    RouteRefresh = 2,
    // RFC 5291
    //OutboundRouteFiltering = 3,
    // RFC 8950
    //ExtendedNextHop = 5,
    // RFC 8654
    //ExtendedMessage = 6,
    // RFC 8205
    //BgpSec = 7,
    // RFC 8277
    //MultipleLabels = 8,
    // RFC 9234
    BgpRole = 9,
    // RFC 4724
    //GracefulRestart = 64,
    // RFC 6793
    FourOctetAsNumber = 65,
    // RFC7911
    AddPath = 69,
    // RFC7313
    EnhancedRouteRefresh = 70,
}

// Send/Receive value for a per-AFI/SAFI instance of the ADD-PATH Capability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AddPathMode {
    Receive = 1,
    Send = 2,
    ReceiveSend = 3,
}

// BGP Error (Notification) Codes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum ErrorCode {
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6,
    // RFC 7313
    RouteRefreshMessageError = 7,
}

// Message Header Error subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum MessageHeaderErrorSubcode {
    Unspecific = 0,
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
    // RFC 9234.
    RoleMismatch = 11,
}

// OPEN Message Error subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-6
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum OpenMessageErrorSubcode {
    Unspecific = 0,
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptParam = 4,
    UnacceptableHoldTime = 6,
    // RFC 5492
    UnsupportedCapability = 7,
    // RFC 9234
    RoleMismatch = 11,
}

// UPDATE Message Error subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-7
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum UpdateMessageErrorSubcode {
    Unspecific = 0,
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    InvalidNexthopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

// BGP Finite State Machine Error Subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum FsmErrorSubcode {
    UnexpectedMessageInOpenSent = 1,
    UnexpectedMessageInOpenConfirm = 2,
    UnexpectedMessageInEstablished = 3,
}

// BGP Cease NOTIFICATION message subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-8
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum CeaseSubcode {
    MaximumNumberofPrefixesReached = 1,
    AdministrativeShutdown = 2,
    PeerDeConfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollisionResolution = 7,
    OutOfResources = 8,
    // RFC 8538
    HardReset = 9,
    // RFC 9384
    BfdDown = 10,
}

// BGP ROUTE-REFRESH Message Error subcodes.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-error-subcodes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum RouteRefreshErrorSubcode {
    InvalidMessageLength = 1,
}

// Address Family identifiers (AFI).
pub type Afi = AddressFamily;

// Subsequent Address Family Identifiers (SAFI).
//
// IANA registry:
// https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml#safi-namespace-2
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
#[derive(Arbitrary)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    LabeledUnicast = 4,
    MulticastVpn = 5,
    Pseudowire = 6,
    TunnelEncap = 7,
    McastVpls = 8,
    Tunnel = 64,
    Vpls = 65,
    Mdt = 66,
    V4OverV6 = 67,
    V6OverV4 = 68,
    L1VpnAutoDiscovery = 69,
    Evpn = 70,
    BgpLs = 71,
    BgpLsVpn = 72,
    SrTe = 73,
    SdWanCapabilities = 74,
    LabeledVpn = 128,
    MulticastMplsVpn = 129,
    RouteTarget = 132,
    Ipv4FlowSpec = 133,
    Vpnv4FlowSpec = 134,
    VpnAutoDiscovery = 140,
}

// BGP Path Attribute Flags.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AttrFlags: u8 {
        const OPTIONAL = 0x80;
        const TRANSITIVE = 0x40;
        const PARTIAL = 0x20;
        const EXTENDED = 0x10;
    }
}

// BGP Path Attribute Types.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
#[derive(Arbitrary)]
pub enum AttrType {
    Origin = 1,
    AsPath = 2,
    Nexthop = 3,
    Med = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    // RFC 1997
    Communities = 8,
    // RFC 4456
    OriginatorId = 9,
    ClusterList = 10,
    // RFC 4760
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    // RFC 4360
    ExtCommunities = 16,
    // RFC 6793
    As4Path = 17,
    As4Aggregator = 18,
    // RFC 6514
    //PmsiTunnel = 22,
    // RFC 9012
    //TunnelEncap = 23,
    // RFC 5543
    //TrafficEngineering = 24,
    // RFC 5701
    Extv6Community = 25,
    // RFC 7311
    //Aigp = 26,
    // RFC 6514
    //PeDistinguisherLabels = 27,
    // RFC-ietf-idr-rfc7752bis-16
    //BgpLs = 29,
    // RFC 8092
    LargeCommunity = 32,
    // RFC 8205
    //BgpSecPath = 33,
    // RFC 9234
    Otc = 35,
    // RFC 9015
    //Sfp = 37,
    // RFC 9026
    //BfdDiscriminator = 38,
    // RFC 8669
    //BgpPrefixSid = 40,
    // RFC6 368
    //AttrSet = 128,
}

// BGP Origin.
pub type Origin = holo_utils::bgp::Origin;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AsPathSegmentType {
    Set = 1,
    Sequence = 2,
    ConfedSequence = 3,
    ConfedSet = 4,
}

// Re-exports for convenience.
pub type WellKnownCommunities = holo_utils::bgp::WellKnownCommunities;

// BGP AIGP Attribute Types.
//
// IANA registry:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-aigp
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum AigpType {
    Aigp = 1,
}
