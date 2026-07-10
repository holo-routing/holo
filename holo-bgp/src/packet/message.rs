//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_as_inner::EnumAsInner;
use holo_utils::bgp::RouteDistinguisher;
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::ip::{
    IpAddrExt, Ipv4AddrExt, Ipv4NetworkExt, Ipv6AddrExt, Ipv6NetworkExt,
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::neighbor::PeerType;
use crate::packet::attribute::Attrs;
use crate::packet::error::{
    DecodeError, MessageHeaderError, OpenMessageError, UpdateMessageError,
};
use crate::packet::iana::{
    Afi, CapabilityCode, ErrorCode, MessageHeaderErrorSubcode, MessageType,
    OpenMessageErrorSubcode, OpenParamType, Safi, UpdateMessageErrorSubcode,
};

//
// BGP message.
//
// Encoding format (message header):
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                                                               +
// |                           Marker                              |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Length               |      Type     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Message {
    Open(OpenMsg),
    Update(UpdateMsg),
    Notification(NotificationMsg),
    Keepalive(KeepaliveMsg),
    RouteRefresh(RouteRefreshMsg),
}

//
// OPEN Message.
//
// Encoding format (message body):
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+
// |    Version    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     My Autonomous System      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Hold Time           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         BGP Identifier                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Opt Parm Len  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |             Optional Parameters (variable)                    |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Encoding format (optional parameter):
//
// 0                   1
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
// |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct OpenMsg {
    pub version: u8,
    pub my_as: u16,
    pub holdtime: u16,
    pub identifier: Ipv4Addr,
    pub capabilities: BTreeSet<Capability>,
}

//
// Capabilities Optional Parameter.
//
// Encoding format:
//
// +------------------------------+
// | Capability Code (1 octet)    |
// +------------------------------+
// | Capability Length (1 octet)  |
// +------------------------------+
// | Capability Value (variable)  |
// ~                              ~
// +------------------------------+
//
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(EnumAsInner)]
#[derive(Deserialize, Serialize)]
pub enum Capability {
    MultiProtocol { afi: Afi, safi: Safi },
    FourOctetAsNumber { asn: u32 },
    AddPath(BTreeSet<AddPathTuple>),
    RouteRefresh,
    EnhancedRouteRefresh,
}

// This is a stripped down version of `Capability`, containing only data that
// is relevant in terms of capability negotiation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(EnumAsInner)]
#[derive(Deserialize, Serialize)]
#[derive(Arbitrary)]
pub enum NegotiatedCapability {
    MultiProtocol { afi: Afi, safi: Safi },
    FourOctetAsNumber,
    AddPath,
    RouteRefresh,
    EnhancedRouteRefresh,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct AddPathTuple {
    pub afi: Afi,
    pub safi: Safi,
    pub mode: AddPathMode,
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

//
// UPDATE Message.
//
// Encoding format (message body):
//
// +-----------------------------------------------------+
// |   Withdrawn Routes Length (2 octets)                |
// +-----------------------------------------------------+
// |   Withdrawn Routes (variable)                       |
// +-----------------------------------------------------+
// |   Total Path Attribute Length (2 octets)            |
// +-----------------------------------------------------+
// |   Path Attributes (variable)                        |
// +-----------------------------------------------------+
// |   Network Layer Reachability Information (variable) |
// +-----------------------------------------------------+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct UpdateMsg {
    pub reach: Option<ReachNlri>,
    pub unreach: Option<UnreachNlri>,
    pub mp_reach: Option<MpReachNlri>,
    pub mp_unreach: Option<MpUnreachNlri>,
    pub attrs: Option<Attrs>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ReachNlri {
    pub prefixes: Vec<Ipv4Network>,
    pub nexthop: Ipv4Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct UnreachNlri {
    pub prefixes: Vec<Ipv4Network>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MpReachNlri {
    Ipv4Unicast {
        prefixes: Vec<Ipv4Network>,
        nexthop: Ipv4Addr,
    },
    Ipv6Unicast {
        prefixes: Vec<Ipv6Network>,
        nexthop: Ipv6Addr,
        ll_nexthop: Option<Ipv6Addr>,
    },
    L3vpnIpv4Unicast {
        prefixes: Vec<LabeledVpnIpv4Nlri>,
        nexthop: Ipv4Addr,
    },
    L3vpnIpv6Unicast {
        prefixes: Vec<LabeledVpnIpv6Nlri>,
        nexthop: Ipv6Addr,
    },
    L2vpnEvpn {
        routes: Vec<EvpnRoute>,
        nexthop: IpAddr,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MpUnreachNlri {
    Ipv4Unicast { prefixes: Vec<Ipv4Network> },
    Ipv6Unicast { prefixes: Vec<Ipv6Network> },
    L3vpnIpv4Unicast { prefixes: Vec<LabeledVpnIpv4Nlri> },
    L3vpnIpv6Unicast { prefixes: Vec<LabeledVpnIpv6Nlri> },
    L2vpnEvpn { routes: Vec<EvpnRoute> },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LabeledVpnIpv4Nlri {
    pub label: u32,
    pub rd: RouteDistinguisher,
    pub prefix: Ipv4Network,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct LabeledVpnIpv6Nlri {
    pub label: u32,
    pub rd: RouteDistinguisher,
    pub prefix: Ipv6Network,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum EvpnRoute {
    EthernetAutoDiscovery(EvpnEthernetAutoDiscovery),
    EthernetSegment(EvpnEthernetSegment),
    MacIpAdvertisement(EvpnMacIpAdvertisement),
    InclusiveMulticastEthernetTag(EvpnInclusiveMulticastEthernetTag),
    IpPrefix(EvpnIpPrefix),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EvpnEthernetAutoDiscovery {
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ethernet_tag_id: u32,
    pub label: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EvpnEthernetSegment {
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub originator_ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EvpnMacIpAdvertisement {
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ethernet_tag_id: u32,
    pub mac: [u8; 6],
    pub ip: Option<IpAddr>,
    pub label: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EvpnInclusiveMulticastEthernetTag {
    pub rd: RouteDistinguisher,
    pub ethernet_tag_id: u32,
    pub originator_ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EvpnIpPrefix {
    pub rd: RouteDistinguisher,
    pub esi: [u8; 10],
    pub ethernet_tag_id: u32,
    pub prefix: IpNetwork,
    pub gateway_ip: Option<IpAddr>,
    pub label: u32,
}

//
// NOTIFICATION Message.
//
// Encoding format (message body):
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Error code    | Error subcode |   Data (variable)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct NotificationMsg {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

//
// KEEPALIVE Message.
//
// A KEEPALIVE message consists of only the message header and has a length of
// 19 octets.
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct KeepaliveMsg {}

//
// Route-REFRESH Message.
//
// Encoding format (message body):
//
// 0       7      15      23      31
// +-------+-------+-------+-------+
// |      AFI      | Res.  | SAFI  |
// +-------+-------+-------+-------+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct RouteRefreshMsg {
    pub afi: u16,
    pub safi: u8,
}

// BGP message decoding context.
pub struct EncodeCxt {
    pub capabilities: BTreeSet<NegotiatedCapability>,
}

// BGP message decoding context.
#[derive(Debug)]
#[derive(Arbitrary)]
pub struct DecodeCxt {
    pub peer_type: PeerType,
    pub peer_as: u32,
    pub reject_as_sets: bool,
    pub capabilities: BTreeSet<NegotiatedCapability>,
}

// ===== impl Message =====

impl Message {
    pub const MIN_LEN: u16 = 19;
    pub const MAX_LEN: u16 = 4096;
    const MSG_LEN_POS: std::ops::Range<usize> = 16..18;

    // Encodes BGP message into a bytes buffer.
    pub fn encode(&self, cxt: &EncodeCxt) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            // Marker field.
            buf.put_u128(u128::MAX);
            // The length field will be initialized later.
            buf.put_u16(0);

            // Message type and body.
            match self {
                Message::Open(msg) => msg.encode(&mut buf),
                Message::Update(msg) => msg.encode(&mut buf, cxt),
                Message::Notification(msg) => msg.encode(&mut buf),
                Message::Keepalive(msg) => msg.encode(&mut buf),
                Message::RouteRefresh(msg) => msg.encode(&mut buf),
            }

            // Rewrite message length.
            let msg_len = buf.len() as u16;
            buf[Self::MSG_LEN_POS].copy_from_slice(&msg_len.to_be_bytes());

            buf.clone().freeze()
        })
    }

    // Decode buffer into a BGP message.
    pub fn decode(data: &[u8], cxt: &DecodeCxt) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(data);

        let msg_etype = Self::decode_header(&mut buf)?;
        match msg_etype {
            MessageType::Open => {
                let msg = OpenMsg::decode(&mut buf)?;
                Ok(Message::Open(msg))
            }
            MessageType::Update => {
                let msg = UpdateMsg::decode(&mut buf, cxt)?;
                Ok(Message::Update(msg))
            }
            MessageType::Notification => {
                let msg = NotificationMsg::decode(&mut buf)?;
                Ok(Message::Notification(msg))
            }
            MessageType::Keepalive => {
                let msg = KeepaliveMsg::decode(&mut buf)?;
                Ok(Message::Keepalive(msg))
            }
            MessageType::RouteRefresh => {
                let msg = RouteRefreshMsg::decode(&mut buf)?;
                Ok(Message::RouteRefresh(msg))
            }
        }
    }

    // Decodes the BGP message header.
    fn decode_header(
        buf: &mut Bytes,
    ) -> Result<MessageType, MessageHeaderError> {
        // Parse and validate marker.
        let marker = buf.try_get_u128()?;
        if marker != u128::MAX {
            return Err(MessageHeaderError::ConnectionNotSynchronized);
        }

        // Parse and validate message length.
        let msg_len = buf.try_get_u16()?;
        if msg_len < Self::MIN_LEN || msg_len > Self::MAX_LEN {
            return Err(MessageHeaderError::BadMessageLength(msg_len));
        }

        // Parse message type.
        let msg_type = buf.try_get_u8()?;
        let Some(msg_etype) = MessageType::from_u8(msg_type) else {
            return Err(MessageHeaderError::BadMessageType(msg_type));
        };

        // Parse message body.
        let min_msg_len = match msg_etype {
            MessageType::Open => OpenMsg::MIN_LEN,
            MessageType::Update => UpdateMsg::MIN_LEN,
            MessageType::Notification => NotificationMsg::MIN_LEN,
            MessageType::Keepalive => KeepaliveMsg::LEN,
            MessageType::RouteRefresh => RouteRefreshMsg::LEN,
        };
        if msg_len < min_msg_len {
            return Err(MessageHeaderError::BadMessageLength(msg_len));
        }

        Ok(msg_etype)
    }

    // Parses the given buffer to determine if it contains a complete BGP
    // message, and returns the length of the message if successful.
    pub fn get_message_len(data: &[u8]) -> Option<usize> {
        // Validate that the buffer contains sufficient space for at least the
        // message header.
        let buf_size = data.len();
        if buf_size < Self::MIN_LEN as usize {
            return None;
        }

        // Ensure the buffer is big enough to hold the entire message.
        let mut buf = Bytes::copy_from_slice(&data[0..Self::MIN_LEN as usize]);
        let _marker = buf.get_u128();
        let msg_len = buf.get_u16();
        if msg_len < Self::MIN_LEN || msg_len as usize > buf_size {
            return None;
        }

        // Return the message size.
        Some(msg_len as usize)
    }
}

// ===== impl OpenMsg =====

impl OpenMsg {
    pub const VERSION: u8 = 4;
    const MIN_LEN: u16 = 29;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(MessageType::Open as u8);
        buf.put_u8(self.version);
        buf.put_u16(self.my_as);
        buf.put_u16(self.holdtime);
        buf.put_ipv4(&self.identifier);

        // Capabilities.
        let opt_param_len_pos = buf.len();
        buf.put_u8(0);
        for capability in &self.capabilities {
            buf.put_u8(OpenParamType::Capabilities as u8);

            // The "Parm. Length" field will be initialized later.
            let param_len_pos = buf.len();
            buf.put_u8(0);

            // Encode individual capability.
            capability.encode(buf);

            // Rewrite the "Parm. Length" field.
            let param_len = buf.len() - param_len_pos - 1;
            buf[param_len_pos] = param_len as u8;
        }

        // Rewrite the "Opt Parm Len" field.
        let opt_param_len = buf.len() - opt_param_len_pos - 1;
        buf[opt_param_len_pos] = opt_param_len as u8;
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, OpenMessageError> {
        // Parse and validate BGP version.
        let version = buf.try_get_u8()?;
        if version != Self::VERSION {
            return Err(OpenMessageError::UnsupportedVersion(Self::VERSION));
        }

        // Parse and validate ASN.
        let my_as = buf.try_get_u16()?;
        if my_as == 0 {
            return Err(OpenMessageError::BadPeerAs);
        }

        // Parse and validate hold time.
        let holdtime = buf.try_get_u16()?;
        if holdtime == 1 || holdtime == 2 {
            return Err(OpenMessageError::UnacceptableHoldTime);
        }

        // Parse and validate BGP identifier.
        //
        // RFC 6286 redefines the BGP Identifier as a 4-octet, unsigned,
        // non-zero integer (no longer restricted to valid unicast IPv4).
        let identifier = buf.try_get_ipv4()?;
        if identifier.is_unspecified() {
            return Err(OpenMessageError::BadBgpIdentifier);
        }

        // Parse and validate optional parameters.
        let mut capabilities = BTreeSet::new();
        let opt_param_len = buf.try_get_u8()?;
        if opt_param_len as usize > buf.remaining() {
            return Err(OpenMessageError::MalformedOptParam);
        }
        let mut buf_opts = buf.copy_to_bytes(opt_param_len as usize);
        while buf_opts.remaining() > 0 {
            if buf_opts.remaining() < 2 {
                return Err(OpenMessageError::MalformedOptParam);
            }
            let param_type = buf_opts.try_get_u8()?;
            let param_len = buf_opts.try_get_u8()?;
            if param_len as usize > buf_opts.remaining() {
                return Err(OpenMessageError::MalformedOptParam);
            }
            let mut buf_param_value =
                buf_opts.copy_to_bytes(param_len as usize);

            // Parse and validate capabilities.
            match OpenParamType::from_u8(param_type) {
                Some(OpenParamType::Capabilities) => {
                    while buf_param_value.remaining() > 0 {
                        if let Some(cap) =
                            Capability::decode(&mut buf_param_value)?
                        {
                            capabilities.insert(cap);
                        }
                    }
                }
                None => {
                    return Err(OpenMessageError::UnsupportedOptParam);
                }
            }
        }

        Ok(OpenMsg {
            version,
            my_as,
            holdtime,
            identifier,
            capabilities,
        })
    }

    pub fn real_as(&self) -> u32 {
        self.capabilities
            .iter()
            .find_map(|cap| {
                if let Capability::FourOctetAsNumber { asn } = cap {
                    Some(*asn)
                } else {
                    None
                }
            })
            .unwrap_or(self.my_as as u32)
    }
}

// ===== impl Capability =====

impl Capability {
    fn encode(&self, buf: &mut BytesMut) {
        let start_pos = buf.len();

        match self {
            Capability::MultiProtocol { afi, safi } => {
                buf.put_u8(CapabilityCode::MultiProtocol as u8);
                buf.put_u8(0);
                buf.put_u16(*afi as u16);
                buf.put_u8(0);
                buf.put_u8(*safi as u8);
            }
            Capability::FourOctetAsNumber { asn } => {
                buf.put_u8(CapabilityCode::FourOctetAsNumber as u8);
                buf.put_u8(0);
                buf.put_u32(*asn);
            }
            Capability::AddPath(tuples) => {
                buf.put_u8(CapabilityCode::AddPath as u8);
                buf.put_u8(0);
                for tuple in tuples {
                    buf.put_u16(tuple.afi as u16);
                    buf.put_u8(tuple.safi as u8);
                    buf.put_u8(tuple.mode as u8);
                }
            }
            Capability::RouteRefresh => {
                buf.put_u8(CapabilityCode::RouteRefresh as u8);
                buf.put_u8(0);
            }
            Capability::EnhancedRouteRefresh => {
                buf.put_u8(CapabilityCode::EnhancedRouteRefresh as u8);
                buf.put_u8(0);
            }
        }

        // Rewrite the "Capability Length" field.
        let cap_len = buf.len() - start_pos - 2;
        buf[start_pos + 1] = cap_len as u8;
    }

    pub fn decode(buf: &mut Bytes) -> Result<Option<Self>, OpenMessageError> {
        if buf.remaining() < 2 {
            return Err(OpenMessageError::MalformedOptParam);
        }
        let cap_type = buf.try_get_u8()?;
        let cap_len = buf.try_get_u8()?;
        if cap_len as usize > buf.remaining() {
            return Err(OpenMessageError::MalformedOptParam);
        }

        let mut buf_cap = buf.copy_to_bytes(cap_len as usize);
        let cap = match CapabilityCode::from_u8(cap_type) {
            Some(CapabilityCode::MultiProtocol) => {
                if cap_len != 4 {
                    return Err(OpenMessageError::MalformedOptParam);
                }

                let afi = buf_cap.try_get_u16()?;
                let Some(afi) = Afi::from_u16(afi) else {
                    // Ignore unknown AFI.
                    return Ok(None);
                };
                let _reserved = buf_cap.try_get_u8()?;
                let safi = buf_cap.try_get_u8()?;
                let Some(safi) = Safi::from_u8(safi) else {
                    // Ignore unknown SAFI.
                    return Ok(None);
                };

                Capability::MultiProtocol { afi, safi }
            }
            Some(CapabilityCode::FourOctetAsNumber) => {
                if cap_len != 4 {
                    return Err(OpenMessageError::MalformedOptParam);
                }

                let asn = buf_cap.try_get_u32()?;
                if asn == 0 {
                    return Err(OpenMessageError::BadPeerAs);
                }
                Capability::FourOctetAsNumber { asn }
            }
            Some(CapabilityCode::AddPath) => {
                if cap_len % 4 != 0 {
                    return Err(OpenMessageError::MalformedOptParam);
                }

                let mut tuples = BTreeSet::new();
                while buf_cap.remaining() > 0 {
                    let afi = buf_cap.try_get_u16()?;
                    let Some(afi) = Afi::from_u16(afi) else {
                        // Ignore unknown AFI.
                        return Ok(None);
                    };
                    let safi = buf_cap.try_get_u8()?;
                    let Some(safi) = Safi::from_u8(safi) else {
                        // Ignore unknown SAFI.
                        return Ok(None);
                    };
                    let mode = buf_cap.try_get_u8()?;
                    let Some(mode) = AddPathMode::from_u8(mode) else {
                        // Ignore unknown value.
                        return Ok(None);
                    };
                    tuples.insert(AddPathTuple { afi, safi, mode });
                }
                Capability::AddPath(tuples)
            }
            Some(CapabilityCode::RouteRefresh) => {
                if cap_len != 0 {
                    return Err(OpenMessageError::MalformedOptParam);
                }

                Capability::RouteRefresh
            }
            Some(CapabilityCode::EnhancedRouteRefresh) => {
                if cap_len != 0 {
                    return Err(OpenMessageError::MalformedOptParam);
                }

                Capability::EnhancedRouteRefresh
            }
            _ => {
                // Ignore unknown capability.
                return Ok(None);
            }
        };

        Ok(Some(cap))
    }

    pub fn code(&self) -> CapabilityCode {
        match self {
            Capability::MultiProtocol { .. } => CapabilityCode::MultiProtocol,
            Capability::FourOctetAsNumber { .. } => {
                CapabilityCode::FourOctetAsNumber
            }
            Capability::AddPath { .. } => CapabilityCode::AddPath,
            Capability::RouteRefresh => CapabilityCode::RouteRefresh,
            Capability::EnhancedRouteRefresh => {
                CapabilityCode::EnhancedRouteRefresh
            }
        }
    }

    pub fn as_negotiated(&self) -> NegotiatedCapability {
        match *self {
            Capability::MultiProtocol { afi, safi } => {
                NegotiatedCapability::MultiProtocol { afi, safi }
            }
            Capability::FourOctetAsNumber { .. } => {
                NegotiatedCapability::FourOctetAsNumber
            }
            Capability::AddPath { .. } => NegotiatedCapability::AddPath,
            Capability::RouteRefresh => NegotiatedCapability::RouteRefresh,
            Capability::EnhancedRouteRefresh => {
                NegotiatedCapability::EnhancedRouteRefresh
            }
        }
    }
}

// ===== impl NegotiatedCapability =====

impl NegotiatedCapability {
    pub fn code(&self) -> CapabilityCode {
        match self {
            NegotiatedCapability::MultiProtocol { .. } => {
                CapabilityCode::MultiProtocol
            }
            NegotiatedCapability::FourOctetAsNumber => {
                CapabilityCode::FourOctetAsNumber
            }
            NegotiatedCapability::AddPath => CapabilityCode::AddPath,
            NegotiatedCapability::RouteRefresh => CapabilityCode::RouteRefresh,
            NegotiatedCapability::EnhancedRouteRefresh => {
                CapabilityCode::EnhancedRouteRefresh
            }
        }
    }
}

// ===== impl UpdateMsg =====

impl UpdateMsg {
    pub const MIN_LEN: u16 = 23;

    fn encode(&self, buf: &mut BytesMut, cxt: &EncodeCxt) {
        buf.put_u8(MessageType::Update as u8);

        // Withdrawn Routes.
        let start_pos = buf.len();
        buf.put_u16(0);
        if let Some(unreach) = &self.unreach {
            // Encode prefixes.
            for prefix in &unreach.prefixes {
                let plen = prefix.prefix();
                let prefix_bytes = prefix.ip().octets();
                let plen_wire = prefix_wire_len(plen);
                buf.put_u8(plen);
                buf.put(&prefix_bytes[0..plen_wire]);
            }

            // Rewrite the "Withdrawn Routes Length" field.
            let len = (buf.len() - start_pos - 2) as u16;
            buf[start_pos..start_pos + 2].copy_from_slice(&len.to_be_bytes());
        }

        // Path Attributes.
        let start_pos = buf.len();
        buf.put_u16(0);
        if let Some(attrs) = &self.attrs {
            // Encode path attributes.
            attrs.encode(
                buf,
                &self.reach,
                &self.mp_reach,
                &self.mp_unreach,
                cxt,
            );

            // Rewrite the "Total Path Attribute Length" field.
            let len = (buf.len() - start_pos - 2) as u16;
            buf[start_pos..start_pos + 2].copy_from_slice(&len.to_be_bytes());
        }

        // Network Layer Reachability Information.
        if let Some(reach) = &self.reach {
            // Encode prefixes.
            for prefix in &reach.prefixes {
                encode_ipv4_prefix(buf, prefix);
            }
        }
    }

    pub fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
    ) -> Result<Self, UpdateMessageError> {
        let mut reach = None;
        let mut unreach = None;
        let mut mp_reach = None;
        let mut mp_unreach = None;
        let mut attrs = None;
        let mut nexthop = None;

        // Withdrawn Routes Length.
        let wdraw_len = buf.try_get_u16()?;
        if wdraw_len as usize > buf.remaining() {
            return Err(UpdateMessageError::MalformedAttributeList);
        }

        // Withdrawn Routes.
        let mut buf_wdraw = buf.copy_to_bytes(wdraw_len as usize);
        let mut prefixes = Vec::new();
        while buf_wdraw.remaining() > 0 {
            if let Some(prefix) = decode_ipv4_prefix(&mut buf_wdraw)? {
                prefixes.push(prefix);
            }
        }
        if !prefixes.is_empty() {
            unreach = Some(UnreachNlri { prefixes });
        }

        // Total Path Attribute Length.
        if buf.remaining() < 2 {
            return Err(UpdateMessageError::MalformedAttributeList);
        }
        let attr_len = buf.try_get_u16()?;
        if attr_len as usize > buf.remaining() {
            return Err(UpdateMessageError::MalformedAttributeList);
        }

        // Path Attributes.
        if attr_len != 0 {
            let mut buf_attr = buf.copy_to_bytes(attr_len as usize);
            let nlri_present = buf.remaining() > 0;
            attrs = Attrs::decode(
                &mut buf_attr,
                cxt,
                &mut nexthop,
                nlri_present,
                &mut mp_unreach,
                &mut mp_reach,
            )?;
        }

        // Network Layer Reachability Information.
        //
        // All prefixes are ignored if the NEXT_HOP attribute is missing.
        let mut prefixes = Vec::new();
        while buf.remaining() > 0 {
            if let Some(prefix) = decode_ipv4_prefix(buf)? {
                prefixes.push(prefix);
            }
        }
        if !prefixes.is_empty()
            && let Some(nexthop) = nexthop
        {
            reach = Some(ReachNlri { prefixes, nexthop });
        }

        Ok(UpdateMsg {
            reach,
            unreach,
            mp_reach,
            mp_unreach,
            attrs,
        })
    }
}

// ===== impl NotificationMsg =====

impl NotificationMsg {
    const MIN_LEN: u16 = 21;

    pub(crate) fn new(
        error_code: impl ToPrimitive,
        error_subcode: impl ToPrimitive,
    ) -> Self {
        NotificationMsg {
            error_code: error_code.to_u8().unwrap(),
            error_subcode: error_subcode.to_u8().unwrap(),
            data: Default::default(),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(MessageType::Notification as u8);
        buf.put_u8(self.error_code);
        buf.put_u8(self.error_subcode);
        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let error_code = buf.try_get_u8()?;
        let error_subcode = buf.try_get_u8()?;

        Ok(NotificationMsg {
            error_code,
            error_subcode,
            data: buf.to_vec(),
        })
    }
}

impl From<DecodeError> for NotificationMsg {
    fn from(error: DecodeError) -> NotificationMsg {
        let error_code;
        let error_subcode;
        let data = vec![];

        match error {
            DecodeError::ReadOutOfBounds => {
                error_code = ErrorCode::Cease as u8;
                error_subcode = 0;
            }
            DecodeError::MessageHeader(error) => {
                error_code = ErrorCode::MessageHeaderError as u8;
                error_subcode = match error {
                    MessageHeaderError::ReadOutOfBounds => {
                        MessageHeaderErrorSubcode::Unspecific
                    }
                    MessageHeaderError::ConnectionNotSynchronized => {
                        MessageHeaderErrorSubcode::ConnectionNotSynchronized
                    }
                    MessageHeaderError::BadMessageLength(..) => {
                        MessageHeaderErrorSubcode::BadMessageLength
                    }
                    MessageHeaderError::BadMessageType(..) => {
                        MessageHeaderErrorSubcode::BadMessageType
                    }
                } as u8;
            }
            DecodeError::OpenMessage(error) => {
                error_code = ErrorCode::OpenMessageError as u8;
                error_subcode = match error {
                    OpenMessageError::ReadOutOfBounds => {
                        OpenMessageErrorSubcode::Unspecific
                    }
                    OpenMessageError::UnsupportedVersion(..) => {
                        OpenMessageErrorSubcode::UnsupportedVersionNumber
                    }
                    OpenMessageError::BadPeerAs => {
                        OpenMessageErrorSubcode::BadPeerAs
                    }
                    OpenMessageError::BadBgpIdentifier => {
                        OpenMessageErrorSubcode::BadBgpIdentifier
                    }
                    OpenMessageError::UnsupportedOptParam => {
                        OpenMessageErrorSubcode::UnsupportedOptParam
                    }
                    OpenMessageError::UnacceptableHoldTime => {
                        OpenMessageErrorSubcode::UnacceptableHoldTime
                    }
                    OpenMessageError::UnsupportedCapability => {
                        OpenMessageErrorSubcode::UnsupportedCapability
                    }
                    OpenMessageError::MalformedOptParam => {
                        OpenMessageErrorSubcode::Unspecific
                    }
                } as u8;
            }
            DecodeError::UpdateMessage(error) => {
                error_code = ErrorCode::UpdateMessageError as u8;
                error_subcode = match error {
                    UpdateMessageError::ReadOutOfBounds => {
                        UpdateMessageErrorSubcode::Unspecific
                    }
                    UpdateMessageError::MalformedAttributeList => {
                        UpdateMessageErrorSubcode::MalformedAttributeList
                    }
                    UpdateMessageError::UnrecognizedWellKnownAttribute => {
                        UpdateMessageErrorSubcode::UnrecognizedWellKnownAttribute
                    }
                    UpdateMessageError::OptionalAttributeError => {
                        UpdateMessageErrorSubcode::OptionalAttributeError
                    }
                    UpdateMessageError::InvalidNetworkField => {
                        UpdateMessageErrorSubcode::InvalidNetworkField
                    }
                } as u8;
            }
        }

        // TODO: set notification data.

        NotificationMsg {
            error_code,
            error_subcode,
            data,
        }
    }
}

// ===== impl KeepaliveMsg =====

impl KeepaliveMsg {
    const LEN: u16 = 19;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(MessageType::Keepalive as u8);
    }

    pub fn decode(_buf: &mut Bytes) -> Result<Self, DecodeError> {
        // A KEEPALIVE message consists of only the message header.
        Ok(KeepaliveMsg {})
    }
}

// ===== impl RouteRefreshMsg =====

impl RouteRefreshMsg {
    const LEN: u16 = 23;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(MessageType::RouteRefresh as u8);
        buf.put_u16(self.afi);
        buf.put_u8(0);
        buf.put_u8(self.safi);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let afi = buf.try_get_u16()?;
        let _reserved = buf.try_get_u8()?;
        let safi = buf.try_get_u8()?;
        Ok(RouteRefreshMsg { afi, safi })
    }
}

// ===== helper functions =====

pub(crate) fn encode_ipv4_prefix(buf: &mut BytesMut, prefix: &Ipv4Network) {
    // Encode prefix length.
    let plen = prefix.prefix();
    buf.put_u8(plen);

    // Encode prefix address (variable length).
    let prefix_bytes = prefix.ip().octets();
    let plen_wire = prefix_wire_len(plen);
    buf.put(&prefix_bytes[0..plen_wire]);
}

pub(crate) fn encode_ipv6_prefix(buf: &mut BytesMut, prefix: &Ipv6Network) {
    // Encode prefix length.
    let plen = prefix.prefix();
    buf.put_u8(plen);

    // Encode prefix address (variable length).
    let prefix_bytes = prefix.ip().octets();
    let plen_wire = prefix_wire_len(plen);
    buf.put(&prefix_bytes[0..plen_wire]);
}

pub(crate) fn encode_labeled_vpn_ipv4_prefix(
    buf: &mut BytesMut,
    nlri: &LabeledVpnIpv4Nlri,
) {
    encode_labeled_vpn_prefix(
        buf,
        nlri.label,
        nlri.rd,
        nlri.prefix.prefix(),
        &nlri.prefix.ip().octets(),
    );
}

pub(crate) fn encode_labeled_vpn_ipv6_prefix(
    buf: &mut BytesMut,
    nlri: &LabeledVpnIpv6Nlri,
) {
    encode_labeled_vpn_prefix(
        buf,
        nlri.label,
        nlri.rd,
        nlri.prefix.prefix(),
        &nlri.prefix.ip().octets(),
    );
}

fn encode_labeled_vpn_prefix(
    buf: &mut BytesMut,
    label: u32,
    rd: RouteDistinguisher,
    plen: u8,
    prefix_bytes: &[u8],
) {
    // RFC 8277 label stack entry: 20-bit label, TC=0, BoS=1, TTL absent.
    let label_entry = (label << 4) | 1;
    buf.put_u8(plen + 24 + 64);
    buf.put_u24(label_entry);
    buf.put_slice(&rd.encode());
    let plen_wire = prefix_wire_len(plen);
    buf.put(&prefix_bytes[0..plen_wire]);
}

pub fn decode_ipv4_prefix(
    buf: &mut Bytes,
) -> Result<Option<Ipv4Network>, UpdateMessageError> {
    // Parse prefix length.
    let plen = buf.try_get_u8()?;
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv4Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField);
    }

    // Parse prefix address (variable length).
    let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
    buf.try_copy_to_slice(&mut prefix_bytes[..plen_wire])?;
    let prefix = Ipv4Addr::from(prefix_bytes);
    let prefix = Ipv4Network::new(prefix, plen)
        .map(|prefix| prefix.apply_mask())
        .map_err(|_| UpdateMessageError::InvalidNetworkField)?;

    // Ignore semantically incorrect prefix.
    if !prefix.is_routable() {
        return Ok(None);
    }

    // Normalize prefix.
    let prefix = prefix.apply_mask();

    Ok(Some(prefix))
}

pub fn decode_ipv6_prefix(
    buf: &mut Bytes,
) -> Result<Option<Ipv6Network>, UpdateMessageError> {
    // Parse prefix length.
    let plen = buf.try_get_u8()?;
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv6Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField);
    }

    // Parse prefix address (variable length).
    let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
    buf.try_copy_to_slice(&mut prefix_bytes[..plen_wire])?;
    let prefix = Ipv6Addr::from(prefix_bytes);
    let prefix = Ipv6Network::new(prefix, plen)
        .map(|prefix| prefix.apply_mask())
        .map_err(|_| UpdateMessageError::InvalidNetworkField)?;

    // Ignore semantically incorrect prefix.
    if !prefix.is_routable() {
        return Ok(None);
    }

    // Normalize prefix.
    let prefix = prefix.apply_mask();

    Ok(Some(prefix))
}

pub fn decode_labeled_vpn_ipv4_prefix(
    buf: &mut Bytes,
) -> Result<Option<LabeledVpnIpv4Nlri>, UpdateMessageError> {
    let (label, rd, plen) = decode_labeled_vpn_prefix_header(buf)?;
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv4Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField);
    }

    let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
    buf.try_copy_to_slice(&mut prefix_bytes[..plen_wire])?;
    let prefix = Ipv4Network::new(Ipv4Addr::from(prefix_bytes), plen)
        .map(|prefix| prefix.apply_mask())
        .map_err(|_| UpdateMessageError::InvalidNetworkField)?;
    if !prefix.is_routable() {
        return Ok(None);
    }

    Ok(Some(LabeledVpnIpv4Nlri { label, rd, prefix }))
}

pub fn decode_labeled_vpn_ipv6_prefix(
    buf: &mut Bytes,
) -> Result<Option<LabeledVpnIpv6Nlri>, UpdateMessageError> {
    let (label, rd, plen) = decode_labeled_vpn_prefix_header(buf)?;
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv6Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField);
    }

    let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
    buf.try_copy_to_slice(&mut prefix_bytes[..plen_wire])?;
    let prefix = Ipv6Network::new(Ipv6Addr::from(prefix_bytes), plen)
        .map(|prefix| prefix.apply_mask())
        .map_err(|_| UpdateMessageError::InvalidNetworkField)?;
    if !prefix.is_routable() {
        return Ok(None);
    }

    Ok(Some(LabeledVpnIpv6Nlri { label, rd, prefix }))
}

pub(crate) fn encode_evpn_route(buf: &mut BytesMut, route: &EvpnRoute) {
    match route {
        EvpnRoute::EthernetAutoDiscovery(route) => {
            let len = 8 + 10 + 4 + 3;
            buf.put_u8(1);
            buf.put_u8(len);
            buf.put_slice(&route.rd.encode());
            buf.put_slice(&route.esi);
            buf.put_u32(route.ethernet_tag_id);
            encode_evpn_label(buf, route.label);
        }
        EvpnRoute::EthernetSegment(route) => {
            let len = 8 + 10 + 1 + route.originator_ip.length();
            buf.put_u8(4);
            buf.put_u8(len as u8);
            buf.put_slice(&route.rd.encode());
            buf.put_slice(&route.esi);
            match route.originator_ip {
                IpAddr::V4(addr) => {
                    buf.put_u8(32);
                    buf.put_ipv4(&addr);
                }
                IpAddr::V6(addr) => {
                    buf.put_u8(128);
                    buf.put_ipv6(&addr);
                }
            }
        }
        EvpnRoute::MacIpAdvertisement(route) => {
            let len = 8
                + 10
                + 4
                + 1
                + 6
                + 1
                + route.ip.map(|ip| ip.length()).unwrap_or_default()
                + 3;
            buf.put_u8(2);
            buf.put_u8(len as u8);
            buf.put_slice(&route.rd.encode());
            buf.put_slice(&route.esi);
            buf.put_u32(route.ethernet_tag_id);
            buf.put_u8(48);
            buf.put_slice(&route.mac);
            encode_evpn_ip(buf, route.ip);
            encode_evpn_label(buf, route.label);
        }
        EvpnRoute::InclusiveMulticastEthernetTag(route) => {
            let len = 8 + 4 + route.originator_ip.length();
            buf.put_u8(3);
            buf.put_u8(len as u8);
            buf.put_slice(&route.rd.encode());
            buf.put_u32(route.ethernet_tag_id);
            match route.originator_ip {
                IpAddr::V4(addr) => buf.put_ipv4(&addr),
                IpAddr::V6(addr) => buf.put_ipv6(&addr),
            }
        }
        EvpnRoute::IpPrefix(route) => {
            let prefix_len = route.prefix.prefix();
            let prefix_wire_len = prefix_wire_len(prefix_len);
            let gw_len =
                route.gateway_ip.map(|ip| ip.length()).unwrap_or_default();
            let len = 8 + 10 + 4 + 1 + prefix_wire_len + gw_len + 3;
            buf.put_u8(5);
            buf.put_u8(len as u8);
            buf.put_slice(&route.rd.encode());
            buf.put_slice(&route.esi);
            buf.put_u32(route.ethernet_tag_id);
            buf.put_u8(prefix_len);
            match route.prefix {
                IpNetwork::V4(prefix) => {
                    buf.put(&prefix.ip().octets()[0..prefix_wire_len]);
                }
                IpNetwork::V6(prefix) => {
                    buf.put(&prefix.ip().octets()[0..prefix_wire_len]);
                }
            }
            if let Some(gateway_ip) = route.gateway_ip {
                match gateway_ip {
                    IpAddr::V4(addr) => buf.put_ipv4(&addr),
                    IpAddr::V6(addr) => buf.put_ipv6(&addr),
                }
            }
            encode_evpn_label(buf, route.label);
        }
    }
}

pub(crate) fn decode_evpn_route(
    buf: &mut Bytes,
) -> Result<Option<EvpnRoute>, UpdateMessageError> {
    if buf.remaining() < 2 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let route_type = buf.try_get_u8()?;
    let route_len = buf.try_get_u8()? as usize;
    if route_len > buf.remaining() {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let mut route_buf = buf.copy_to_bytes(route_len);

    match route_type {
        1 => decode_evpn_ethernet_auto_discovery(&mut route_buf)
            .map(|route| route.map(EvpnRoute::EthernetAutoDiscovery)),
        4 => decode_evpn_ethernet_segment(&mut route_buf)
            .map(|route| route.map(EvpnRoute::EthernetSegment)),
        2 => decode_evpn_mac_ip_advertisement(&mut route_buf)
            .map(|route| route.map(EvpnRoute::MacIpAdvertisement)),
        3 => decode_evpn_imet(&mut route_buf)
            .map(|route| route.map(EvpnRoute::InclusiveMulticastEthernetTag)),
        5 => decode_evpn_ip_prefix(&mut route_buf)
            .map(|route| route.map(EvpnRoute::IpPrefix)),
        _ => Ok(None),
    }
}

fn decode_evpn_ethernet_auto_discovery(
    buf: &mut Bytes,
) -> Result<Option<EvpnEthernetAutoDiscovery>, UpdateMessageError> {
    if buf.remaining() != 8 + 10 + 4 + 3 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let rd = decode_rd(buf)?;
    let mut esi = [0; 10];
    buf.try_copy_to_slice(&mut esi)?;
    let ethernet_tag_id = buf.try_get_u32()?;
    let label = decode_evpn_label(buf)?;
    Ok(Some(EvpnEthernetAutoDiscovery {
        rd,
        esi,
        ethernet_tag_id,
        label,
    }))
}

fn decode_evpn_ethernet_segment(
    buf: &mut Bytes,
) -> Result<Option<EvpnEthernetSegment>, UpdateMessageError> {
    if buf.remaining() < 8 + 10 + 1 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let rd = decode_rd(buf)?;
    let mut esi = [0; 10];
    buf.try_copy_to_slice(&mut esi)?;
    let ip_len = buf.try_get_u8()?;
    let originator_ip = match ip_len {
        32 if buf.remaining() == Ipv4Addr::LENGTH => {
            IpAddr::V4(buf.try_get_ipv4()?)
        }
        128 if buf.remaining() == Ipv6Addr::LENGTH => {
            IpAddr::V6(buf.try_get_ipv6()?)
        }
        _ => return Err(UpdateMessageError::InvalidNetworkField),
    };

    Ok(Some(EvpnEthernetSegment {
        rd,
        esi,
        originator_ip,
    }))
}

fn decode_evpn_mac_ip_advertisement(
    buf: &mut Bytes,
) -> Result<Option<EvpnMacIpAdvertisement>, UpdateMessageError> {
    if buf.remaining() < 8 + 10 + 4 + 1 + 6 + 1 + 3 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let rd = decode_rd(buf)?;
    let mut esi = [0; 10];
    buf.try_copy_to_slice(&mut esi)?;
    let ethernet_tag_id = buf.try_get_u32()?;
    let mac_len = buf.try_get_u8()?;
    if mac_len != 48 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let mut mac = [0; 6];
    buf.try_copy_to_slice(&mut mac)?;
    let ip_len = buf.try_get_u8()?;
    let ip = match ip_len {
        0 => None,
        32 => Some(IpAddr::V4(buf.try_get_ipv4()?)),
        128 => Some(IpAddr::V6(buf.try_get_ipv6()?)),
        _ => return Err(UpdateMessageError::InvalidNetworkField),
    };
    if buf.remaining() != 3 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let label = decode_evpn_label(buf)?;
    Ok(Some(EvpnMacIpAdvertisement {
        rd,
        esi,
        ethernet_tag_id,
        mac,
        ip,
        label,
    }))
}

fn decode_evpn_imet(
    buf: &mut Bytes,
) -> Result<Option<EvpnInclusiveMulticastEthernetTag>, UpdateMessageError> {
    if buf.remaining() != 8 + 4 + Ipv4Addr::LENGTH
        && buf.remaining() != 8 + 4 + Ipv6Addr::LENGTH
    {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let rd = decode_rd(buf)?;
    let ethernet_tag_id = buf.try_get_u32()?;
    let originator_ip = match buf.remaining() {
        Ipv4Addr::LENGTH => IpAddr::V4(buf.try_get_ipv4()?),
        Ipv6Addr::LENGTH => IpAddr::V6(buf.try_get_ipv6()?),
        _ => unreachable!(),
    };
    Ok(Some(EvpnInclusiveMulticastEthernetTag {
        rd,
        ethernet_tag_id,
        originator_ip,
    }))
}

fn decode_evpn_ip_prefix(
    buf: &mut Bytes,
) -> Result<Option<EvpnIpPrefix>, UpdateMessageError> {
    if buf.remaining() < 8 + 10 + 4 + 1 + 3 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let rd = decode_rd(buf)?;
    let mut esi = [0; 10];
    buf.try_copy_to_slice(&mut esi)?;
    let ethernet_tag_id = buf.try_get_u32()?;
    let prefix_len = buf.try_get_u8()?;
    let prefix_wire_len = prefix_wire_len(prefix_len);
    let suffix_len = buf
        .remaining()
        .checked_sub(3)
        .ok_or(UpdateMessageError::InvalidNetworkField)?;
    let (prefix, gateway_ip) = match suffix_len.checked_sub(prefix_wire_len) {
        Some(0) => (decode_evpn_ip_prefix_addr(buf, prefix_len, false)?, None),
        Some(Ipv4Addr::LENGTH) => {
            let prefix = decode_evpn_ip_prefix_addr(buf, prefix_len, false)?;
            (prefix, Some(IpAddr::V4(buf.try_get_ipv4()?)))
        }
        Some(Ipv6Addr::LENGTH) => {
            let prefix = decode_evpn_ip_prefix_addr(buf, prefix_len, true)?;
            (prefix, Some(IpAddr::V6(buf.try_get_ipv6()?)))
        }
        _ => return Err(UpdateMessageError::InvalidNetworkField),
    };
    let label = decode_evpn_label(buf)?;
    Ok(Some(EvpnIpPrefix {
        rd,
        esi,
        ethernet_tag_id,
        prefix,
        gateway_ip,
        label,
    }))
}

fn decode_evpn_ip_prefix_addr(
    buf: &mut Bytes,
    prefix_len: u8,
    ipv6: bool,
) -> Result<IpNetwork, UpdateMessageError> {
    let prefix_wire_len = prefix_wire_len(prefix_len);
    if ipv6 || prefix_len > Ipv4Network::MAX_PREFIXLEN {
        if prefix_len > Ipv6Network::MAX_PREFIXLEN {
            return Err(UpdateMessageError::InvalidNetworkField);
        }
        let mut bytes = [0; Ipv6Addr::LENGTH];
        buf.try_copy_to_slice(&mut bytes[..prefix_wire_len])?;
        return Ipv6Network::new(Ipv6Addr::from(bytes), prefix_len)
            .map(|prefix| prefix.apply_mask().into())
            .map_err(|_| UpdateMessageError::InvalidNetworkField);
    }

    let mut bytes = [0; Ipv4Addr::LENGTH];
    buf.try_copy_to_slice(&mut bytes[..prefix_wire_len])?;
    Ipv4Network::new(Ipv4Addr::from(bytes), prefix_len)
        .map(|prefix| prefix.apply_mask().into())
        .map_err(|_| UpdateMessageError::InvalidNetworkField)
}

fn encode_evpn_ip(buf: &mut BytesMut, ip: Option<IpAddr>) {
    match ip {
        Some(IpAddr::V4(addr)) => {
            buf.put_u8(32);
            buf.put_ipv4(&addr);
        }
        Some(IpAddr::V6(addr)) => {
            buf.put_u8(128);
            buf.put_ipv6(&addr);
        }
        None => buf.put_u8(0),
    }
}

fn encode_evpn_label(buf: &mut BytesMut, label: u32) {
    let label_entry = (label << 4) | 1;
    buf.put_u24(label_entry);
}

fn decode_evpn_label(buf: &mut Bytes) -> Result<u32, UpdateMessageError> {
    let label_entry = buf.try_get_u24()?;
    if label_entry & 1 == 0 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    Ok(label_entry >> 4)
}

fn decode_rd(
    buf: &mut Bytes,
) -> Result<RouteDistinguisher, UpdateMessageError> {
    let mut rd_bytes = [0; 8];
    buf.try_copy_to_slice(&mut rd_bytes)?;
    RouteDistinguisher::decode(rd_bytes)
        .ok_or(UpdateMessageError::InvalidNetworkField)
}

fn decode_labeled_vpn_prefix_header(
    buf: &mut Bytes,
) -> Result<(u32, RouteDistinguisher, u8), UpdateMessageError> {
    let plen = buf.try_get_u8()?;
    if plen < 24 + 64 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let plen = plen - 24 - 64;
    if 3 + 8 > buf.remaining() {
        return Err(UpdateMessageError::InvalidNetworkField);
    }

    let label_entry = buf.try_get_u24()?;
    if label_entry & 1 == 0 {
        return Err(UpdateMessageError::InvalidNetworkField);
    }
    let label = label_entry >> 4;

    let mut rd_bytes = [0; 8];
    buf.try_copy_to_slice(&mut rd_bytes)?;
    let Some(rd) = RouteDistinguisher::decode(rd_bytes) else {
        return Err(UpdateMessageError::InvalidNetworkField);
    };

    Ok((label, rd, plen))
}

// Calculates the number of bytes required to encode a prefix.
fn prefix_wire_len(len: u8) -> usize {
    (len as usize).div_ceil(8)
}
