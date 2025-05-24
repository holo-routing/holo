//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_as_inner::EnumAsInner;
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use holo_utils::ip::{
    Ipv4AddrExt, Ipv4NetworkExt, Ipv6AddrExt, Ipv6NetworkExt,
};
use ipnetwork::{Ipv4Network, Ipv6Network};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::neighbor::PeerType;
use crate::packet::attribute::Attrs;
use crate::packet::consts::{
    AddPathMode, Afi, BGP_VERSION, CapabilityCode, ErrorCode,
    MessageHeaderErrorSubcode, MessageType, OpenMessageErrorSubcode,
    OpenParamType, Safi, UpdateMessageErrorSubcode,
};
use crate::packet::error::{
    DecodeError, DecodeResult, MessageHeaderError, OpenMessageError,
    UpdateMessageError,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MpUnreachNlri {
    Ipv4Unicast { prefixes: Vec<Ipv4Network> },
    Ipv6Unicast { prefixes: Vec<Ipv6Network> },
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
    //
    // This function panics if the provided buffer doesn't contain an entire
    // message.
    pub fn decode(data: &[u8], cxt: &DecodeCxt) -> DecodeResult<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        // Parse and validate marker.
        let marker = buf.get_u128();
        if marker != u128::MAX {
            return Err(MessageHeaderError::ConnectionNotSynchronized.into());
        }

        // Parse and validate message length.
        let msg_len = buf.get_u16();
        if msg_len < Self::MIN_LEN || msg_len > Self::MAX_LEN {
            return Err(MessageHeaderError::BadMessageLength(msg_len).into());
        }

        // Parse message type.
        let msg_type = buf.get_u8();
        let Some(msg_etype) = MessageType::from_u8(msg_type) else {
            return Err(MessageHeaderError::BadMessageType(msg_type).into());
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
            return Err(MessageHeaderError::BadMessageLength(msg_len).into());
        }
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

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // Parse and validate BGP version.
        let version = buf.get_u8();
        if version != BGP_VERSION {
            return Err(
                OpenMessageError::UnsupportedVersion(BGP_VERSION).into()
            );
        }

        // Parse and validate ASN.
        let my_as = buf.get_u16();
        if my_as == 0 {
            return Err(OpenMessageError::BadPeerAs.into());
        }

        // Parse and validate hold time.
        let holdtime = buf.get_u16();
        if holdtime == 1 || holdtime == 2 {
            return Err(OpenMessageError::UnacceptableHoldTime.into());
        }

        // Parse and validate BGP identifier.
        let identifier = buf.get_ipv4();
        if identifier.is_unspecified()
            || identifier.is_multicast()
            || identifier.is_broadcast()
        {
            return Err(OpenMessageError::BadBgpIdentifier.into());
        }

        // Parse and validate optional parameters.
        let mut capabilities = BTreeSet::new();
        let opt_param_len = buf.get_u8();
        if opt_param_len as usize > buf.remaining() {
            return Err(OpenMessageError::MalformedOptParam.into());
        }
        let mut buf_opts = buf.copy_to_bytes(opt_param_len as usize);
        while buf_opts.remaining() > 0 {
            if buf_opts.remaining() < 2 {
                return Err(OpenMessageError::MalformedOptParam.into());
            }
            let param_type = buf_opts.get_u8();
            let param_len = buf_opts.get_u8();
            if param_len as usize > buf_opts.remaining() {
                return Err(OpenMessageError::MalformedOptParam.into());
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
                    return Err(OpenMessageError::UnsupportedOptParam.into());
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

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Option<Self>> {
        if buf.remaining() < 2 {
            return Err(OpenMessageError::MalformedOptParam.into());
        }
        let cap_type = buf.get_u8();
        let cap_len = buf.get_u8();
        if cap_len as usize > buf.remaining() {
            return Err(OpenMessageError::MalformedOptParam.into());
        }

        let mut buf_cap = buf.copy_to_bytes(cap_len as usize);
        let cap = match CapabilityCode::from_u8(cap_type) {
            Some(CapabilityCode::MultiProtocol) => {
                if cap_len != 4 {
                    return Err(OpenMessageError::MalformedOptParam.into());
                }

                let afi = buf_cap.get_u16();
                let Some(afi) = Afi::from_u16(afi) else {
                    // Ignore unknown AFI.
                    return Ok(None);
                };
                let _reserved = buf_cap.get_u8();
                let safi = buf_cap.get_u8();
                let Some(safi) = Safi::from_u8(safi) else {
                    // Ignore unknown SAFI.
                    return Ok(None);
                };

                Capability::MultiProtocol { afi, safi }
            }
            Some(CapabilityCode::FourOctetAsNumber) => {
                if cap_len != 4 {
                    return Err(OpenMessageError::MalformedOptParam.into());
                }

                let asn = buf_cap.get_u32();
                Capability::FourOctetAsNumber { asn }
            }
            Some(CapabilityCode::AddPath) => {
                if cap_len % 4 != 0 {
                    return Err(OpenMessageError::MalformedOptParam.into());
                }

                let mut tuples = BTreeSet::new();
                while buf_cap.remaining() > 0 {
                    let afi = buf_cap.get_u16();
                    let Some(afi) = Afi::from_u16(afi) else {
                        // Ignore unknown AFI.
                        return Ok(None);
                    };
                    let safi = buf_cap.get_u8();
                    let Some(safi) = Safi::from_u8(safi) else {
                        // Ignore unknown SAFI.
                        return Ok(None);
                    };
                    let mode = buf_cap.get_u8();
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
                    return Err(OpenMessageError::MalformedOptParam.into());
                }

                Capability::RouteRefresh
            }
            Some(CapabilityCode::EnhancedRouteRefresh) => {
                if cap_len != 0 {
                    return Err(OpenMessageError::MalformedOptParam.into());
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

    pub fn decode(buf: &mut Bytes, cxt: &DecodeCxt) -> DecodeResult<Self> {
        let mut reach = None;
        let mut unreach = None;
        let mut mp_reach = None;
        let mut mp_unreach = None;
        let mut attrs = None;
        let mut nexthop = None;

        // Withdrawn Routes Length.
        let wdraw_len = buf.get_u16();
        if wdraw_len as usize > buf.remaining() {
            return Err(UpdateMessageError::MalformedAttributeList.into());
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
            return Err(UpdateMessageError::MalformedAttributeList.into());
        }
        let attr_len = buf.get_u16();
        if attr_len as usize > buf.remaining() {
            return Err(UpdateMessageError::MalformedAttributeList.into());
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

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let error_code = buf.get_u8();
        let error_subcode = buf.get_u8();

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
            DecodeError::MessageHeader(error) => {
                error_code = ErrorCode::MessageHeaderError as u8;
                error_subcode = match error {
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

    pub fn decode(_buf: &mut Bytes) -> DecodeResult<Self> {
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

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let afi = buf.get_u16();
        let _reserved = buf.get_u8();
        let safi = buf.get_u8();
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

pub fn decode_ipv4_prefix(
    buf: &mut Bytes,
) -> DecodeResult<Option<Ipv4Network>> {
    // Parse prefix length.
    let plen = buf.get_u8();
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv4Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField.into());
    }

    // Parse prefix address (variable length).
    let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
    buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
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
) -> DecodeResult<Option<Ipv6Network>> {
    // Parse prefix length.
    let plen = buf.get_u8();
    let plen_wire = prefix_wire_len(plen);
    if plen_wire > buf.remaining() || plen > Ipv6Network::MAX_PREFIXLEN {
        return Err(UpdateMessageError::InvalidNetworkField.into());
    }

    // Parse prefix address (variable length).
    let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
    buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
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

// Calculates the number of bytes required to encode a prefix.
fn prefix_wire_len(len: u8) -> usize {
    (len as usize).div_ceil(8)
}
