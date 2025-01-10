//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::DecodeCxt;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::messages::{
    AddressMsg, CapabilityMsg, HelloMsg, InitMsg, KeepaliveMsg, LabelMsg,
    NotifMsg,
};
use crate::packet::pdu::PduDecodeInfo;
use crate::packet::tlv::{self, TlvDecodeInfo};

//
// LDP message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |U|   Message Type              |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                     Mandatory Parameters                      |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                     Optional Parameters                       |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Message {
    Notification(NotifMsg),
    Hello(HelloMsg),
    Initialization(InitMsg),
    Keepalive(KeepaliveMsg),
    Address(AddressMsg),
    Label(LabelMsg),
    Capability(CapabilityMsg),
}

// LDP message types.
//
// IANA registry:
// https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#ldp-namespaces-2
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MessageType {
    Notification = 0x0001,
    Hello = 0x0100,
    Initialization = 0x0200,
    Keepalive = 0x0201,
    Address = 0x0300,
    AddressWithdraw = 0x0301,
    LabelMapping = 0x0400,
    LabelRequest = 0x0401,
    LabelWithdraw = 0x0402,
    LabelRelease = 0x0403,
    LabelAbortReq = 0x0404,
    // RFC 5561
    Capability = 0x0202,
}

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AddressMessageType {
    Address = 0x0300,
    AddressWithdraw = 0x0301,
}

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LabelMessageType {
    LabelMapping = 0x0400,
    LabelRequest = 0x0401,
    LabelWithdraw = 0x0402,
    LabelRelease = 0x0403,
    LabelAbortReq = 0x0404,
}

//
// Message decode information.
//
// Used as a control block during the decode process, and used to return
// detailed error information.
//
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageDecodeInfo {
    pub msg_raw: Bytes,
    pub msg_type: u16,
    pub msg_etype: Option<MessageType>,
    pub msg_len: u16,
    pub msg_rlen: u16,
    pub msg_id: u32,
}

pub trait MessageKind: std::fmt::Debug {
    const U_BIT: bool;

    fn msg_id(&self) -> u32;

    fn msg_type(&self) -> MessageType;

    fn encode_hdr(&self, buf: &mut BytesMut) {
        let mut msg_type = self.msg_type() as u16;
        if Self::U_BIT {
            msg_type |= Message::UNKNOWN_FLAG;
        }

        buf.put_u16(msg_type);
        // The message length will be rewritten later.
        buf.put_u16(0);
        buf.put_u32(self.msg_id());
    }

    fn encode_body(&self, buf: &mut BytesMut);

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message>;

    fn decode_opt_tlv(
        &mut self,
        _buf: &mut Bytes,
        _cxt: &DecodeCxt,
        _tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<bool> {
        Ok(true)
    }

    fn decode_opt_tlvs(
        &mut self,
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<()> {
        while msgi.msg_rlen >= tlv::TLV_HDR_SIZE {
            let tlvi = tlv::decode_tlv_hdr(buf, msgi)?;

            // Decode TLV.
            let unknown = match tlvi.tlv_etype {
                Some(_) => self.decode_opt_tlv(buf, cxt, &tlvi)?,
                None => true,
            };

            // Unknown TLV type.
            if unknown {
                // Ignore TLV is the u-bit is set, otherwise return an error.
                if tlvi.tlv_type & tlv::TLV_UNKNOWN_FLAG != 0 {
                    buf.advance(tlvi.tlv_len as usize);
                } else {
                    return Err(DecodeError::UnknownTlv(
                        msgi.clone(),
                        tlvi.tlv_type,
                        tlvi.tlv_raw,
                    ));
                }
            }
        }

        Ok(())
    }
}

// ===== impl Message =====

impl Message {
    pub const HDR_SIZE: u16 = 8;
    pub const HDR_MIN_LEN: u16 = 4;
    pub const HDR_DEAD_LEN: u16 = 4;
    pub const UNKNOWN_FLAG: u16 = 0x8000;
    pub const TYPE_MASK: u16 = 0x7FFF;

    pub(crate) fn msg_id(&self) -> u32 {
        match self {
            Message::Notification(msg) => msg.msg_id(),
            Message::Hello(msg) => msg.msg_id(),
            Message::Initialization(msg) => msg.msg_id(),
            Message::Keepalive(msg) => msg.msg_id(),
            Message::Address(msg) => msg.msg_id(),
            Message::Label(msg) => msg.msg_id(),
            Message::Capability(msg) => msg.msg_id(),
        }
    }

    pub(crate) fn msg_type(&self) -> MessageType {
        match self {
            Message::Notification(msg) => msg.msg_type(),
            Message::Hello(msg) => msg.msg_type(),
            Message::Initialization(msg) => msg.msg_type(),
            Message::Keepalive(msg) => msg.msg_type(),
            Message::Address(msg) => msg.msg_type(),
            Message::Label(msg) => msg.msg_type(),
            Message::Capability(msg) => msg.msg_type(),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let start_pos = buf.len();

        self.encode_hdr(buf);
        self.encode_body(buf);

        // Rewrite message length.
        let msg_len = (buf.len() - start_pos) as u16 - Message::HDR_DEAD_LEN;
        buf[start_pos + 2..start_pos + 4]
            .copy_from_slice(&msg_len.to_be_bytes());
    }

    fn encode_hdr(&self, buf: &mut BytesMut) {
        match self {
            Message::Notification(msg) => msg.encode_hdr(buf),
            Message::Hello(msg) => msg.encode_hdr(buf),
            Message::Initialization(msg) => msg.encode_hdr(buf),
            Message::Keepalive(msg) => msg.encode_hdr(buf),
            Message::Address(msg) => msg.encode_hdr(buf),
            Message::Label(msg) => msg.encode_hdr(buf),
            Message::Capability(msg) => msg.encode_hdr(buf),
        }
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        match self {
            Message::Notification(msg) => msg.encode_body(buf),
            Message::Hello(msg) => msg.encode_body(buf),
            Message::Initialization(msg) => msg.encode_body(buf),
            Message::Keepalive(msg) => msg.encode_body(buf),
            Message::Address(msg) => msg.encode_body(buf),
            Message::Label(msg) => msg.encode_body(buf),
            Message::Capability(msg) => msg.encode_body(buf),
        }
    }

    pub fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        pdui: &mut PduDecodeInfo,
    ) -> DecodeResult<Option<Self>> {
        // Parse message header.
        let msgi = Message::decode_hdr(buf, cxt, pdui)?;

        // Parse message body.
        match msgi.msg_etype {
            Some(_) => {
                let msg = Message::decode_known_message(buf, cxt, msgi)?;
                Ok(Some(msg))
            }
            None => {
                Message::decode_unknown_message(buf, msgi)?;
                Ok(None)
            }
        }
    }

    fn decode_hdr(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        pdui: &mut PduDecodeInfo,
    ) -> DecodeResult<MessageDecodeInfo> {
        let buf_copy = buf.clone();

        // Parse message type.
        let msg_type = buf.get_u16();
        let msg_etype = MessageType::decode(msg_type);

        // Parse and validate message length.
        let msg_len = buf.get_u16();
        let msg_size = msg_len + Message::HDR_DEAD_LEN;
        if msg_len < Message::HDR_MIN_LEN || msg_size > pdui.pdu_rlen {
            return Err(DecodeError::InvalidMessageLength(msg_len));
        }

        // Parse message ID.
        let msg_id = buf.get_u32();

        // Save slice containing the entire message.
        let msg_raw = buf_copy.slice(0..msg_size as usize);

        // Calculate remaining bytes in the message header.
        let msg_rlen = msg_len - Message::HDR_MIN_LEN;

        // Update number of remaining bytes in the PDU.
        pdui.pdu_rlen -= msg_size;

        // Call custom validation closure.
        if let Some(validate_msg_hdr) = &cxt.validate_msg_hdr {
            (validate_msg_hdr)(msg_type, msg_id)?;
        }

        Ok(MessageDecodeInfo {
            msg_raw,
            msg_type,
            msg_etype,
            msg_len,
            msg_rlen,
            msg_id,
        })
    }

    fn decode_known_message(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        mut msgi: MessageDecodeInfo,
    ) -> DecodeResult<Self> {
        let msg = match &mut msgi.msg_etype.unwrap() {
            MessageType::Notification => {
                NotifMsg::decode_body(buf, cxt, &mut msgi)?
            }
            MessageType::Hello => HelloMsg::decode_body(buf, cxt, &mut msgi)?,
            MessageType::Initialization => {
                InitMsg::decode_body(buf, cxt, &mut msgi)?
            }
            MessageType::Keepalive => {
                KeepaliveMsg::decode_body(buf, cxt, &mut msgi)?
            }
            MessageType::Address | MessageType::AddressWithdraw => {
                AddressMsg::decode_body(buf, cxt, &mut msgi)?
            }
            MessageType::LabelMapping
            | MessageType::LabelRequest
            | MessageType::LabelWithdraw
            | MessageType::LabelRelease
            | MessageType::LabelAbortReq => {
                LabelMsg::decode_body(buf, cxt, &mut msgi)?
            }
            MessageType::Capability => {
                CapabilityMsg::decode_body(buf, cxt, &mut msgi)?
            }
        };

        // Check for trailing data.
        if msgi.msg_rlen != 0 {
            return Err(DecodeError::InvalidMessageLength(msgi.msg_len));
        }

        Ok(msg)
    }

    fn decode_unknown_message(
        buf: &mut Bytes,
        msgi: MessageDecodeInfo,
    ) -> DecodeResult<()> {
        // Ignore message if the u-bit is set, otherwise return an error.
        if msgi.msg_type & Message::UNKNOWN_FLAG == 0 {
            let msg_type = msgi.msg_type;
            return Err(DecodeError::UnknownMessage(msgi, msg_type));
        }

        buf.advance(msgi.msg_len as usize);
        Ok(())
    }
}

//
// Type conversion functions.
//

impl From<NotifMsg> for Message {
    fn from(msg: NotifMsg) -> Message {
        Message::Notification(msg)
    }
}

impl From<NotifMsg> for Option<Message> {
    fn from(msg: NotifMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<HelloMsg> for Message {
    fn from(msg: HelloMsg) -> Message {
        Message::Hello(msg)
    }
}

impl From<HelloMsg> for Option<Message> {
    fn from(msg: HelloMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<InitMsg> for Message {
    fn from(msg: InitMsg) -> Message {
        Message::Initialization(msg)
    }
}

impl From<InitMsg> for Option<Message> {
    fn from(msg: InitMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<KeepaliveMsg> for Message {
    fn from(msg: KeepaliveMsg) -> Message {
        Message::Keepalive(msg)
    }
}

impl From<KeepaliveMsg> for Option<Message> {
    fn from(msg: KeepaliveMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<AddressMsg> for Message {
    fn from(msg: AddressMsg) -> Message {
        Message::Address(msg)
    }
}

impl From<AddressMsg> for Option<Message> {
    fn from(msg: AddressMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<LabelMsg> for Message {
    fn from(msg: LabelMsg) -> Message {
        Message::Label(msg)
    }
}

impl From<LabelMsg> for Option<Message> {
    fn from(msg: LabelMsg) -> Option<Message> {
        Some(msg.into())
    }
}

impl From<CapabilityMsg> for Message {
    fn from(msg: CapabilityMsg) -> Message {
        Message::Capability(msg)
    }
}

impl From<CapabilityMsg> for Option<Message> {
    fn from(msg: CapabilityMsg) -> Option<Message> {
        Some(msg.into())
    }
}

// ===== impl MessageType =====

impl MessageType {
    pub(crate) fn decode(value: u16) -> Option<Self> {
        MessageType::from_u16(value & Message::TYPE_MASK)
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Notification => write!(f, "Notification"),
            MessageType::Hello => write!(f, "Hello"),
            MessageType::Initialization => write!(f, "Initialization"),
            MessageType::Keepalive => write!(f, "KeepAlive"),
            MessageType::Address => write!(f, "Address"),
            MessageType::AddressWithdraw => write!(f, "Address Withdraw"),
            MessageType::LabelMapping => write!(f, "Label Mapping"),
            MessageType::LabelRequest => write!(f, "Label Request"),
            MessageType::LabelWithdraw => write!(f, "Label Withdraw"),
            MessageType::LabelRelease => write!(f, "Label Release"),
            MessageType::LabelAbortReq => write!(f, "Label Abort Request"),
            MessageType::Capability => write!(f, "Capability"),
        }
    }
}

impl From<AddressMessageType> for MessageType {
    fn from(msg_type: AddressMessageType) -> MessageType {
        match msg_type {
            AddressMessageType::Address => MessageType::Address,
            AddressMessageType::AddressWithdraw => MessageType::AddressWithdraw,
        }
    }
}

impl From<LabelMessageType> for MessageType {
    fn from(msg_type: LabelMessageType) -> MessageType {
        match msg_type {
            LabelMessageType::LabelMapping => MessageType::LabelMapping,
            LabelMessageType::LabelRequest => MessageType::LabelRequest,
            LabelMessageType::LabelWithdraw => MessageType::LabelWithdraw,
            LabelMessageType::LabelRelease => MessageType::LabelRelease,
            LabelMessageType::LabelAbortReq => MessageType::LabelAbortReq,
        }
    }
}
