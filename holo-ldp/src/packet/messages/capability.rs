//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::tlv::{TlvDecodeInfo, TlvKind, TlvType};
use crate::packet::DecodeCxt;

//
// Capability Message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|    Capability (0x0202)      |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     TLV_1                                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     . . .                                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     TLV_N                                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityMsg {
    pub msg_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub twcard_fec: Option<TlvCapTwcardFec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrec_notif: Option<TlvCapUnrecNotif>,
}

//
// Capability Parameter TLV (generic form).
//
// Encoding format:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |U|F| TLV Code Point            |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S| Reserved    |                                               |
// +-+-+-+-+-+-+-+-+       Capability Data                         |
// |                                               +-+-+-+-+-+-+-+-+
// |                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
pub const TLV_CAP_S_BIT: u8 = 0x80;

//
// Dynamic Capability Announcement TLV.
//
// RFC 5561 - Section 9:
//  "The Dynamic Capability Announcement Parameter MAY be included by an
//  LDP speaker in an Initialization message to signal its peer that the
//  speaker is capable of processing Capability messages.
//
//  An LDP speaker MUST NOT include the Dynamic Capability Announcement
//  Parameter in Capability messages sent to its peers".
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1|0| DynCap Ann. (0x0506)      |            Length (1)         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1| Reserved    |
// +-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvCapDynamic();

//
// Typed Wildcard FEC Capability TLV.
//
// Encoding format:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1|0|Typed WCard FEC Cap(0x050B)|            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S| Reserved    |
// +-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvCapTwcardFec(pub bool);

//
// Unrecognized Notification Capability.
//
// Encoding format:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1|0| Unrecognized Noti (0x0603)|            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S| Reserved    |
// +-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvCapUnrecNotif(pub bool);

// ===== impl CapabilityMsg =====

impl MessageKind for CapabilityMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        MessageType::Capability
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode optional TLV(s).
        if let Some(tlv) = &self.twcard_fec {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.unrec_notif {
            tlv.encode(self.msg_type(), buf);
        }
    }

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message> {
        // Create new message.
        let mut msg = CapabilityMsg {
            msg_id: msgi.msg_id,
            ..Default::default()
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Capability(msg))
    }

    fn decode_opt_tlv(
        &mut self,
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<bool> {
        //
        // RFC 5561 - Section 3:
        // "An LDP speaker MUST NOT include more than one instance of a
        // Capability Parameter (as identified by the same TLV code point) in an
        // Initialization or Capability message.  If an LDP speaker receives
        // more than one instance of the same Capability Parameter type in a
        // message, it SHOULD send a Notification message to the peer before
        // terminating the session with the peer.  The Status Code in the Status
        // TLV of the Notification message MUST be Malformed TLV value, and the
        // message SHOULD contain the second Capability Parameter TLV of the
        // same type (code point) that is received in the message".
        //
        match tlvi.tlv_etype.unwrap() {
            TlvType::CapTwcardFec => {
                if self.twcard_fec.is_some() {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }
                self.twcard_fec =
                    Some(TlvCapTwcardFec::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::CapUnrecNotif => {
                if self.unrec_notif.is_some() {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }
                self.unrec_notif =
                    Some(TlvCapUnrecNotif::decode_value(buf, cxt, tlvi)?);
            }
            _ => {
                return Ok(true);
            }
        };

        Ok(false)
    }
}

// ===== impl TlvCapDynamic =====

impl TlvKind for TlvCapDynamic {
    const TLV_TYPE: TlvType = TlvType::CapDynamic;
    const U_BIT: bool = true;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        //
        // RFC 5561 - Section 9:
        // "Once enabled during session initialization, the Dynamic Capability
        // Announcement capability cannot be disabled. This implies that the
        // S-bit is always 1 for the Dynamic Capability Announcement".
        //
        buf.put_u8(TLV_CAP_S_BIT);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 1 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let flags = buf.get_u8();
        if flags & TLV_CAP_S_BIT == 0 {
            return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
        }

        Ok(Self())
    }
}

// ===== impl TlvCapTwcardFec =====

impl TlvKind for TlvCapTwcardFec {
    const TLV_TYPE: TlvType = TlvType::CapTwcardFec;
    const U_BIT: bool = true;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        let mut flags = 0;
        if self.0 {
            flags |= TLV_CAP_S_BIT;
        }

        buf.put_u8(flags);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 1 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let flags = buf.get_u8();
        let s_bit = flags & TLV_CAP_S_BIT != 0;

        Ok(Self(s_bit))
    }
}

// ===== impl TlvCapUnrecNotif =====

impl TlvKind for TlvCapUnrecNotif {
    const TLV_TYPE: TlvType = TlvType::CapUnrecNotif;
    const U_BIT: bool = true;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        let mut flags = 0;
        if self.0 {
            flags |= TLV_CAP_S_BIT;
        }

        buf.put_u8(flags);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 1 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let flags = buf.get_u8();
        let s_bit = flags & TLV_CAP_S_BIT != 0;

        Ok(Self(s_bit))
    }
}
