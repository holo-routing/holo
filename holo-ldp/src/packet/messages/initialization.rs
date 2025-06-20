//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::packet::DecodeCxt;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::messages::capability::{
    TlvCapDynamic, TlvCapTwcardFec, TlvCapUnrecNotif,
};
use crate::packet::pdu::Pdu;
use crate::packet::tlv::{self, TlvDecodeInfo, TlvKind, TlvType};

//
// Initialization Message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Initialization (0x0200)   |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Common Session Parameters TLV             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct InitMsg {
    pub msg_id: u32,
    pub params: TlvCommonSessParams,
    pub cap_dynamic: Option<TlvCapDynamic>,
    pub cap_twcard_fec: Option<TlvCapTwcardFec>,
    pub cap_unrec_notif: Option<TlvCapUnrecNotif>,
}

//
// Common Session Parameters TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|0| Common Sess Parms (0x0500)|      Length                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Protocol Version              |      KeepAlive Time           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |A|D|  Reserved |     PVLim     |      Max PDU Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Receiver LDP Identifier                       |
// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |
// -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvCommonSessParams {
    pub version: u16,
    pub keepalive_time: u16,
    pub flags: InitFlags,
    pub pvlim: u8,
    pub max_pdu_len: u16,
    pub lsr_id: Ipv4Addr,
    pub lspace_id: u16,
}

// Common Session Parameters TLV flags.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct InitFlags: u8 {
        const ADV_DISCIPLINE = 0x80;
        const LOOP_DETECTION = 0x40;
    }
}

// ===== impl InitMsg =====

impl MessageKind for InitMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        MessageType::Initialization
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode mandatory TLV(s).
        self.params.encode(self.msg_type(), buf);

        // Encode optional TLV(s).
        if let Some(tlv) = &self.cap_dynamic {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.cap_twcard_fec {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.cap_unrec_notif {
            tlv.encode(self.msg_type(), buf);
        }
    }

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message> {
        // Decode mandatory TLV(s).
        let tlvi = tlv::decode_tlv_hdr(buf, msgi)?;
        if tlvi.tlv_type != TlvType::CommonSessParams as u16 {
            return Err(DecodeError::MissingMsgParams(
                msgi.clone(),
                TlvType::CommonSessParams,
            ));
        }
        let params = TlvCommonSessParams::decode_value(buf, cxt, &tlvi)?;

        // Create new message.
        let mut msg = Self {
            msg_id: msgi.msg_id,
            params,
            ..Default::default()
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Initialization(msg))
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
            // ATM and Frame-Relay aren't supported.
            TlvType::AtmSessParams | TlvType::FrSessParams => {
                return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
            }
            TlvType::CapDynamic => {
                if self.cap_dynamic.is_some() {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }
                self.cap_dynamic =
                    Some(TlvCapDynamic::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::CapTwcardFec => {
                if self.cap_twcard_fec.is_some() {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }
                self.cap_twcard_fec =
                    Some(TlvCapTwcardFec::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::CapUnrecNotif => {
                if self.cap_unrec_notif.is_some() {
                    return Err(DecodeError::InvalidTlvValue(tlvi.clone()));
                }
                self.cap_unrec_notif =
                    Some(TlvCapUnrecNotif::decode_value(buf, cxt, tlvi)?);
            }
            _ => {
                return Ok(true);
            }
        };

        Ok(false)
    }
}

// ===== impl TlvCommonSessParams =====

impl TlvKind for TlvCommonSessParams {
    const TLV_TYPE: TlvType = TlvType::CommonSessParams;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.version);
        buf.put_u16(self.keepalive_time);
        buf.put_u8(self.flags.bits());
        buf.put_u8(self.pvlim);
        buf.put_u16(self.max_pdu_len);
        buf.put_ipv4(&self.lsr_id);
        buf.put_u16(self.lspace_id);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 14 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let version = buf.try_get_u16()?;
        if version != Pdu::VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        let keepalive_time = buf.try_get_u16()?;
        if keepalive_time == 0 {
            return Err(DecodeError::BadKeepaliveTime(
                tlvi.clone(),
                keepalive_time,
            ));
        }

        // Ignore unknown flags.
        let flags = InitFlags::from_bits_truncate(buf.try_get_u8()?);

        let pvlim = buf.try_get_u8()?;
        let max_pdu_len = buf.try_get_u16()?;
        let lsr_id = buf.try_get_ipv4()?;
        let lspace_id = buf.try_get_u16()?;

        Ok(Self {
            version,
            keepalive_time,
            flags,
            pvlim,
            max_pdu_len,
            lsr_id,
            lspace_id,
        })
    }
}

impl Default for TlvCommonSessParams {
    fn default() -> TlvCommonSessParams {
        TlvCommonSessParams {
            version: 0,
            keepalive_time: 0,
            flags: InitFlags::empty(),
            pvlim: 0,
            max_pdu_len: 0,
            lsr_id: Ipv4Addr::new(0, 0, 0, 0),
            lspace_id: 0,
        }
    }
}
