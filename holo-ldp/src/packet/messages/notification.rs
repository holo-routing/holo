//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::packet::DecodeCxt;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::messages::label::TlvFec;
use crate::packet::pdu::Pdu;
use crate::packet::tlv::{self, TlvDecodeInfo, TlvKind, TlvType};

//
// Notification Message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Notification (0x0001)     |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Status (TLV)                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct NotifMsg {
    pub msg_id: u32,
    pub status: TlvStatus,
    pub ext_status: Option<TlvExtStatus>,
    pub returned_pdu: Option<TlvReturnedPdu>,
    pub returned_msg: Option<TlvReturnedMsg>,
    pub returned_tlvs: Option<TlvReturnedTlvs>,
    pub fec: Option<TlvFec>,
}

//
// Status TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |U|F| Status (0x0300)           |      Length                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Status Code                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Message Type             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvStatus {
    pub status_code: u32,
    pub msg_id: u32,
    pub msg_type: u16,
}

// Extended Status TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvExtStatus(pub u32);

// Returned PDU TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvReturnedPdu(Vec<u8>);

// Returned Message TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvReturnedMsg(Vec<u8>);

// Returned TLVs TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvReturnedTlvs(Vec<u8>);

//
// LDP Status Code.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |E|F|                 Status Data                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// IANA registry:
// https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#status-codes
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum StatusCode {
    Success = 0x0000_0000,
    BadLdpId = 0x0000_0001,
    BadProtoVers = 0x0000_0002,
    BadPduLen = 0x0000_0003,
    UnknownMsgType = 0x0000_0004,
    BadMsgLen = 0x0000_0005,
    UnknownTlv = 0x0000_0006,
    BadTlvLen = 0x0000_0007,
    MalformedTlvValue = 0x0000_0008,
    HoldTimerExp = 0x0000_0009,
    Shutdown = 0x0000_000A,
    LoopDetected = 0x0000_000B,
    UnknownFec = 0x0000_000C,
    NoRoute = 0x0000_000D,
    NoLabelRes = 0x0000_000E,
    LabelResAvailable = 0x0000_000F,
    SessRejNoHello = 0x0000_0010,
    SessRejAdvMode = 0x0000_0011,
    SessRejMaxPduLen = 0x0000_0012,
    SessRejLabelRange = 0x0000_0013,
    KeepaliveExp = 0x0000_0014,
    LabelReqAbrt = 0x0000_0015,
    MissingMsgParams = 0x0000_0016,
    UnsupportedAf = 0x0000_0017,
    SessRejKeepalive = 0x0000_0018,
    InternalError = 0x0000_0019,
    // RFC 5561
    UnsupportedCap = 0x0000_002E,
    // RFC 5919
    EndOfLib = 0x0000_002F,
    // RFC 7552
    TransportMismatch = 0x0000_0032,
    DsNoncompliance = 0x0000_0033,
}

const TLV_STATUS_CODE_E_FLAG: u32 = 0x8000_0000;
const TLV_STATUS_CODE_F_FLAG: u32 = 0x4000_0000;
const TLV_STATUS_CODE_MASK: u32 = 0x3FFF_FFFF;

// ===== impl NotifMsg =====

impl MessageKind for NotifMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        MessageType::Notification
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode mandatory TLV(s).
        self.status.encode(self.msg_type(), buf);

        // Encode optional TLV(s).
        if let Some(tlv) = &self.ext_status {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.returned_pdu {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.returned_msg {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.returned_tlvs {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.fec {
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
        if tlvi.tlv_type != TlvType::Status as u16 {
            return Err(DecodeError::MissingMsgParams(
                msgi.clone(),
                TlvType::Status,
            ));
        }
        let status = TlvStatus::decode_value(buf, cxt, &tlvi)?;

        // Create new message.
        let mut msg = Self {
            msg_id: msgi.msg_id,
            status,
            ..Default::default()
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Notification(msg))
    }

    fn decode_opt_tlv(
        &mut self,
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<bool> {
        match tlvi.tlv_etype.unwrap() {
            TlvType::ExtStatus => {
                self.ext_status =
                    Some(TlvExtStatus::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::ReturnedPdu => {
                self.returned_pdu =
                    Some(TlvReturnedPdu::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::ReturnedMsg => {
                self.returned_msg =
                    Some(TlvReturnedMsg::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::ReturnedTlvs => {
                self.returned_tlvs =
                    Some(TlvReturnedTlvs::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::Fec => {
                self.fec = Some(TlvFec::decode_value(buf, cxt, tlvi)?);
            }
            _ => {
                return Ok(true);
            }
        };

        Ok(false)
    }
}

impl NotifMsg {
    pub(crate) fn is_fatal_error(&self) -> bool {
        self.status.status_code & TLV_STATUS_CODE_E_FLAG != 0
    }
}

// ===== impl TlvStatus =====

impl TlvKind for TlvStatus {
    const TLV_TYPE: TlvType = TlvType::Status;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    //
    // Override the default implementation of encode_hdr() since the U-bit and
    // the F-bit need to be set dynamically, depending on the following
    // conditions (as specified by RFC 5036):
    //
    // U-bit
    //    SHOULD be 0 when the Status TLV is sent in a Notification message.
    //    SHOULD be 1 when the Status TLV is sent in some other message.
    //
    // F-bit
    //    SHOULD be the same as the setting of the F-bit in the Status Code
    //    field.
    //
    fn encode_hdr(&self, msg_type: MessageType, buf: &mut BytesMut) {
        let mut tlv_type = Self::TLV_TYPE as u16;
        if msg_type != MessageType::Notification {
            tlv_type |= tlv::TLV_UNKNOWN_FLAG;
        }
        if self.status_code & TLV_STATUS_CODE_F_FLAG != 0 {
            tlv_type |= tlv::TLV_FORWARD_FLAG;
        }

        buf.put_u16(tlv_type);
        // The message length will be rewritten later.
        buf.put_u16(0);
    }

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.status_code);
        buf.put_u32(self.msg_id);
        buf.put_u16(self.msg_type);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 10 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let status_code = buf.try_get_u32()?;
        let msg_id = buf.try_get_u32()?;
        let msg_type = buf.try_get_u16()?;

        Ok(Self {
            status_code,
            msg_id,
            msg_type,
        })
    }
}

// ===== impl TlvExtStatus =====

impl TlvKind for TlvExtStatus {
    const TLV_TYPE: TlvType = TlvType::ExtStatus;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let ext_status = buf.try_get_u32()?;

        Ok(Self(ext_status))
    }
}

// ===== impl TlvReturnedPdu =====

impl TlvKind for TlvReturnedPdu {
    const TLV_TYPE: TlvType = TlvType::ReturnedPdu;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.extend(self.0.clone());
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len < Pdu::HDR_SIZE {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let mut pdu = vec![0; tlvi.tlv_len as usize];
        buf.try_copy_to_slice(&mut pdu)?;
        Ok(Self(pdu.to_vec()))
    }
}

// ===== impl TlvReturnedMsg =====

impl TlvKind for TlvReturnedMsg {
    const TLV_TYPE: TlvType = TlvType::ReturnedMsg;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.extend(self.0.clone());
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len < Message::HDR_DEAD_LEN {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let mut msg = vec![0; tlvi.tlv_len as usize];
        buf.try_copy_to_slice(&mut msg)?;
        Ok(Self(msg.to_vec()))
    }
}

// ===== impl TlvReturnedTlvs =====

impl TlvKind for TlvReturnedTlvs {
    const TLV_TYPE: TlvType = TlvType::ReturnedTlvs;
    const U_BIT: bool = true;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.extend(self.0.clone());
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len < tlv::TLV_HDR_SIZE {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let mut tlvs = vec![0; tlvi.tlv_len as usize];
        buf.try_copy_to_slice(&mut tlvs)?;
        Ok(Self(tlvs.to_vec()))
    }
}

// ===== impl StatusCode =====

impl StatusCode {
    pub fn encode(self, f_bit: bool) -> u32 {
        let mut value = self as u32;
        if self.is_fatal_error() {
            value |= TLV_STATUS_CODE_E_FLAG;
        }
        if f_bit {
            value |= TLV_STATUS_CODE_F_FLAG;
        }

        value
    }

    pub(crate) fn decode(value: u32) -> Option<Self> {
        StatusCode::from_u32(value & TLV_STATUS_CODE_MASK)
    }

    pub(crate) fn is_fatal_error(&self) -> bool {
        matches!(
            self,
            StatusCode::BadLdpId
                | StatusCode::BadProtoVers
                | StatusCode::BadPduLen
                | StatusCode::BadMsgLen
                | StatusCode::BadTlvLen
                | StatusCode::MalformedTlvValue
                | StatusCode::HoldTimerExp
                | StatusCode::Shutdown
                | StatusCode::SessRejNoHello
                | StatusCode::SessRejAdvMode
                | StatusCode::SessRejMaxPduLen
                | StatusCode::SessRejLabelRange
                | StatusCode::KeepaliveExp
                | StatusCode::SessRejKeepalive
                | StatusCode::InternalError
                | StatusCode::TransportMismatch
                | StatusCode::DsNoncompliance
        )
    }
}

impl From<DecodeError> for StatusCode {
    fn from(error: DecodeError) -> StatusCode {
        match error {
            DecodeError::InvalidPduLength(_) => StatusCode::BadPduLen,
            DecodeError::InvalidVersion(_) => StatusCode::BadProtoVers,
            DecodeError::InvalidLsrId(_)
            | DecodeError::InvalidLabelSpace(_) => StatusCode::BadLdpId,
            DecodeError::InvalidMessageLength(_) => StatusCode::BadMsgLen,
            DecodeError::UnknownMessage(_, _) => StatusCode::UnknownMsgType,
            DecodeError::MissingMsgParams(_, _) => StatusCode::MissingMsgParams,
            DecodeError::InvalidTlvLength(_) => StatusCode::BadTlvLen,
            DecodeError::UnknownTlv(_, _, _) => StatusCode::UnknownTlv,
            DecodeError::InvalidTlvValue(_) => StatusCode::MalformedTlvValue,
            DecodeError::UnsupportedAf(_, _) => StatusCode::UnsupportedAf,
            DecodeError::UnknownFec(_, _) => StatusCode::UnknownFec,
            DecodeError::BadKeepaliveTime(_, _) => StatusCode::SessRejKeepalive,
            _ => StatusCode::InternalError,
        }
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusCode::Success => write!(f, "Success"),
            StatusCode::BadLdpId => write!(f, "Bad LDP Identifier"),
            StatusCode::BadProtoVers => write!(f, "Bad Protocol Version"),
            StatusCode::BadPduLen => write!(f, "Bad PDU Length"),
            StatusCode::UnknownMsgType => write!(f, "Unknown Message Type"),
            StatusCode::BadMsgLen => write!(f, "Bad Message Length"),
            StatusCode::UnknownTlv => write!(f, "Unknown TLV"),
            StatusCode::BadTlvLen => write!(f, "Bad TLV Length"),
            StatusCode::MalformedTlvValue => write!(f, "Malformed TLV Value"),
            StatusCode::HoldTimerExp => write!(f, "Hold Timer Expired"),
            StatusCode::Shutdown => write!(f, "Shutdown"),
            StatusCode::LoopDetected => write!(f, "Loop Detected"),
            StatusCode::UnknownFec => write!(f, "Unknown FEC"),
            StatusCode::NoRoute => write!(f, "No Route"),
            StatusCode::NoLabelRes => write!(f, "No Label Resources"),
            StatusCode::LabelResAvailable => {
                write!(f, "Label Resources Available")
            }
            StatusCode::SessRejNoHello => {
                write!(f, "Session Rejected: No Hello")
            }
            StatusCode::SessRejAdvMode => {
                write!(f, "Session Rejected: Parameters Advertisement Mode")
            }
            StatusCode::SessRejMaxPduLen => {
                write!(f, "Session Rejected: Parameters Max PDU Length")
            }
            StatusCode::SessRejLabelRange => {
                write!(f, "Session Rejected: Parameters Label Range")
            }
            StatusCode::KeepaliveExp => write!(f, "KeepAlive Timer Expired"),
            StatusCode::LabelReqAbrt => write!(f, "Label Request Aborted"),
            StatusCode::MissingMsgParams => {
                write!(f, "Missing Message Parameters")
            }
            StatusCode::UnsupportedAf => {
                write!(f, "Unsupported Address Family")
            }
            StatusCode::SessRejKeepalive => {
                write!(f, "Session Rejected: Bad KeepAlive Time")
            }
            StatusCode::InternalError => write!(f, "Internal Error"),
            StatusCode::UnsupportedCap => write!(f, "Unsupported Capability"),
            StatusCode::EndOfLib => write!(f, "End-of-LIB"),
            StatusCode::TransportMismatch => {
                write!(f, "Transport Connection Mismatch")
            }
            StatusCode::DsNoncompliance => {
                write!(f, "Dual-Stack Noncompliance")
            }
        }
    }
}
