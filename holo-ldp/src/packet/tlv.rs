//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{MessageDecodeInfo, MessageType};
use crate::packet::DecodeCxt;

//
// LDP Type-Length-Value.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |U|F|        Type               |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                             Value                             |
// ~                                                               ~
// |                                                               |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
pub const TLV_HDR_SIZE: u16 = 4;
pub const TLV_UNKNOWN_FLAG: u16 = 0x8000;
pub const TLV_FORWARD_FLAG: u16 = 0x4000;
pub const TLV_TYPE_MASK: u16 = 0x3FFF;

// LDP TLV type.
//
// IANA registry:
// https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#ldp-namespaces-4
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
#[derive(Deserialize, Serialize)]
pub enum TlvType {
    Fec = 0x0100,
    AddrList = 0x0101,
    HopCount = 0x0103,
    PathVector = 0x0104,
    GenericLabel = 0x0200,
    AtmLabel = 0x0201,
    FrLabel = 0x0202,
    Status = 0x0300,
    ExtStatus = 0x0301,
    ReturnedPdu = 0x0302,
    ReturnedMsg = 0x0303,
    CommonHelloParams = 0x0400,
    Ipv4TransAddr = 0x0401,
    ConfigSeqNo = 0x0402,
    Ipv6TransAddr = 0x0403,
    CommonSessParams = 0x0500,
    AtmSessParams = 0x0501,
    FrSessParams = 0x0502,
    LabelRequestId = 0x0600,
    // RFC 5561
    ReturnedTlvs = 0x0304,
    CapDynamic = 0x0506,
    // RFC 5918
    CapTwcardFec = 0x050B,
    // RFC 5919
    CapUnrecNotif = 0x0603,
    // RFC 7552
    DualStack = 0x0701,
}

//
// TLV decode information.
//
// Used as a control block during the decode process, and used to return
// detailed error information.
//
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlvDecodeInfo {
    pub tlv_raw: Bytes,
    pub tlv_type: u16,
    pub tlv_etype: Option<TlvType>,
    pub tlv_len: u16,
}

pub trait TlvKind: std::fmt::Debug {
    const TLV_TYPE: TlvType;
    const U_BIT: bool;
    const F_BIT: bool;

    fn encode_hdr(&self, _msg_type: MessageType, buf: &mut BytesMut) {
        let mut tlv_type = Self::TLV_TYPE as u16;
        if Self::U_BIT {
            tlv_type |= TLV_UNKNOWN_FLAG;
        }
        if Self::F_BIT {
            tlv_type |= TLV_FORWARD_FLAG;
        }

        buf.put_u16(tlv_type);
        // The TLV length will be rewritten later.
        buf.put_u16(0);
    }

    fn encode_value(&self, buf: &mut BytesMut);

    fn encode(&self, msg_type: MessageType, buf: &mut BytesMut) {
        let start_pos = buf.len();

        self.encode_hdr(msg_type, buf);
        self.encode_value(buf);

        // Rewrite TLV length.
        let tlv_len = (buf.len() - start_pos) as u16 - TLV_HDR_SIZE;
        buf[start_pos + 2..start_pos + 4]
            .copy_from_slice(&tlv_len.to_be_bytes());
    }

    fn decode_value(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self>
    where
        Self: Sized;
}

// ===== impl TlvType =====

impl TlvType {
    pub(crate) fn decode(value: u16) -> Option<Self> {
        TlvType::from_u16(value & TLV_TYPE_MASK)
    }
}

impl std::fmt::Display for TlvType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvType::Fec => write!(f, "FEC"),
            TlvType::AddrList => write!(f, "Address List"),
            TlvType::HopCount => write!(f, "Hop Count"),
            TlvType::PathVector => write!(f, "Path Vector"),
            TlvType::GenericLabel => write!(f, "Generic Label"),
            TlvType::AtmLabel => write!(f, "ATM Label"),
            TlvType::FrLabel => write!(f, "Frame Relay Label"),
            TlvType::Status => write!(f, "Status"),
            TlvType::ExtStatus => write!(f, "Extended Status"),
            TlvType::ReturnedPdu => write!(f, "Returned PDU"),
            TlvType::ReturnedMsg => write!(f, "Returned Message"),
            TlvType::CommonHelloParams => write!(f, "Common Hello Parameters"),
            TlvType::Ipv4TransAddr => write!(f, "IPv4 Transport Address"),
            TlvType::ConfigSeqNo => write!(f, "Configuration Sequence Number"),
            TlvType::Ipv6TransAddr => write!(f, "IPv6 Transport Address"),
            TlvType::CommonSessParams => write!(f, "Common Session Parameters"),
            TlvType::AtmSessParams => write!(f, "ATM Session Parameters"),
            TlvType::FrSessParams => {
                write!(f, "Frame Relay Session Parameters")
            }
            TlvType::LabelRequestId => write!(f, "Label Request Message ID"),
            TlvType::ReturnedTlvs => write!(f, "Returned TLVs"),
            TlvType::CapDynamic => write!(f, "Dynamic Capability Announcement"),
            TlvType::CapTwcardFec => write!(f, "Typed Wildcard FEC Capability"),
            TlvType::CapUnrecNotif => {
                write!(f, "Unrecognized Notification Capability")
            }
            TlvType::DualStack => write!(f, "Dual-Stack capability"),
        }
    }
}

// ===== global functions =====

pub(crate) fn decode_tlv_hdr(
    buf: &mut Bytes,
    msgi: &mut MessageDecodeInfo,
) -> DecodeResult<TlvDecodeInfo> {
    let buf_copy = buf.clone();

    // Parse TLV type.
    let tlv_type = buf.get_u16();
    let tlv_etype = TlvType::decode(tlv_type);

    // Parse and validate TLV length.
    let tlv_len = buf.get_u16();
    let tlv_size = tlv_len + TLV_HDR_SIZE;
    if tlv_size > msgi.msg_rlen {
        return Err(DecodeError::InvalidTlvLength(tlv_len));
    }

    // Save slice containing the entire TLV.
    let tlv_raw = buf_copy.slice(0..tlv_size as usize);

    // Update number of remaining bytes in the message.
    msgi.msg_rlen -= tlv_size;

    Ok(TlvDecodeInfo {
        tlv_raw,
        tlv_type,
        tlv_etype,
        tlv_len,
    })
}
