//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::{Ipv4AddrExt, Ipv6AddrExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::{
    Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::tlv::{self, TlvDecodeInfo, TlvKind, TlvType};
use crate::packet::DecodeCxt;

//
// Hello Message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   Hello (0x0100)            |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Common Hello Parameters TLV               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct HelloMsg {
    pub msg_id: u32,
    pub params: TlvCommonHelloParams,
    pub ipv4_addr: Option<TlvIpv4TransAddr>,
    pub ipv6_addr: Option<TlvIpv6TransAddr>,
    pub cfg_seqno: Option<TlvConfigSeqNo>,
    pub dual_stack: Option<TlvDualStack>,
}

//
// Common Hello Parameters TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|0| Common Hello Parms(0x0400)|      Length                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Hold Time                |T|R| Reserved                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvCommonHelloParams {
    pub holdtime: u16,
    pub flags: HelloFlags,
}

// Common Hello Parameters TLV flags.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct HelloFlags: u16 {
        const TARGETED = 0x8000;
        const REQ_TARGETED = 0x4000;
        const GTSM = 0x2000;
    }
}

// IPv4 Transport Address TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvIpv4TransAddr(pub Ipv4Addr);

// IPv6 Transport Address TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvIpv6TransAddr(pub Ipv6Addr);

// Configuration Sequence Number TLV.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvConfigSeqNo(pub u32);

//
// Dual-Stack Capability TLV.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1|0|  Dual-Stack capability    |        Length                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |TR     |        Reserved       |     MBZ                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TlvDualStack(pub TransportPref);

// Dual-Stack transport preference.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum TransportPref {
    LDPOIPV4 = 0x4000,
    LDPOIPV6 = 0x6000,
}

// ===== impl HelloMsg =====

impl MessageKind for HelloMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        MessageType::Hello
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        // Encode mandatory TLV(s).
        self.params.encode(self.msg_type(), buf);

        // Encode optional TLV(s).
        if let Some(tlv) = &self.ipv4_addr {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.ipv6_addr {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.cfg_seqno {
            tlv.encode(self.msg_type(), buf);
        }
        if let Some(tlv) = &self.dual_stack {
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
        if tlvi.tlv_type != TlvType::CommonHelloParams as u16 {
            return Err(DecodeError::MissingMsgParams(
                msgi.clone(),
                TlvType::CommonHelloParams,
            ));
        }
        let params = TlvCommonHelloParams::decode_value(buf, cxt, &tlvi)?;

        // Create new message.
        let mut msg = Self {
            msg_id: msgi.msg_id,
            params,
            ..Default::default()
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Hello(msg))
    }

    fn decode_opt_tlv(
        &mut self,
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<bool> {
        //
        // RFC 7552 - Section 6.1:
        // An LSR SHOULD accept the Hello message that contains both IPv4 and
        // IPv6 Transport Address optional objects but MUST use only the
        // transport address whose address family is the same as that of the
        // IP packet carrying the Hello message.  An LSR SHOULD accept only
        // the first Transport Address optional object for a given address
        // family in the received Hello message and ignore the rest if the
        // LSR receives more than one Transport Address optional object for a
        // given address family.
        //
        match tlvi.tlv_etype.unwrap() {
            TlvType::Ipv4TransAddr => {
                let addr = TlvIpv4TransAddr::decode_value(buf, cxt, tlvi)?;
                if cxt.pkt_info.src_addr.is_ipv4() && self.ipv4_addr.is_none() {
                    self.ipv4_addr = Some(addr);
                }
            }
            TlvType::Ipv6TransAddr => {
                let addr = TlvIpv6TransAddr::decode_value(buf, cxt, tlvi)?;
                if cxt.pkt_info.src_addr.is_ipv6() && self.ipv6_addr.is_none() {
                    self.ipv6_addr = Some(addr);
                }
            }
            TlvType::ConfigSeqNo => {
                self.cfg_seqno =
                    Some(TlvConfigSeqNo::decode_value(buf, cxt, tlvi)?);
            }
            TlvType::DualStack => {
                self.dual_stack =
                    Some(TlvDualStack::decode_value(buf, cxt, tlvi)?);
            }
            _ => {
                return Ok(true);
            }
        };

        Ok(false)
    }
}

impl HelloMsg {
    pub const INFINITE_HOLDTIME: u16 = u16::MAX;
}

// ===== impl TlvCommonHelloParams =====

impl TlvKind for TlvCommonHelloParams {
    const TLV_TYPE: TlvType = TlvType::CommonHelloParams;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.holdtime);
        buf.put_u16(self.flags.bits());
    }

    fn decode_value(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let holdtime = buf.get_u16();

        // Ignore unknown flags.
        let flags = HelloFlags::from_bits_truncate(buf.get_u16());

        // Additional sanity checks.
        if let IpAddr::V6(addr) = cxt.pkt_info.src_addr {
            if flags.contains(HelloFlags::TARGETED)
                && addr.is_unicast_link_local()
            {
                return Err(DecodeError::InvalidSrcAddr(
                    tlvi.clone(),
                    cxt.pkt_info.src_addr,
                ));
            }
        }

        if let Some(multicast) = cxt.pkt_info.multicast {
            if multicast && flags.contains(HelloFlags::TARGETED) {
                return Err(DecodeError::McastTHello(
                    tlvi.clone(),
                    cxt.pkt_info.src_addr,
                ));
            }
            if !multicast && !flags.contains(HelloFlags::TARGETED) {
                return Err(DecodeError::UcastLHello(
                    tlvi.clone(),
                    cxt.pkt_info.src_addr,
                ));
            }
        }

        Ok(Self { holdtime, flags })
    }
}

// ===== impl TlvIpv4TransAddr =====

impl TlvKind for TlvIpv4TransAddr {
    const TLV_TYPE: TlvType = TlvType::Ipv4TransAddr;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_ipv4(&self.0);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let addr = buf.get_ipv4();
        if !addr.is_usable() {
            return Err(DecodeError::InvalidTransportAddr(
                tlvi.clone(),
                addr.into(),
            ));
        }

        Ok(Self(addr))
    }
}

// ===== impl TlvIpv6TransAddr =====

impl TlvKind for TlvIpv6TransAddr {
    const TLV_TYPE: TlvType = TlvType::Ipv6TransAddr;
    const U_BIT: bool = false;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_ipv6(&self.0);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 16 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        let addr = buf.get_ipv6();
        if !addr.is_usable() {
            return Err(DecodeError::InvalidTransportAddr(
                tlvi.clone(),
                addr.into(),
            ));
        }

        Ok(Self(addr))
    }
}

// ===== impl TlvConfigSeqNo =====

impl TlvKind for TlvConfigSeqNo {
    const TLV_TYPE: TlvType = TlvType::ConfigSeqNo;
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

        let seq_no = buf.get_u32();

        Ok(Self(seq_no))
    }
}

// ===== impl TlvDualStack =====

impl TlvKind for TlvDualStack {
    const TLV_TYPE: TlvType = TlvType::DualStack;
    const U_BIT: bool = true;
    const F_BIT: bool = false;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.0 as u16);
        buf.put_u16(0);
    }

    fn decode_value(
        buf: &mut Bytes,
        _cxt: &DecodeCxt,
        tlvi: &TlvDecodeInfo,
    ) -> DecodeResult<Self> {
        if tlvi.tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlvi.tlv_len));
        }

        // Parse the TR field.
        let trans_pref = buf.get_u16();
        if let Some(trans_pref) = TransportPref::from_u16(trans_pref) {
            // Ignore MBZ.
            let _ = buf.get_u16();

            return Ok(Self(trans_pref));
        }

        Err(DecodeError::InvalidTransportPref(tlvi.clone(), trans_pref))
    }
}
