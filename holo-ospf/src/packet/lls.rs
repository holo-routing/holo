//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
use std::collections::BTreeMap;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use internet_checksum::Checksum;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{self, Deserialize, Serialize};

use super::auth::AuthEncodeCtx;
use super::error::{DecodeError, DecodeResult};
use super::tlv::{tlv_encode_end, tlv_encode_start};
use crate::packet::AuthDecodeCtx;
use crate::version::Version;

pub type ReverseMetric = u16;
pub type ReverseTeMetric = u32;

// LLS header size.
pub const LLS_HDR_SIZE: u16 = 4;

pub trait LlsVersion<V: Version> {
    type LlsDataBlock: From<LlsHelloData>
        + From<LlsDbDescData>
        + std::fmt::Debug;

    fn encode_lls_block(
        buf: &mut BytesMut,
        lls: V::LlsDataBlock,
        auth: Option<&AuthEncodeCtx<'_>>,
    );

    fn decode_lls_block(
        buf: &[u8],
        pkt_len: u16,
        hdr_auth: V::PacketHdrAuth,
        auth: Option<&AuthDecodeCtx<'_>>,
    ) -> DecodeResult<Option<V::LlsDataBlock>>;

    const CKSUM_RANGE: std::ops::Range<usize> = 0..2;
    const LENGTH_RANGE: std::ops::Range<usize> = 2..4;

    fn update_len(buf: &mut BytesMut, start_pos: usize, len: u16) {
        buf[start_pos + Self::LENGTH_RANGE.start
            ..start_pos + Self::LENGTH_RANGE.end]
            .copy_from_slice(&len.to_be_bytes());
    }

    fn update_cksum(buf: &mut BytesMut, start_pos: usize) {
        let mut cksum = Checksum::new();
        cksum.add_bytes(&buf[start_pos..]);
        buf[start_pos + Self::CKSUM_RANGE.start
            ..start_pos + Self::CKSUM_RANGE.end]
            .copy_from_slice(&cksum.checksum());
    }

    fn verify_cksum(data: &[u8]) -> DecodeResult<()> {
        let mut cksum = Checksum::new();
        cksum.add_bytes(&data[Self::CKSUM_RANGE.end..]);
        if cksum.checksum() != data[Self::CKSUM_RANGE] {
            return Err(DecodeError::InvalidChecksum);
        }
        Ok(())
    }
}

// LLS TLV types.
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml
#[derive(ToPrimitive, FromPrimitive)]
pub enum LlsTlvType {
    ExtendedOptionsFlags = 1,
    CryptoAuth = 2,
    ReverseMetric = 19,
    ReverseTeMetric = 20,
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[derive(Serialize, Deserialize)]
pub enum LlsData {
    Hello(LlsHelloData),
    DbDesc(LlsDbDescData),
}

impl LlsData {
    pub(crate) fn encode<V>(
        &self,
        buf: &mut BytesMut,
        auth: Option<&AuthEncodeCtx<'_>>,
    ) where
        V: Version,
    {
        let lls: V::LlsDataBlock = match self {
            Self::Hello(hello) => hello.clone().into(),
            Self::DbDesc(dbdesc) => (*dbdesc).into(),
        };
        V::encode_lls_block(buf, lls, auth);
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
#[derive(Serialize, Deserialize)]
pub struct LlsHelloData {
    pub eof: Option<ExtendedOptionsFlags>,
    pub reverse_metric: BTreeMap<u8, (ReverseMetricFlags, ReverseMetric)>,
    pub reverse_te_metric: Option<(ReverseTeMetricFlags, ReverseTeMetric)>,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub struct LlsDbDescData {
    pub eof: Option<ExtendedOptionsFlags>,
}

// Extended Options and Flags
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml#ospf-lls-tlvs-2
bitflags! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy)]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ExtendedOptionsFlags: u32 {
        const LR = 0x00000001;
        const RS = 0x00000002;
    }
}

// RFC 5613 : LLS Extended Options and Flags TLV.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             1                 |            4                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Extended Options and Flags                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct ExtendedOptionsFlagsTlv(pub ExtendedOptionsFlags);

impl ExtendedOptionsFlagsTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let opts = ExtendedOptionsFlags::from_bits_truncate(buf.try_get_u32()?);
        Ok(ExtendedOptionsFlagsTlv(opts))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::ExtendedOptionsFlags);
        buf.put_u32(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }
}

// RFC 9339 : Reverse Metric TLV
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     MTID      | Flags     |O|H|        Reverse Metric         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
#[derive(Serialize, Deserialize)]
pub struct ReverseMetricTlv {
    pub mtid: u8,
    pub flags: ReverseMetricFlags,
    pub metric: u16,
}

// Reverse Metric flags
bitflags! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy)]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ReverseMetricFlags: u8 {
        const H = 0x01;
        const O = 0x02;
    }
}

impl ReverseMetricTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let mtid = buf.try_get_u8()?;
        let flags = ReverseMetricFlags::from_bits_truncate(buf.try_get_u8()?);
        let metric = buf.try_get_u16()?;

        Ok(Self {
            mtid,
            flags,
            metric,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::ReverseMetric);
        buf.put_u8(self.mtid);
        buf.put_u8(self.flags.bits());
        buf.put_u16(self.metric);
        tlv_encode_end(buf, start_pos);
    }
}

impl From<(&u8, &(ReverseMetricFlags, ReverseMetric))> for ReverseMetricTlv {
    fn from(value: (&u8, &(ReverseMetricFlags, ReverseMetric))) -> Self {
        let mtid = *value.0;
        let (flags, metric) = *value.1;
        Self {
            mtid,
            flags,
            metric,
        }
    }
}

// RFC 9339 : Reverse TE Metric TLV
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Flags   |O|H|                 RESERVED                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Reverse TE Metric                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
#[derive(Serialize, Deserialize)]
pub struct ReverseTeMetricTlv {
    pub flags: ReverseTeMetricFlags,
    pub metric: u32,
}

// Reverse TE Metric flags
bitflags! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy)]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ReverseTeMetricFlags: u8 {
        const H = 0x01;
        const O = 0x02;
    }
}

impl ReverseTeMetricTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 8 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let flags = ReverseTeMetricFlags::from_bits_truncate(buf.try_get_u8()?);
        let _ = buf.try_get_u24()?;
        let metric = buf.try_get_u32()?;

        Ok(Self { flags, metric })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::ReverseTeMetric);
        buf.put_u8(self.flags.bits());
        buf.put_u24(0);
        buf.put_u32(self.metric);
        tlv_encode_end(buf, start_pos);
    }
}

impl From<&(ReverseTeMetricFlags, ReverseTeMetric)> for ReverseTeMetricTlv {
    fn from(value: &(ReverseTeMetricFlags, ReverseTeMetric)) -> Self {
        let flags = value.0;
        let metric = value.1;
        Self { flags, metric }
    }
}

// ===== global functions =====

pub(crate) fn lls_encode_start(buf: &mut BytesMut) -> usize {
    let start_pos = buf.len();
    // Checksum will be rewritten later.
    buf.put_u16(0);
    // The LLS data block length will be rewritten later.
    buf.put_u16(0);
    start_pos
}

pub(crate) fn lls_encode_end<V>(
    buf: &mut BytesMut,
    start_pos: usize,
    skip_cksum: bool,
) where
    V: Version,
{
    // RFC 5613 : "The 16-bit LLS Data Length field contains the length (in
    // 32-bit words) of the LLS block including the header and payload."
    let lls_len = ((buf.len() - start_pos) / 4) as u16;

    // Rewrite LLS length.
    V::update_len(buf, start_pos, lls_len);

    // Rewrite LLS checksum if authentication is disabled.
    if !skip_cksum {
        V::update_cksum(buf, start_pos);
    }
}
