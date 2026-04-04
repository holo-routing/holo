//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mpls::Label;
use holo_utils::sr::Sid;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::SystemId;
use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::iana::{AslaSabmFlags, AslaStlvType, NeighborStlvType};
use crate::packet::tlv::{
    TLV_HDR_SIZE, UnknownTlv, tlv_encode_end, tlv_encode_start,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct AdminGroupStlv(u32);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct ExtAdminGroupStlv(Vec<u32>);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4InterfaceAddrStlv(Ipv4Addr);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4NeighborAddrStlv(Ipv4Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MaxLinkBwStlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MaxResvLinkBwStlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UnreservedBwStlv([f32; 8]);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct TeDefaultMetricStlv(u32);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniLinkDelayStlv {
    pub flags: UniLinkDelayFlags,
    pub delay: u32,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct UniLinkDelayFlags: u8 {
        const A = 0x80;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MinMaxUniLinkDelayStlv {
    pub flags: MinMaxUniLinkDelayFlags,
    pub min_delay: u32,
    pub max_delay: u32,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct MinMaxUniLinkDelayFlags: u8 {
        const A = 0x80;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniDelayVariationStlv(u32);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniLinkLossStlv {
    pub flags: UniLinkLossFlags,
    pub loss: u32,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct UniLinkLossFlags: u8 {
        const A = 0x80;
    }
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniResidualBwStlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniAvailBwStlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UniUtilBwStlv(f32);

// RFC 9479, Section 4.2: Application-Specific Link Attributes Sub-TLV.
//
// This sub-TLV carries per-application link attributes. The SABM and UDABM
// identify which applications are associated with the enclosed sub-sub-TLVs.
#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AslaStlv {
    pub l_flag: bool,
    pub r_flag: bool,
    pub sabm_length: u8,
    pub sabm: AslaSabmFlags,
    pub udabm_length: u8,
    pub udabm: u64,
    pub sub_tlvs: AslaStlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct AslaStlvs {
    pub admin_group: Option<AdminGroupStlv>,
    pub ext_admin_group: Option<ExtAdminGroupStlv>,
    pub max_link_bw: Option<MaxLinkBwStlv>,
    pub max_resv_link_bw: Option<MaxResvLinkBwStlv>,
    pub unreserved_bw: Option<UnreservedBwStlv>,
    pub te_default_metric: Option<TeDefaultMetricStlv>,
    pub uni_link_delay: Option<UniLinkDelayStlv>,
    pub min_max_uni_link_delay: Option<MinMaxUniLinkDelayStlv>,
    pub uni_delay_variation: Option<UniDelayVariationStlv>,
    pub uni_link_loss: Option<UniLinkLossStlv>,
    pub uni_resid_bw: Option<UniResidualBwStlv>,
    pub uni_avail_bw: Option<UniAvailBwStlv>,
    pub uni_util_bw: Option<UniUtilBwStlv>,
    pub unknown: Vec<UnknownTlv>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AdjSidFlags: u8 {
        const F = 0x80;
        const B = 0x40;
        const V = 0x20;
        const L = 0x10;
        const S = 0x08;
        const P = 0x04;
    }
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct AdjSidStlv {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub nbr_system_id: Option<SystemId>,
    pub sid: Sid,
}

// ===== impl AdminGroupStlv =====

impl AdminGroupStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let groups = buf.try_get_u32()?;

        Ok(AdminGroupStlv(groups))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::AdminGroup);
        buf.put_u32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

// ===== impl ExtAdminGroupStlv =====

impl ExtAdminGroupStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // RFC 7308: length MUST be a non-zero multiple of 4.
        if stlv_len == 0 || !(stlv_len as usize).is_multiple_of(4) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let count = stlv_len as usize / 4;
        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            groups.push(buf.try_get_u32()?);
        }

        Ok(ExtAdminGroupStlv(groups))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::ExtendedAdminGroup);
        for word in &self.0 {
            buf.put_u32(*word);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &[u32] {
        &self.0
    }
}

// ===== impl Ipv4InterfaceAddrStlv =====

impl Ipv4InterfaceAddrStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let addr = buf.try_get_ipv4()?;

        Ok(Ipv4InterfaceAddrStlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::Ipv4InterfaceAddress);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

// ===== impl Ipv4NeighborAddrStlv =====

impl Ipv4NeighborAddrStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let addr = buf.try_get_ipv4()?;

        Ok(Ipv4NeighborAddrStlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::Ipv4NeighborAddress);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

// ===== impl MaxLinkBwStlv =====

impl MaxLinkBwStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let bw = buf.try_get_f32()?;

        Ok(MaxLinkBwStlv(bw))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::MaxLinkBandwidth);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl MaxResvLinkBwStlv =====

impl MaxResvLinkBwStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let bw = buf.try_get_f32()?;

        Ok(MaxResvLinkBwStlv(bw))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::MaxResvLinkBandwidth);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl UnreservedBwStlv =====

impl UnreservedBwStlv {
    const SIZE: usize = 32;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut bws = [0f32; 8];
        for bw in &mut bws {
            *bw = buf.try_get_f32()?;
        }

        Ok(UnreservedBwStlv(bws))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::UnreservedBandwidth);
        for bw in &self.0 {
            buf.put_f32(*bw);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &f32)> {
        self.0.iter().enumerate()
    }
}

// ===== impl TeDefaultMetricStlv =====

impl TeDefaultMetricStlv {
    const SIZE: usize = 3;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let metric = buf.try_get_u24()?;

        Ok(TeDefaultMetricStlv(metric))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::TeDefaultMetric);
        buf.put_u24(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

// ===== impl UniLinkDelayStlv =====

impl UniLinkDelayStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags = UniLinkDelayFlags::from_bits_truncate(buf.try_get_u8()?);
        let delay = buf.try_get_u24()?;

        Ok(UniLinkDelayStlv { flags, delay })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::UniLinkDelay);
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.delay);
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl MinMaxUniLinkDelayStlv =====

impl MinMaxUniLinkDelayStlv {
    const SIZE: usize = 8;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags =
            MinMaxUniLinkDelayFlags::from_bits_truncate(buf.try_get_u8()?);
        let min_delay = buf.try_get_u24()?;
        let _reserved = buf.try_get_u8()?;
        let max_delay = buf.try_get_u24()?;

        Ok(MinMaxUniLinkDelayStlv {
            flags,
            min_delay,
            max_delay,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::MinMaxUniLinkDelay);
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.min_delay);
        buf.put_u8(0);
        buf.put_u24(self.max_delay);
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl UniDelayVariationStlv =====

impl UniDelayVariationStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let _reserved = buf.try_get_u8()?;
        let variation = buf.try_get_u24()?;

        Ok(UniDelayVariationStlv(variation))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::UniDelayVariation);
        buf.put_u8(0);
        buf.put_u24(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

// ===== impl UniLinkLossStlv =====

impl UniLinkLossStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags = UniLinkLossFlags::from_bits_truncate(buf.try_get_u8()?);
        let loss = buf.try_get_u24()?;

        Ok(UniLinkLossStlv { flags, loss })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::UniLinkLoss);
        buf.put_u8(self.flags.bits());
        buf.put_u24(self.loss);
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl UniResidualBwStlv =====

impl UniResidualBwStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        Ok(UniResidualBwStlv(buf.try_get_f32()?))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::UniResidualBw);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl UniAvailBwStlv =====

impl UniAvailBwStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        Ok(UniAvailBwStlv(buf.try_get_f32()?))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::UniAvailBw);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl UniUtilBwStlv =====

impl UniUtilBwStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        Ok(UniUtilBwStlv(buf.try_get_f32()?))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::UniUtilBw);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl AslaStlv =====

impl AslaStlv {
    const MIN_SIZE: usize = 2;
    const MAX_MASK_LEN: u8 = 8;
    const FLAG_MASK: u8 = 0x80;
    const LENGTH_MASK: u8 = 0x7F;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Option<Self>> {
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let byte0 = buf.try_get_u8()?;
        let l_flag = (byte0 & Self::FLAG_MASK) != 0;
        let sabm_length = byte0 & Self::LENGTH_MASK;

        let byte1 = buf.try_get_u8()?;
        let r_flag = (byte1 & Self::FLAG_MASK) != 0;
        let udabm_length = byte1 & Self::LENGTH_MASK;

        // Per RFC 9479, ignore the entire sub-TLV if either mask length > 8.
        if sabm_length > Self::MAX_MASK_LEN || udabm_length > Self::MAX_MASK_LEN
        {
            return Ok(None);
        }

        // Parse SABM.
        let mut sabm_raw = 0u64;
        for i in 0..sabm_length as usize {
            sabm_raw |= (buf.try_get_u8()? as u64) << (56 - i * 8);
        }
        let sabm = AslaSabmFlags::from_bits_truncate(sabm_raw);

        // Parse UDABM.
        let mut udabm_raw = 0u64;
        for i in 0..udabm_length as usize {
            udabm_raw |= (buf.try_get_u8()? as u64) << (56 - i * 8);
        }

        // Parse sub-sub-TLVs.
        let sub_tlvs = AslaStlvs::decode(buf);

        Ok(Some(AslaStlv {
            l_flag,
            r_flag,
            sabm_length,
            sabm,
            udabm_length,
            udabm: udabm_raw,
            sub_tlvs,
        }))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::AppSpecificLinkAttr);
        let byte0 = if self.l_flag { Self::FLAG_MASK } else { 0 }
            | (self.sabm_length & Self::LENGTH_MASK);
        buf.put_u8(byte0);
        let byte1 = if self.r_flag { Self::FLAG_MASK } else { 0 }
            | (self.udabm_length & Self::LENGTH_MASK);
        buf.put_u8(byte1);
        for i in 0..self.sabm_length as usize {
            buf.put_u8((self.sabm.bits() >> (56 - i * 8)) as u8);
        }
        for i in 0..self.udabm_length as usize {
            buf.put_u8((self.udabm >> (56 - i * 8)) as u8);
        }
        self.sub_tlvs.encode(buf);
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl AslaStlvs =====

impl AslaStlvs {
    pub(crate) fn decode(buf: &mut Bytes) -> Self {
        let mut sub_tlvs = AslaStlvs::default();

        while buf.remaining() >= TLV_HDR_SIZE {
            let stlv_type = buf.get_u8();
            let stlv_etype = AslaStlvType::from_u8(stlv_type);
            let stlv_len = buf.get_u8();
            if stlv_len as usize > buf.remaining() {
                break;
            }
            let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
            match stlv_etype {
                Some(AslaStlvType::AdminGroup) => {
                    match AdminGroupStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.admin_group = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::ExtendedAdminGroup) => {
                    match ExtAdminGroupStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.ext_admin_group = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::MaxLinkBandwidth) => {
                    match MaxLinkBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.max_link_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::MaxResvLinkBandwidth) => {
                    match MaxResvLinkBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.max_resv_link_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UnreservedBandwidth) => {
                    match UnreservedBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.unreserved_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::TeDefaultMetric) => {
                    match TeDefaultMetricStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.te_default_metric = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniLinkDelay) => {
                    match UniLinkDelayStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.uni_link_delay = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::MinMaxUniLinkDelay) => {
                    match MinMaxUniLinkDelayStlv::decode(
                        stlv_len,
                        &mut buf_stlv,
                    ) {
                        Ok(stlv) => {
                            sub_tlvs.min_max_uni_link_delay = Some(stlv)
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniDelayVariation) => {
                    match UniDelayVariationStlv::decode(stlv_len, &mut buf_stlv)
                    {
                        Ok(stlv) => sub_tlvs.uni_delay_variation = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniLinkLoss) => {
                    match UniLinkLossStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.uni_link_loss = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniResidualBw) => {
                    match UniResidualBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.uni_resid_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniAvailBw) => {
                    match UniAvailBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.uni_avail_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(AslaStlvType::UniUtilBw) => {
                    match UniUtilBwStlv::decode(stlv_len, &mut buf_stlv) {
                        Ok(stlv) => sub_tlvs.uni_util_bw = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                None => {
                    sub_tlvs.unknown.push(UnknownTlv {
                        tlv_type: stlv_type,
                        length: stlv_len,
                        value: buf_stlv,
                    });
                }
            }
        }

        sub_tlvs
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        if let Some(stlv) = &self.admin_group {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.ext_admin_group {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.max_link_bw {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.max_resv_link_bw {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.unreserved_bw {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.te_default_metric {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_link_delay {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.min_max_uni_link_delay {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_delay_variation {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_link_loss {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_resid_bw {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_avail_bw {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.uni_util_bw {
            stlv.encode(buf);
        }
    }
}

// ===== impl AdjSidStlv =====

impl AdjSidStlv {
    pub(crate) fn decode(
        _stlv_len: u8,
        lan: bool,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Option<Self>> {
        let flags = buf.try_get_u8()?;
        let flags = AdjSidFlags::from_bits_truncate(flags);
        let weight = buf.try_get_u8()?;

        let mut nbr_system_id = None;
        if lan {
            nbr_system_id = Some(SystemId::decode(buf)?);
        }

        // Parse SID (variable length).
        let sid = if !flags.intersects(AdjSidFlags::V | AdjSidFlags::L) {
            Sid::Index(buf.try_get_u32()?)
        } else if flags.contains(AdjSidFlags::V | AdjSidFlags::L) {
            let label = buf.try_get_u24()? & Label::VALUE_MASK;
            Sid::Label(Label::new(label))
        } else {
            // Invalid V-Flag and L-Flag combination - ignore.
            return Ok(None);
        };

        Ok(Some(AdjSidStlv {
            flags,
            weight,
            nbr_system_id,
            sid,
        }))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let stlv_type = match self.nbr_system_id {
            Some(_) => NeighborStlvType::LanAdjacencySid,
            None => NeighborStlvType::AdjacencySid,
        };
        let start_pos = tlv_encode_start(buf, stlv_type);
        buf.put_u8(self.flags.bits());
        buf.put_u8(self.weight);
        if let Some(nbr_system_id) = &self.nbr_system_id {
            nbr_system_id.encode(buf);
        }
        match self.sid {
            Sid::Index(index) => buf.put_u32(index),
            Sid::Label(label) => buf.put_u24(label.get()),
        }
        tlv_encode_end(buf, start_pos);
    }
}
