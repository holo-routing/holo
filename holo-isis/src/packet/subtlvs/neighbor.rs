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
use serde::{Deserialize, Serialize};

use crate::packet::SystemId;
use crate::packet::consts::NeighborStlvType;
use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::tlv::{tlv_encode_end, tlv_encode_start};

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
