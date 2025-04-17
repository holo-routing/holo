//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use serde::{Deserialize, Serialize};

use crate::packet::consts::NeighborStlvType;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::tlv::{tlv_encode_end, tlv_encode_start};

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct AdminGroupStlv(u32);

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

// ===== impl AdminGroupStlv =====

impl AdminGroupStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let groups = buf.get_u32();

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

// ===== impl Ipv4InterfaceAddrStlv =====

impl Ipv4InterfaceAddrStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let addr = buf.get_ipv4();

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

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let addr = buf.get_ipv4();

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

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let bw = buf.get_f32();

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

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let bw = buf.get_f32();

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

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let mut bws = [0f32; 8];
        for bw in &mut bws {
            *bw = buf.get_f32();
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

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let metric = buf.get_u24();

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
