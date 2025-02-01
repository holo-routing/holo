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

use crate::packet::consts::NeighborSubTlvType;
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::tlv::{tlv_encode_end, tlv_encode_start};

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct AdminGroupSubTlv(u32);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4InterfaceAddrSubTlv(Ipv4Addr);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4NeighborAddrSubTlv(Ipv4Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MaxLinkBwSubTlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct MaxResvLinkBwSubTlv(f32);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UnreservedBwSubTlv([f32; 8]);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct TeDefaultMetricSubTlv(u32);

// ===== impl AdminGroupSubTlv =====

impl AdminGroupSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let groups = buf.get_u32();

        Ok(AdminGroupSubTlv(groups))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborSubTlvType::AdminGroup);
        buf.put_u32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}

// ===== impl Ipv4InterfaceAddrSubTlv =====

impl Ipv4InterfaceAddrSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(Ipv4InterfaceAddrSubTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::Ipv4InterfaceAddress);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

// ===== impl Ipv4NeighborAddrSubTlv =====

impl Ipv4NeighborAddrSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(Ipv4NeighborAddrSubTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::Ipv4NeighborAddress);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

// ===== impl MaxLinkBwSubTlv =====

impl MaxLinkBwSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let bw = buf.get_f32();

        Ok(MaxLinkBwSubTlv(bw))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::MaxLinkBandwidth);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl MaxResvLinkBwSubTlv =====

impl MaxResvLinkBwSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let bw = buf.get_f32();

        Ok(MaxResvLinkBwSubTlv(bw))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::MaxResvLinkBandwidth);
        buf.put_f32(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &f32 {
        &self.0
    }
}

// ===== impl UnreservedBwSubTlv =====

impl UnreservedBwSubTlv {
    const SIZE: usize = 32;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let mut bws = [0f32; 8];
        for bw in &mut bws {
            *bw = buf.get_f32();
        }

        Ok(UnreservedBwSubTlv(bws))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::UnreservedBandwidth);
        for bw in &self.0 {
            buf.put_f32(*bw);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &f32)> {
        self.0.iter().enumerate()
    }
}

// ===== impl TeDefaultMetricSubTlv =====

impl TeDefaultMetricSubTlv {
    const SIZE: usize = 3;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let metric = buf.get_u24();

        Ok(TeDefaultMetricSubTlv(metric))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborSubTlvType::TeDefaultMetric);
        buf.put_u24(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> u32 {
        self.0
    }
}
