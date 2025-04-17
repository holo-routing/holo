//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bier::{BierEncapId, BiftId};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::consts::{BierSubStlvType, PrefixStlvType};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::tlv::{TLV_HDR_SIZE, tlv_encode_end, tlv_encode_start};

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct PrefixAttrFlags: u8 {
        const X = 0x80;
        const R = 0x40;
        const N = 0x20;
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct PrefixAttrFlagsStlv(PrefixAttrFlags);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4SourceRidStlv(Ipv4Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6SourceRidStlv(Ipv6Addr);

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct PrefixSidFlags: u8 {
        const R = 0x80;
        const N = 0x40;
        const P = 0x20;
        const E = 0x10;
        const V = 0x08;
        const L = 0x04;
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct PrefixSidStlv {
    pub flags: PrefixSidFlags,
    pub algo: IgpAlgoType,
    pub sid: Sid,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierInfoStlv {
    pub bar: u8,
    pub ipa: u8,
    pub sub_domain_id: u8,
    pub bfr_id: u16,
    pub subtlvs: Vec<BierSubStlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub enum BierSubStlv {
    BierEncapSubStlv(BierEncapSubStlv),
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierEncapSubStlv {
    pub max_si: u8,
    pub bs_len: u8,
    pub id: BierEncapId,
}

// ===== impl PrefixAttrFlagsStlv =====

impl PrefixAttrFlagsStlv {
    const SIZE: usize = 1;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // A TLV length of zero is permitted under RFC 7794.
        if stlv_len == 0 {
            return Ok(PrefixAttrFlagsStlv::default());
        }

        // Any remaining bits beyond the first byte are ignored.
        let flags = buf.get_u8();
        let flags = PrefixAttrFlags::from_bits_truncate(flags);

        Ok(PrefixAttrFlagsStlv(flags))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixStlvType::PrefixAttributeFlags);
        buf.put_u8(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    pub(crate) fn get(&self) -> PrefixAttrFlags {
        self.0
    }

    pub(crate) fn set(&mut self, flag: PrefixAttrFlags) {
        self.0.insert(flag);
    }
}

// ===== impl Ipv4SourceRidStlv =====

impl Ipv4SourceRidStlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(Ipv4SourceRidStlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixStlvType::Ipv4SourceRouterId);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

// ===== impl Ipv6SourceRidStlv =====

impl Ipv6SourceRidStlv {
    const SIZE: usize = 16;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }

        let addr = buf.get_ipv6();

        Ok(Ipv6SourceRidStlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixStlvType::Ipv6SourceRouterId);
        buf.put_ipv6(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    pub(crate) fn get(&self) -> &Ipv6Addr {
        &self.0
    }
}

// ===== impl PrefixSidStlv =====

impl PrefixSidStlv {
    pub(crate) fn decode(
        _stlv_len: u8,
        buf: &mut Bytes,
    ) -> DecodeResult<Option<Self>> {
        let flags = buf.get_u8();
        let flags = PrefixSidFlags::from_bits_truncate(flags);
        let algo = buf.get_u8();
        let algo = match IgpAlgoType::from_u8(algo) {
            Some(algo) => algo,
            None => {
                // Unsupported algorithm - ignore.
                return Ok(None);
            }
        };

        // Parse SID (variable length).
        let sid = if !flags.intersects(PrefixSidFlags::V | PrefixSidFlags::L) {
            Sid::Index(buf.get_u32())
        } else if flags.contains(PrefixSidFlags::V | PrefixSidFlags::L) {
            let label = buf.get_u24() & Label::VALUE_MASK;
            Sid::Label(Label::new(label))
        } else {
            // Invalid V-Flag and L-Flag combination - ignore.
            return Ok(None);
        };

        Ok(Some(PrefixSidStlv { flags, algo, sid }))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, PrefixStlvType::PrefixSid);
        buf.put_u8(self.flags.bits());
        buf.put_u8(self.algo as u8);
        match self.sid {
            Sid::Index(index) => buf.put_u32(index),
            Sid::Label(label) => buf.put_u24(label.get()),
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + 2
            + match self.sid {
                Sid::Index(_) => 4,
                Sid::Label(_) => 3,
            }
    }
}

// ===== impl BierInfoStlv =====

impl BierInfoStlv {
    const MIN_SIZE: usize = 5;

    pub(crate) fn decode(stlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        if stlv_len < Self::MIN_SIZE as u8 {
            return Err(DecodeError::InvalidTlvLength(stlv_len));
        }
        let bar = buf.get_u8();
        let ipa = buf.get_u8();
        let sub_domain_id = buf.get_u8();
        let bfr_id = buf.get_u16();

        let mut subtlvs: Vec<BierSubStlv> = Vec::new();

        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse Stlv type.
            let stlv_type = buf.get_u8();
            let stlv_etype = BierSubStlvType::from_u8(stlv_type);

            // Parse and validate Stlv length.
            let stlv_len = buf.get_u8();
            if stlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse Stlv value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
            match stlv_etype {
                Some(
                    BierSubStlvType::MplsEncap | BierSubStlvType::NonMplsEncap,
                ) => {
                    let max_si = buf_stlv.get_u8();
                    let id = buf_stlv.get_u24();
                    let bs_len = ((id >> 20) & 0xf) as u8;
                    let id = match stlv_etype.unwrap() {
                        BierSubStlvType::MplsEncap => {
                            BierEncapId::Mpls(Label::new(id))
                        }
                        BierSubStlvType::NonMplsEncap => {
                            BierEncapId::NonMpls(BiftId::new(id))
                        }
                    };
                    subtlvs.push(BierSubStlv::BierEncapSubStlv(
                        BierEncapSubStlv { max_si, bs_len, id },
                    ));
                }
                _ => {
                    // Igore unknown Sub-TLV
                    continue;
                }
            }
        }

        Ok(BierInfoStlv {
            bar,
            ipa,
            sub_domain_id,
            bfr_id,
            subtlvs,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, PrefixStlvType::BierInfo);
        buf.put_u8(self.bar);
        buf.put_u8(self.ipa);
        buf.put_u8(self.sub_domain_id);
        buf.put_u16(self.bfr_id);
        for subtlv in &self.subtlvs {
            match subtlv {
                BierSubStlv::BierEncapSubStlv(encap) => {
                    let stlv_type = match encap.id {
                        BierEncapId::NonMpls(_) => {
                            BierSubStlvType::NonMplsEncap
                        }
                        BierEncapId::Mpls(_) => BierSubStlvType::MplsEncap,
                    };
                    let start_pos = tlv_encode_start(buf, stlv_type);
                    buf.put_u8(encap.max_si);
                    buf.put_u24(
                        (encap.id.clone().get() & 0x0fffff)
                            | ((encap.bs_len as u32 | 0xf) << 20),
                    );
                    tlv_encode_end(buf, start_pos);
                }
            }
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + Self::MIN_SIZE
            + self
                .subtlvs
                .iter()
                .map(|stlv| match stlv {
                    BierSubStlv::BierEncapSubStlv(_) => 6,
                })
                .sum::<usize>()
    }
}
