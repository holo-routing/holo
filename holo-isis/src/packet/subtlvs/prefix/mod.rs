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
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::consts::{BierSubSubTlvType, PrefixSubTlvType};
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
pub struct PrefixAttrFlagsSubTlv(PrefixAttrFlags);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4SourceRidSubTlv(Ipv4Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6SourceRidSubTlv(Ipv6Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierInfoSubTlv {
    pub bar: u8,
    pub ipa: u8,
    pub sub_domain_id: u8,
    pub bfr_id: u16,
    pub subtlvs: Vec<BierSubSubTlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub enum BierSubSubTlv {
    BierEncapSubSubTlv(BierEncapSubSubTlv),
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct BierEncapSubSubTlv {
    pub max_si: u8,
    pub bs_len: u8,
    pub id: BierEncapId,
}

// ===== impl PrefixAttrFlagsSubTlv =====

impl PrefixAttrFlagsSubTlv {
    const SIZE: usize = 1;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // A TLV length of zero is permitted under RFC 7794.
        if tlv_len == 0 {
            return Ok(PrefixAttrFlagsSubTlv::default());
        }

        // Any remaining bits beyond the first byte are ignored.
        let flags = buf.get_u8();
        let flags = PrefixAttrFlags::from_bits_truncate(flags);

        Ok(PrefixAttrFlagsSubTlv(flags))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixSubTlvType::PrefixAttributeFlags);
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

// ===== impl Ipv4SourceRidSubTlv =====

impl Ipv4SourceRidSubTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(Ipv4SourceRidSubTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixSubTlvType::Ipv4SourceRouterId);
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

// ===== impl Ipv6SourceRidSubTlv =====

impl Ipv6SourceRidSubTlv {
    const SIZE: usize = 16;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv6();

        Ok(Ipv6SourceRidSubTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixSubTlvType::Ipv6SourceRouterId);
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

// ===== impl BierInfoSubTlv =====

impl BierInfoSubTlv {
    const MIN_SIZE: usize = 5;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len < Self::MIN_SIZE as u8 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let bar = buf.get_u8();
        let ipa = buf.get_u8();
        let sub_domain_id = buf.get_u8();
        let bfr_id = buf.get_u16();

        let mut subtlvs: Vec<BierSubSubTlv> = Vec::new();

        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse SubTlv type.
            let stlv_type = buf.get_u8();
            let stlv_etype = BierSubSubTlvType::from_u8(stlv_type);

            // Parse and validate SubTlv length.
            let stlv_len = buf.get_u8();
            if stlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse SubTlv value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
            match stlv_etype {
                Some(
                    BierSubSubTlvType::MplsEncap
                    | BierSubSubTlvType::NonMplsEncap,
                ) => {
                    let max_si = buf_stlv.get_u8();
                    let id = buf_stlv.get_u24();
                    let bs_len = ((id >> 20) & 0xf) as u8;
                    let id = match stlv_etype.unwrap() {
                        BierSubSubTlvType::MplsEncap => {
                            BierEncapId::Mpls(Label::new(id))
                        }
                        BierSubSubTlvType::NonMplsEncap => {
                            BierEncapId::NonMpls(BiftId::new(id))
                        }
                    };
                    subtlvs.push(BierSubSubTlv::BierEncapSubSubTlv(
                        BierEncapSubSubTlv { max_si, bs_len, id },
                    ));
                }
                _ => {
                    // Igore unknown Sub-TLV
                    continue;
                }
            }
        }

        Ok(BierInfoSubTlv {
            bar,
            ipa,
            sub_domain_id,
            bfr_id,
            subtlvs,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, PrefixSubTlvType::BierInfo);
        buf.put_u8(self.bar);
        buf.put_u8(self.ipa);
        buf.put_u8(self.sub_domain_id);
        buf.put_u16(self.bfr_id);
        for subtlv in &self.subtlvs {
            match subtlv {
                BierSubSubTlv::BierEncapSubSubTlv(encap) => {
                    let tlv_type = match encap.id {
                        BierEncapId::NonMpls(_) => {
                            BierSubSubTlvType::NonMplsEncap
                        }
                        BierEncapId::Mpls(_) => BierSubSubTlvType::MplsEncap,
                    };
                    let start_pos = tlv_encode_start(buf, tlv_type);
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
                    BierSubSubTlv::BierEncapSubSubTlv(_) => 6,
                })
                .sum::<usize>()
    }
}
