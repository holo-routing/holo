//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::consts::{LabelBindingStlvType, RouterCapStlvType};
use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::tlv::{
    TLV_HDR_SIZE, TLV_MAX_LEN, tlv_encode_end, tlv_encode_start,
};

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SrCapabilitiesStlv {
    pub flags: SrCapabilitiesFlags,
    pub srgb_entries: Vec<LabelBlockEntry>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct SrCapabilitiesFlags: u8 {
        const I = 0x80;
        const V = 0x40;
    }
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SrAlgoStlv(BTreeSet<IgpAlgoType>);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SrLocalBlockStlv {
    pub entries: Vec<LabelBlockEntry>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct LabelBlockEntry {
    pub range: u32,
    pub first: Sid,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct NodeAdminTagStlv(BTreeSet<u32>);

// ===== impl SrCapabilitiesStlv =====

impl SrCapabilitiesStlv {
    const MIN_SIZE: usize = 1;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags = buf.try_get_u8()?;
        let flags = SrCapabilitiesFlags::from_bits_truncate(flags);
        let mut srgb_entries = vec![];
        while buf.remaining() >= 1 {
            let entry = LabelBlockEntry::decode(buf)?;
            srgb_entries.push(entry);
        }

        Ok(SrCapabilitiesStlv {
            flags,
            srgb_entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterCapStlvType::SrCapability);
        // Flags.
        buf.put_u8(self.flags.bits());
        // SRGB entries.
        for entry in &self.srgb_entries {
            entry.encode(buf);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + 1
            + self
                .srgb_entries
                .iter()
                .map(|entry| entry.len())
                .sum::<usize>()
    }
}

// ===== impl SrAlgoStlv =====

impl SrAlgoStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        let mut list = BTreeSet::new();
        for _ in 0..stlv_len {
            let algo = buf.try_get_u8()?;
            let Some(algo) = IgpAlgoType::from_u8(algo) else {
                // Unsupported algorithm - ignore.
                continue;
            };
            list.insert(algo);
        }

        // TODO: return an error if algorithm 0 isn't present.

        Ok(SrAlgoStlv(list))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterCapStlvType::SrAlgorithm);
        for algo in &self.0 {
            buf.put_u8(*algo as u8);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + self.0.len()
    }

    pub(crate) fn get(&self) -> &BTreeSet<IgpAlgoType> {
        &self.0
    }
}

// ===== impl SrLocalBlockStlv =====

impl SrLocalBlockStlv {
    const MIN_SIZE: usize = 1;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let _flags = buf.try_get_u8()?;
        let mut entries = vec![];
        while buf.remaining() >= 1 {
            let entry = LabelBlockEntry::decode(buf)?;
            entries.push(entry);
        }

        Ok(SrLocalBlockStlv { entries })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterCapStlvType::SrLocalBlock);
        // Flags.
        buf.put_u8(0);
        // SRLB entries.
        for entry in &self.entries {
            entry.encode(buf);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + 1
            + self.entries.iter().map(|entry| entry.len()).sum::<usize>()
    }
}

// ===== impl LabelBlockEntry =====

impl LabelBlockEntry {
    pub(crate) fn decode(buf: &mut Bytes) -> TlvDecodeResult<Self> {
        let range = buf.try_get_u24()?;

        // Only the SID/Label sub-TLV is valid here.
        let stlv_type = buf.try_get_u8()?;
        if stlv_type != LabelBindingStlvType::SidLabel as u8 {
            return Err(TlvDecodeError::UnexpectedType(stlv_type));
        }
        let stlv_len = buf.try_get_u8()?;
        if stlv_len as usize > buf.remaining() {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }
        let first = match stlv_len {
            4 => Sid::Index(buf.try_get_u32()?),
            3 => {
                let label = buf.try_get_u24()? & Label::VALUE_MASK;
                Sid::Label(Label::new(label))
            }
            _ => {
                return Err(TlvDecodeError::InvalidLength(stlv_len));
            }
        };

        Ok(LabelBlockEntry { range, first })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u24(self.range);
        let start_pos = tlv_encode_start(buf, LabelBindingStlvType::SidLabel);
        match self.first {
            Sid::Index(index) => {
                buf.put_u32(index);
            }
            Sid::Label(label) => {
                buf.put_u24(label.get());
            }
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        3 + TLV_HDR_SIZE
            + match self.first {
                Sid::Index(_) => 4,
                Sid::Label(_) => 3,
            }
    }
}

// ===== impl NodeAdminTagStlv =====

impl NodeAdminTagStlv {
    pub const TAG_LEN: usize = 4;
    pub const MAX_ENTRIES: usize = TLV_MAX_LEN / Self::TAG_LEN;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if !(stlv_len as usize).is_multiple_of(Self::TAG_LEN) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut list = BTreeSet::new();
        while buf.remaining() >= Self::TAG_LEN {
            let tag = buf.try_get_u32()?;
            list.insert(tag);
        }

        Ok(NodeAdminTagStlv(list))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterCapStlvType::NodeAdminTag);
        for tag in &self.0 {
            buf.put_u32(*tag);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + self.0.len() * Self::TAG_LEN
    }

    pub(crate) fn get(&self) -> &BTreeSet<u32> {
        &self.0
    }
}
