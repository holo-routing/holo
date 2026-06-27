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
use tracing::debug_span;

use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::iana::{
    FadFlags, FadStlvType, LabelBindingStlvType, PrefixStlvType,
    RouterCapStlvType,
};
use crate::packet::subtlvs::neighbor::ExtAdminGroupStlv;
use crate::packet::tlv::{
    TLV_HDR_SIZE, TLV_MAX_LEN, UnknownTlv, tlv_encode_end, tlv_encode_start,
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

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct FloodingAlgoStlv(u8);

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct FadStlv {
    pub flex_algo: u8,
    pub metric_type: u8,
    pub calc_type: u8,
    pub priority: u8,
    pub sub_tlvs: FadStlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct FadStlvs {
    pub exclude_admin_group: Option<ExtAdminGroupStlv>,
    pub include_any_admin_group: Option<ExtAdminGroupStlv>,
    pub include_all_admin_group: Option<ExtAdminGroupStlv>,
    pub flags: Option<FadFlagsStlv>,
    pub exclude_srlgs: Option<ExcludeSrlgsStlv>,
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct FadFlagsStlv(FadFlags);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct ExcludeSrlgsStlv(Vec<u32>);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct FapmStlv {
    pub flex_algo: u8,
    pub metric: u32,
}

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
        if range == 0 {
            return Err(TlvDecodeError::ZeroLabelBlockRange);
        }

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

        // Sanity checks.
        if let Sid::Label(label) = &first {
            if label.is_reserved() {
                return Err(TlvDecodeError::LabelBlockReservedFirstLabel(
                    *label,
                ));
            }
            let last = label.get().saturating_add(range - 1);
            if last > *Label::UNRESERVED_RANGE.end() {
                return Err(TlvDecodeError::LabelBlockRangeOverflow(
                    *label, range,
                ));
            }
        }

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

// ===== impl FloodingAlgoStlv =====

impl FloodingAlgoStlv {
    pub const SIZE: usize = 1;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate the TLV length.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let algo = buf.try_get_u8()?;
        Ok(FloodingAlgoStlv(algo))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, RouterCapStlvType::FloodingAlgo);
        buf.put_u8(self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    pub(crate) fn get(&self) -> u8 {
        self.0
    }
}

// ===== impl FadStlv =====

impl FadStlv {
    const FIXED_SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if (stlv_len as usize) < Self::FIXED_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flex_algo = buf.try_get_u8()?;
        let metric_type = buf.try_get_u8()?;
        let calc_type = buf.try_get_u8()?;
        let priority = buf.try_get_u8()?;

        let mut sub_tlvs = FadStlvs::default();
        while buf.remaining() >= TLV_HDR_SIZE {
            let sstlv_type = buf.try_get_u8()?;
            let sstlv_etype = FadStlvType::from_u8(sstlv_type);

            let sstlv_len = buf.try_get_u8()?;
            if sstlv_len as usize > buf.remaining() {
                return Err(TlvDecodeError::InvalidLength(sstlv_len));
            }

            let span = debug_span!(
                "sub-sub-TLV",
                r#type = sstlv_type,
                length = sstlv_len
            );
            let _span_guard = span.enter();
            let mut buf_sstlv = buf.copy_to_bytes(sstlv_len as usize);
            match sstlv_etype {
                Some(FadStlvType::ExcludeAdminGroup) => {
                    if sub_tlvs.exclude_admin_group.is_some() {
                        continue;
                    }
                    match ExtAdminGroupStlv::decode(sstlv_len, &mut buf_sstlv) {
                        Ok(stlv) => sub_tlvs.exclude_admin_group = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(FadStlvType::IncludeAnyAdminGroup) => {
                    if sub_tlvs.include_any_admin_group.is_some() {
                        continue;
                    }
                    match ExtAdminGroupStlv::decode(sstlv_len, &mut buf_sstlv) {
                        Ok(stlv) => {
                            sub_tlvs.include_any_admin_group = Some(stlv)
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(FadStlvType::IncludeAllAdminGroup) => {
                    if sub_tlvs.include_all_admin_group.is_some() {
                        continue;
                    }
                    match ExtAdminGroupStlv::decode(sstlv_len, &mut buf_sstlv) {
                        Ok(stlv) => {
                            sub_tlvs.include_all_admin_group = Some(stlv)
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(FadStlvType::Flags) => {
                    if sub_tlvs.flags.is_some() {
                        continue;
                    }
                    match FadFlagsStlv::decode(sstlv_len, &mut buf_sstlv) {
                        Ok(stlv) => sub_tlvs.flags = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                Some(FadStlvType::ExcludeSrlg) => {
                    if sub_tlvs.exclude_srlgs.is_some() {
                        continue;
                    }
                    match ExcludeSrlgsStlv::decode(sstlv_len, &mut buf_sstlv) {
                        Ok(stlv) => sub_tlvs.exclude_srlgs = Some(stlv),
                        Err(error) => error.log(),
                    }
                }
                _ => {
                    sub_tlvs.unknown.push(UnknownTlv::new(
                        sstlv_type, sstlv_len, buf_sstlv,
                    ));
                }
            }
        }

        Ok(FadStlv {
            flex_algo,
            metric_type,
            calc_type,
            priority,
            sub_tlvs,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, RouterCapStlvType::FlexAlgoDefinition);
        buf.put_u8(self.flex_algo);
        buf.put_u8(self.metric_type);
        buf.put_u8(self.calc_type);
        buf.put_u8(self.priority);
        if let Some(stlv) = &self.sub_tlvs.exclude_admin_group {
            stlv.encode(FadStlvType::ExcludeAdminGroup, buf);
        }
        if let Some(stlv) = &self.sub_tlvs.include_any_admin_group {
            stlv.encode(FadStlvType::IncludeAnyAdminGroup, buf);
        }
        if let Some(stlv) = &self.sub_tlvs.include_all_admin_group {
            stlv.encode(FadStlvType::IncludeAllAdminGroup, buf);
        }
        if let Some(stlv) = &self.sub_tlvs.flags {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.sub_tlvs.exclude_srlgs {
            stlv.encode(buf);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        let mut len = TLV_HDR_SIZE + Self::FIXED_SIZE;
        if let Some(stlv) = &self.sub_tlvs.exclude_admin_group {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.include_any_admin_group {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.include_all_admin_group {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.flags {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.exclude_srlgs {
            len += stlv.len();
        }
        len
    }
}

// ===== impl FadFlagsStlv =====

impl FadFlagsStlv {
    const SIZE: usize = 1;

    pub(crate) fn decode(
        sstlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if sstlv_len == 0 {
            return Ok(FadFlagsStlv(FadFlags::from_bits_truncate(0)));
        }
        let flags = buf.try_get_u8()?;
        Ok(FadFlagsStlv(FadFlags::from_bits_retain(flags)))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start = tlv_encode_start(buf, FadStlvType::Flags);
        buf.put_u8(self.0.bits());
        tlv_encode_end(buf, start);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    pub(crate) fn get(&self) -> FadFlags {
        self.0
    }
}

// ===== impl ExcludeSrlgsStlv =====

impl ExcludeSrlgsStlv {
    const SRLG_LEN: usize = 4;

    pub(crate) fn decode(
        sstlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if sstlv_len == 0
            || !(sstlv_len as usize).is_multiple_of(Self::SRLG_LEN)
        {
            return Err(TlvDecodeError::InvalidLength(sstlv_len));
        }
        let mut srlgs = Vec::new();
        while buf.remaining() >= Self::SRLG_LEN {
            let srlg = buf.try_get_u32()?;
            srlgs.push(srlg);
        }
        Ok(ExcludeSrlgsStlv(srlgs))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start = tlv_encode_start(buf, FadStlvType::ExcludeSrlg);
        for srlg in &self.0 {
            buf.put_u32(*srlg);
        }
        tlv_encode_end(buf, start);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + self.0.len() * Self::SRLG_LEN
    }

    pub(crate) fn get(&self) -> &[u32] {
        &self.0
    }
}

// ===== impl FapmStlv =====

impl FapmStlv {
    const SIZE: usize = 5;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flex_algo = buf.try_get_u8()?;
        let metric = buf.try_get_u32()?;

        Ok(FapmStlv { flex_algo, metric })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, PrefixStlvType::FlexAlgoPrefixMetric);
        buf.put_u8(self.flex_algo);
        buf.put_u32(self.metric);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }
}
