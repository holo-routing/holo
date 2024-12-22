//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

#![allow(clippy::match_single_binding)]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::{AddressFamily, Ipv4AddrExt, Ipv6AddrExt};
use ipnetwork::{Ipv4Network, Ipv6Network};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

use crate::packet::consts::{NeighborSubTlvType, PrefixSubTlvType, TlvType};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::{AreaAddr, LanId, LspId};

// TLV header size.
pub const TLV_HDR_SIZE: usize = 2;
// TLV maximum length.
pub const TLV_MAX_LEN: usize = 255;

// Network Layer Protocol IDs.
pub enum Nlpid {
    Ipv4 = 0xCC,
    Ipv6 = 0x8E,
}

// Trait for all TLVs.
pub trait Tlv {
    // Return the length of TLV.
    fn len(&self) -> usize;
}

// Trait for TLVs that might span across multiple instances.
pub trait MultiTlv: From<Vec<Self::Entry>> {
    type Entry;
    const FIXED_FIELDS_LEN: usize = 0;

    // Return an iterator over the TLV entries.
    fn entries(&self) -> impl Iterator<Item = &Self::Entry>;

    // Return the length of a given entry.
    fn entry_len(entry: &Self::Entry) -> usize;

    // Return the length of TLV.
    fn len(&self) -> usize {
        TLV_HDR_SIZE
            + Self::FIXED_FIELDS_LEN
            + self.entries().map(Self::entry_len).sum::<usize>()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AreaAddressesTlv {
    pub list: Vec<AreaAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct NeighborsTlv {
    pub list: Vec<[u8; 6]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PaddingTlv {
    pub length: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ProtocolsSupportedTlv {
    pub list: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4AddressesTlv {
    pub list: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6AddressesTlv {
    pub list: Vec<Ipv6Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspEntriesTlv {
    pub list: Vec<LspEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspEntry {
    pub rem_lifetime: u16,
    pub lsp_id: LspId,
    pub seqno: u32,
    pub cksum: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct IsReachTlv {
    pub list: Vec<IsReach>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct IsReach {
    pub metric: u8,
    pub metric_delay: Option<u8>,
    pub metric_expense: Option<u8>,
    pub metric_error: Option<u8>,
    pub neighbor: LanId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReachTlv {
    pub list: Vec<ExtIsReach>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReach {
    pub neighbor: LanId,
    pub metric: u32,
    pub sub_tlvs: ExtIsReachSubTlvs,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReachSubTlvs {
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4ReachTlv {
    pub list: Vec<Ipv4Reach>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4Reach {
    pub ie_bit: bool,
    pub metric: u8,
    pub metric_delay: Option<u8>,
    pub metric_expense: Option<u8>,
    pub metric_error: Option<u8>,
    pub prefix: Ipv4Network,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIpv4ReachTlv {
    pub list: Vec<ExtIpv4Reach>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIpv4Reach {
    pub metric: u32,
    pub up_down: bool,
    pub prefix: Ipv4Network,
    pub sub_tlvs: ExtIpv4ReachSubTlvs,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIpv4ReachSubTlvs {
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6ReachTlv {
    pub list: Vec<Ipv6Reach>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6Reach {
    pub metric: u32,
    pub up_down: bool,
    pub external: bool,
    pub prefix: Ipv6Network,
    pub sub_tlvs: Ipv6ReachSubTlvs,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6ReachSubTlvs {
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UnknownTlv {
    pub tlv_type: u8,
    pub length: u8,
    pub value: Bytes,
}

// ===== impl Nlpid =====

impl From<AddressFamily> for Nlpid {
    fn from(af: AddressFamily) -> Nlpid {
        match af {
            AddressFamily::Ipv4 => Nlpid::Ipv4,
            AddressFamily::Ipv6 => Nlpid::Ipv6,
        }
    }
}

// ===== impl AreaAddressesTlv =====

impl AreaAddressesTlv {
    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        while buf.remaining() >= 1 {
            // Parse area address length.
            let addr_len = buf.get_u8();

            // Sanity checks.
            if addr_len > AreaAddr::MAX_LEN {
                return Err(DecodeError::InvalidAreaAddrLen(addr_len));
            }
            if addr_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse area address.
            let addr = buf.copy_to_bytes(addr_len as usize);
            list.push(AreaAddr::from(addr.as_ref()));
        }

        Ok(AreaAddressesTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::AreaAddresses);
        for entry in &self.list {
            buf.put_u8(entry.as_ref().len() as _);
            buf.put_slice(entry.as_ref());
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for AreaAddressesTlv {
    type Entry = AreaAddr;

    fn entries(&self) -> impl Iterator<Item = &AreaAddr> {
        self.list.iter()
    }

    fn entry_len(entry: &AreaAddr) -> usize {
        1 + entry.as_ref().len()
    }
}

impl<I> From<I> for AreaAddressesTlv
where
    I: IntoIterator<Item = AreaAddr>,
{
    fn from(iter: I) -> AreaAddressesTlv {
        AreaAddressesTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl NeighborsTlv =====

impl NeighborsTlv {
    const MAC_ADDR_LEN: usize = 6;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Self::MAC_ADDR_LEN != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Self::MAC_ADDR_LEN {
            // Parse MAC address.
            let mut addr: [u8; Self::MAC_ADDR_LEN] = [0; Self::MAC_ADDR_LEN];
            buf.copy_to_slice(&mut addr);
            list.push(addr);
        }

        Ok(NeighborsTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Neighbors);
        for entry in &self.list {
            buf.put_slice(entry);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for NeighborsTlv {
    type Entry = [u8; 6];

    fn entries(&self) -> impl Iterator<Item = &[u8; 6]> {
        self.list.iter()
    }

    fn entry_len(_entry: &[u8; 6]) -> usize {
        Self::MAC_ADDR_LEN
    }
}

impl<I> From<I> for NeighborsTlv
where
    I: IntoIterator<Item = [u8; 6]>,
{
    fn from(iter: I) -> NeighborsTlv {
        NeighborsTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl PaddingTlv =====

impl PaddingTlv {
    const PADDING: [u8; 255] = [0; 255];

    pub(crate) fn decode(tlv_len: u8, _buf: &mut Bytes) -> DecodeResult<Self> {
        // Ignore padding data.
        Ok(PaddingTlv { length: tlv_len })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Padding);
        buf.put_slice(&Self::PADDING[0..self.length as usize]);
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl ProtocolsSupportedTlv =====

impl ProtocolsSupportedTlv {
    pub(crate) fn decode(_tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        while buf.remaining() >= 1 {
            let proto = buf.get_u8();
            list.push(proto);
        }

        Ok(ProtocolsSupportedTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::ProtocolsSupported);
        for entry in &self.list {
            buf.put_u8(*entry);
        }
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn contains(&self, protocol: Nlpid) -> bool {
        self.list.contains(&(protocol as u8))
    }
}

impl Tlv for ProtocolsSupportedTlv {
    fn len(&self) -> usize {
        TLV_HDR_SIZE + self.list.len()
    }
}

impl<I> From<I> for ProtocolsSupportedTlv
where
    I: IntoIterator<Item = u8>,
{
    fn from(iter: I) -> ProtocolsSupportedTlv {
        ProtocolsSupportedTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl Ipv4AddressesTlv =====

impl Ipv4AddressesTlv {
    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Ipv4Addr::LENGTH != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Ipv4Addr::LENGTH {
            // Parse IPv4 address.
            let addr = buf.get_ipv4();
            list.push(addr);
        }

        Ok(Ipv4AddressesTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Ipv4Addresses);
        for entry in &self.list {
            buf.put_ipv4(entry);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for Ipv4AddressesTlv {
    type Entry = Ipv4Addr;

    fn entries(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.list.iter()
    }

    fn entry_len(_entry: &Ipv4Addr) -> usize {
        Ipv4Addr::LENGTH
    }
}

impl<I> From<I> for Ipv4AddressesTlv
where
    I: IntoIterator<Item = Ipv4Addr>,
{
    fn from(iter: I) -> Ipv4AddressesTlv {
        Ipv4AddressesTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl Ipv6AddressesTlv =====

impl Ipv6AddressesTlv {
    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Ipv6Addr::LENGTH != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Ipv6Addr::LENGTH {
            // Parse IPv6 address.
            let addr = buf.get_ipv6();
            list.push(addr);
        }

        Ok(Ipv6AddressesTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Ipv6Addresses);
        for entry in &self.list {
            buf.put_ipv6(entry);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for Ipv6AddressesTlv {
    type Entry = Ipv6Addr;

    fn entries(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.list.iter()
    }

    fn entry_len(_entry: &Ipv6Addr) -> usize {
        Ipv6Addr::LENGTH
    }
}

impl<I> From<I> for Ipv6AddressesTlv
where
    I: IntoIterator<Item = Ipv6Addr>,
{
    fn from(iter: I) -> Ipv6AddressesTlv {
        Ipv6AddressesTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl LspEntriesTlv =====

impl LspEntriesTlv {
    pub const ENTRY_SIZE: usize = 16;
    pub const MAX_ENTRIES: usize = TLV_MAX_LEN / Self::ENTRY_SIZE;
    pub const MAX_SIZE: usize = TLV_MAX_LEN - Self::MAX_ENTRIES;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Self::ENTRY_SIZE != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Self::ENTRY_SIZE {
            let rem_lifetime = buf.get_u16();
            let lsp_id = LspId::decode(buf);
            let seqno = buf.get_u32();
            let cksum = buf.get_u16();

            let entry = LspEntry {
                rem_lifetime,
                lsp_id,
                cksum,
                seqno,
            };
            list.push(entry);
        }

        Ok(LspEntriesTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::LspEntries);
        for entry in &self.list {
            buf.put_u16(entry.rem_lifetime);
            entry.lsp_id.encode(buf);
            buf.put_u32(entry.seqno);
            buf.put_u16(entry.cksum);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for LspEntriesTlv {
    type Entry = LspEntry;

    fn entries(&self) -> impl Iterator<Item = &LspEntry> {
        self.list.iter()
    }

    fn entry_len(_entry: &LspEntry) -> usize {
        Self::ENTRY_SIZE
    }
}

impl<I> From<I> for LspEntriesTlv
where
    I: IntoIterator<Item = LspEntry>,
{
    fn from(iter: I) -> LspEntriesTlv {
        LspEntriesTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl IsReachTlv =====

impl IsReachTlv {
    const ENTRY_SIZE: usize = 11;
    const METRIC_S_BIT: u8 = 0x80;
    const METRIC_MASK: u8 = 0x3F;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if (tlv_len - 1) as usize % Self::ENTRY_SIZE != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let _virtual_flag = buf.get_u8();
        while buf.remaining() >= Self::ENTRY_SIZE {
            let metric = buf.get_u8();
            let metric = metric & Self::METRIC_MASK;
            let metric_delay = buf.get_u8();
            let metric_delay = (metric_delay & Self::METRIC_S_BIT == 0)
                .then_some(metric_delay & Self::METRIC_MASK);
            let metric_expense = buf.get_u8();
            let metric_expense = (metric_expense & Self::METRIC_S_BIT == 0)
                .then_some(metric_expense & Self::METRIC_MASK);
            let metric_error = buf.get_u8();
            let metric_error = (metric_error & Self::METRIC_S_BIT == 0)
                .then_some(metric_error & Self::METRIC_MASK);
            let neighbor = LanId::decode(buf);

            let entry = IsReach {
                metric,
                metric_delay,
                metric_expense,
                metric_error,
                neighbor,
            };
            list.push(entry);
        }

        Ok(IsReachTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::IsReach);
        // Virtual Flag - Used by partition repair (unsupported).
        buf.put_u8(0);
        for entry in &self.list {
            buf.put_u8(entry.metric);
            buf.put_u8(entry.metric_delay.unwrap_or(Self::METRIC_S_BIT));
            buf.put_u8(entry.metric_expense.unwrap_or(Self::METRIC_S_BIT));
            buf.put_u8(entry.metric_error.unwrap_or(Self::METRIC_S_BIT));
            entry.neighbor.encode(buf);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for IsReachTlv {
    type Entry = IsReach;
    const FIXED_FIELDS_LEN: usize = 1;

    fn entries(&self) -> impl Iterator<Item = &IsReach> {
        self.list.iter()
    }

    fn entry_len(_entry: &IsReach) -> usize {
        Self::ENTRY_SIZE
    }
}

impl<I> From<I> for IsReachTlv
where
    I: IntoIterator<Item = IsReach>,
{
    fn from(iter: I) -> IsReachTlv {
        IsReachTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl ExtIsReachTlv =====

impl ExtIsReachTlv {
    const ENTRY_MIN_SIZE: usize = 11;

    pub(crate) fn decode(_tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        while buf.remaining() >= Self::ENTRY_MIN_SIZE {
            let neighbor = LanId::decode(buf);
            let metric = buf.get_u24();

            // Parse Sub-TLVs.
            let mut sub_tlvs = ExtIsReachSubTlvs::default();
            let mut sub_tlvs_len = buf.get_u8();
            while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                // Parse TLV type.
                let stlv_type = buf.get_u8();
                sub_tlvs_len -= 1;
                let stlv_etype = NeighborSubTlvType::from_u8(stlv_type);

                // Parse and validate TLV length.
                let stlv_len = buf.get_u8();
                sub_tlvs_len -= 1;
                if stlv_len as usize > buf.remaining() {
                    return Err(DecodeError::InvalidTlvLength(stlv_len));
                }

                // Parse TLV value.
                let mut buf_tlv = buf.copy_to_bytes(stlv_len as usize);
                sub_tlvs_len -= stlv_len;
                match stlv_etype {
                    _ => {
                        // Save unknown top-level TLV.
                        let value = buf_tlv.copy_to_bytes(stlv_len as usize);
                        sub_tlvs
                            .unknown
                            .push(UnknownTlv::new(stlv_type, stlv_len, value));
                    }
                }
            }

            list.push(ExtIsReach {
                neighbor,
                metric,
                sub_tlvs,
            });
        }

        Ok(ExtIsReachTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::ExtIsReach);
        for entry in &self.list {
            // Encode neighbor ID.
            entry.neighbor.encode(buf);
            // Encode metric.
            buf.put_u24(entry.metric);
            // Encode Sub-TLVs.
            buf.put_u8(0);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for ExtIsReachTlv {
    type Entry = ExtIsReach;

    fn entries(&self) -> impl Iterator<Item = &ExtIsReach> {
        self.list.iter()
    }

    fn entry_len(_entry: &ExtIsReach) -> usize {
        Self::ENTRY_MIN_SIZE
    }
}

impl<I> From<I> for ExtIsReachTlv
where
    I: IntoIterator<Item = ExtIsReach>,
{
    fn from(iter: I) -> ExtIsReachTlv {
        ExtIsReachTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl Ipv4ReachTlv =====

impl Ipv4ReachTlv {
    const ENTRY_SIZE: usize = 12;
    const METRIC_S_BIT: u8 = 0x80;
    const METRIC_IE_BIT: u8 = 0x80;
    const METRIC_MASK: u8 = 0x3F;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Self::ENTRY_SIZE != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Self::ENTRY_SIZE {
            let metric = buf.get_u8();
            let ie_bit = metric & Self::METRIC_IE_BIT != 0;
            let metric = metric & Self::METRIC_MASK;
            let metric_delay = buf.get_u8();
            let metric_delay = (metric_delay & Self::METRIC_S_BIT == 0)
                .then_some(metric_delay & Self::METRIC_MASK);
            let metric_expense = buf.get_u8();
            let metric_expense = (metric_expense & Self::METRIC_S_BIT == 0)
                .then_some(metric_expense & Self::METRIC_MASK);
            let metric_error = buf.get_u8();
            let metric_error = (metric_error & Self::METRIC_S_BIT == 0)
                .then_some(metric_error & Self::METRIC_MASK);
            let addr = buf.get_ipv4();
            let mask = buf.get_ipv4();
            // Ignore prefixes with non-contiguous subnet masks.
            let Ok(prefix) = Ipv4Network::with_netmask(addr, mask) else {
                continue;
            };

            let entry = Ipv4Reach {
                ie_bit,
                metric,
                metric_delay,
                metric_expense,
                metric_error,
                prefix,
            };
            list.push(entry);
        }

        Ok(Ipv4ReachTlv { list })
    }

    pub(crate) fn encode(&self, tlv_type: TlvType, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, tlv_type);
        for entry in &self.list {
            let mut metric = entry.metric;
            if entry.ie_bit {
                metric |= Self::METRIC_IE_BIT;
            }
            buf.put_u8(metric);
            buf.put_u8(entry.metric_delay.unwrap_or(Self::METRIC_S_BIT));
            buf.put_u8(entry.metric_expense.unwrap_or(Self::METRIC_S_BIT));
            buf.put_u8(entry.metric_error.unwrap_or(Self::METRIC_S_BIT));
            buf.put_ipv4(&entry.prefix.ip());
            buf.put_ipv4(&entry.prefix.mask());
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for Ipv4ReachTlv {
    type Entry = Ipv4Reach;

    fn entries(&self) -> impl Iterator<Item = &Ipv4Reach> {
        self.list.iter()
    }

    fn entry_len(_entry: &Ipv4Reach) -> usize {
        Self::ENTRY_SIZE
    }
}

impl<I> From<I> for Ipv4ReachTlv
where
    I: IntoIterator<Item = Ipv4Reach>,
{
    fn from(iter: I) -> Ipv4ReachTlv {
        Ipv4ReachTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl Ipv4Reach =====

impl Ipv4Reach {
    // Returns the metric associated with the IP prefix.
    pub(crate) fn metric(&self) -> u32 {
        let mut metric = self.metric;

        // RFC 3787 - Section 5:
        // "We interpret the default metric as an 7 bit quantity. Metrics
        // with the external bit set are interpreted as metrics in the range
        // [64..127]. Metrics with the external bit clear are interpreted as
        // metrics in the range [0..63]".
        if self.ie_bit {
            metric += 64;
        }

        metric.into()
    }
}

// ===== impl ExtIpv4ReachTlv =====

impl ExtIpv4ReachTlv {
    const ENTRY_MIN_SIZE: usize = 5;
    const CONTROL_UPDOWN_BIT: u8 = 0x80;
    const CONTROL_SUBTLVS: u8 = 0x40;
    const CONTROL_PLEN_MASK: u8 = 0x3F;

    pub(crate) fn decode(_tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        while buf.remaining() >= Self::ENTRY_MIN_SIZE {
            // Parse metric.
            let metric = buf.get_u32();

            // Parse control field.
            let control = buf.get_u8();
            let up_down = (control & Self::CONTROL_UPDOWN_BIT) != 0;
            let subtlvs = (control & Self::CONTROL_SUBTLVS) != 0;
            let plen = control & Self::CONTROL_PLEN_MASK;

            // Parse prefix (variable length).
            let mut prefix_bytes = [0; Ipv4Addr::LENGTH];
            let plen_wire = prefix_wire_len(plen);
            buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
            let prefix = Ipv4Addr::from(prefix_bytes);

            // Parse Sub-TLVs.
            let mut sub_tlvs = ExtIpv4ReachSubTlvs::default();
            if subtlvs {
                let mut sub_tlvs_len = buf.get_u8();
                while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                    // Parse TLV type.
                    let stlv_type = buf.get_u8();
                    sub_tlvs_len -= 1;
                    let stlv_etype = PrefixSubTlvType::from_u8(stlv_type);

                    // Parse and validate TLV length.
                    let stlv_len = buf.get_u8();
                    sub_tlvs_len -= 1;
                    if stlv_len as usize > buf.remaining() {
                        return Err(DecodeError::InvalidTlvLength(stlv_len));
                    }

                    // Parse TLV value.
                    let mut buf_tlv = buf.copy_to_bytes(stlv_len as usize);
                    sub_tlvs_len -= stlv_len;
                    match stlv_etype {
                        _ => {
                            // Save unknown top-level TLV.
                            let value =
                                buf_tlv.copy_to_bytes(stlv_len as usize);
                            sub_tlvs.unknown.push(UnknownTlv::new(
                                stlv_type, stlv_len, value,
                            ));
                        }
                    }
                }
            }

            // Ignore malformed prefixes.
            let Ok(prefix) = Ipv4Network::new(prefix, plen) else {
                continue;
            };

            list.push(ExtIpv4Reach {
                metric,
                up_down,
                prefix,
                sub_tlvs,
            });
        }

        Ok(ExtIpv4ReachTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::ExtIpv4Reach);
        for entry in &self.list {
            // Encode metric.
            buf.put_u32(entry.metric);

            // Encode control field.
            let plen = entry.prefix.prefix();
            let mut control = 0;
            if entry.up_down {
                control |= Self::CONTROL_UPDOWN_BIT;
            }
            control |= plen;
            buf.put_u8(control);

            // Encode prefix (variable length).
            let plen_wire = prefix_wire_len(plen);
            buf.put(&entry.prefix.ip().octets()[0..plen_wire]);

            // Encode Sub-TLVs.
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for ExtIpv4ReachTlv {
    type Entry = ExtIpv4Reach;

    fn entries(&self) -> impl Iterator<Item = &ExtIpv4Reach> {
        self.list.iter()
    }

    fn entry_len(entry: &ExtIpv4Reach) -> usize {
        let plen = entry.prefix.prefix();
        Self::ENTRY_MIN_SIZE + prefix_wire_len(plen)
    }
}

impl<I> From<I> for ExtIpv4ReachTlv
where
    I: IntoIterator<Item = ExtIpv4Reach>,
{
    fn from(iter: I) -> ExtIpv4ReachTlv {
        ExtIpv4ReachTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== impl Ipv6ReachTlv =====

impl Ipv6ReachTlv {
    const ENTRY_MIN_SIZE: usize = 6;
    const FLAG_UPDOWN: u8 = 0x80;
    const FLAG_EXTERNAL: u8 = 0x40;
    const FLAG_SUBTLVS: u8 = 0x20;

    pub(crate) fn decode(_tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        let mut list = vec![];

        while buf.remaining() >= Self::ENTRY_MIN_SIZE {
            // Parse metric.
            let metric = buf.get_u32();

            // Parse flags field.
            let flags = buf.get_u8();
            let up_down = (flags & Self::FLAG_UPDOWN) != 0;
            let external = (flags & Self::FLAG_EXTERNAL) != 0;
            let subtlvs = (flags & Self::FLAG_SUBTLVS) != 0;

            // Parse prefix length.
            let plen = buf.get_u8();

            // Parse prefix (variable length).
            let mut prefix_bytes = [0; Ipv6Addr::LENGTH];
            let plen_wire = prefix_wire_len(plen);
            buf.copy_to_slice(&mut prefix_bytes[..plen_wire]);
            let prefix = Ipv6Addr::from(prefix_bytes);

            // Parse Sub-TLVs.
            let mut sub_tlvs = Ipv6ReachSubTlvs::default();
            if subtlvs {
                let mut sub_tlvs_len = buf.get_u8();
                while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                    // Parse TLV type.
                    let stlv_type = buf.get_u8();
                    sub_tlvs_len -= 1;
                    let stlv_etype = PrefixSubTlvType::from_u8(stlv_type);

                    // Parse and validate TLV length.
                    let stlv_len = buf.get_u8();
                    sub_tlvs_len -= 1;
                    if stlv_len as usize > buf.remaining() {
                        return Err(DecodeError::InvalidTlvLength(stlv_len));
                    }

                    // Parse TLV value.
                    let mut buf_tlv = buf.copy_to_bytes(stlv_len as usize);
                    sub_tlvs_len -= stlv_len;
                    match stlv_etype {
                        _ => {
                            // Save unknown top-level TLV.
                            let value =
                                buf_tlv.copy_to_bytes(stlv_len as usize);
                            sub_tlvs.unknown.push(UnknownTlv::new(
                                stlv_type, stlv_len, value,
                            ));
                        }
                    }
                }
            }

            // Ignore malformed prefixes.
            let Ok(prefix) = Ipv6Network::new(prefix, plen) else {
                continue;
            };

            list.push(Ipv6Reach {
                metric,
                up_down,
                external,
                prefix,
                sub_tlvs,
            });
        }

        Ok(Ipv6ReachTlv { list })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Ipv6Reach);
        for entry in &self.list {
            // Encode metric.
            buf.put_u32(entry.metric);

            // Encode flags field.
            let mut flags = 0;
            if entry.up_down {
                flags |= Self::FLAG_UPDOWN;
            }
            if entry.external {
                flags |= Self::FLAG_EXTERNAL;
            }
            buf.put_u8(flags);

            // Encode prefix length.
            let plen = entry.prefix.prefix();
            buf.put_u8(plen);

            // Encode prefix (variable length).
            let plen_wire = prefix_wire_len(plen);
            buf.put(&entry.prefix.ip().octets()[0..plen_wire]);

            // Encode Sub-TLVs.
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl MultiTlv for Ipv6ReachTlv {
    type Entry = Ipv6Reach;

    fn entries(&self) -> impl Iterator<Item = &Ipv6Reach> {
        self.list.iter()
    }

    fn entry_len(entry: &Ipv6Reach) -> usize {
        let plen = entry.prefix.prefix();
        Self::ENTRY_MIN_SIZE + prefix_wire_len(plen)
    }
}

impl<I> From<I> for Ipv6ReachTlv
where
    I: IntoIterator<Item = Ipv6Reach>,
{
    fn from(iter: I) -> Ipv6ReachTlv {
        Ipv6ReachTlv {
            list: iter.into_iter().collect(),
        }
    }
}

// ===== blanket implementations =====

impl<T: MultiTlv> Tlv for T {
    fn len(&self) -> usize {
        self.len()
    }
}

// ===== helper functions =====

// Calculates the number of bytes required to encode a prefix.
const fn prefix_wire_len(len: u8) -> usize {
    (len as usize + 7) / 8
}

fn tlv_encode_start(buf: &mut BytesMut, tlv_type: impl ToPrimitive) -> usize {
    let start_pos = buf.len();
    buf.put_u8(tlv_type.to_u8().unwrap());
    // The TLV length will be rewritten later.
    buf.put_u8(0);
    start_pos
}

fn tlv_encode_end(buf: &mut BytesMut, start_pos: usize) {
    // Rewrite TLV length.
    buf[start_pos + 1] = (buf.len() - start_pos - TLV_HDR_SIZE) as u8;
}

// ===== global functions =====

// Takes as many TLVs as will fit into the provided PDU remaining length.
pub(crate) fn tlv_take_max<T>(
    tlv_list: &mut Vec<T>,
    rem_len: &mut usize,
) -> Vec<T>
where
    T: Tlv,
{
    let mut tlvs = Vec::new();
    let mut count = 0;

    if *rem_len == 0 {
        return tlvs;
    }

    for tlv in tlv_list.iter() {
        let tlv_len = tlv.len();
        if *rem_len >= tlv_len {
            *rem_len -= tlv_len;
            count += 1;
        } else {
            *rem_len = 0;
            break;
        }
    }

    tlvs.extend(tlv_list.drain(0..count));
    tlvs
}

// Splits a list of TLV entries into as many TLVs as necessary.
pub(crate) fn tlv_entries_split<T>(
    entries: impl IntoIterator<Item = T::Entry>,
) -> Vec<T>
where
    T: MultiTlv,
{
    let mut tlvs = vec![];
    let mut tlv_entries = vec![];
    let mut tlv_len = 0;

    for entry in entries {
        let entry_len = T::entry_len(&entry);
        if tlv_len + entry_len > (TLV_MAX_LEN - T::FIXED_FIELDS_LEN) {
            let tlv = T::from(std::mem::take(&mut tlv_entries));
            tlvs.push(tlv);
            tlv_len = 0;
            continue;
        }
        tlv_entries.push(entry);
        tlv_len += entry_len;
    }
    if !tlv_entries.is_empty() {
        let tlv = T::from(tlv_entries);
        tlvs.push(tlv);
    }

    tlvs.shrink_to_fit();
    tlvs
}
