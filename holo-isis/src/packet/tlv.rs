//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

#![allow(clippy::len_without_is_empty, clippy::match_single_binding)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, Ipv4AddrExt, Ipv6AddrExt};
use holo_utils::sr::IgpAlgoType;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};

use crate::packet::consts::{
    AuthenticationType, NeighborStlvType, PrefixStlvType, RouterCapStlvType,
    TlvType,
};
use crate::packet::error::{DecodeError, DecodeResult};
#[cfg(feature = "testing")]
use crate::packet::pdu::serde_lsp_rem_lifetime_filter;
use crate::packet::subtlvs::capability::{
    SrAlgoStlv, SrCapabilitiesStlv, SrLocalBlockStlv,
};
use crate::packet::subtlvs::prefix::{
    BierInfoStlv, Ipv4SourceRidStlv, Ipv6SourceRidStlv, PrefixAttrFlags,
    PrefixAttrFlagsStlv, PrefixSidStlv,
};
use crate::packet::{AreaAddr, LanId, LspId, subtlvs};

// TLV header size.
pub const TLV_HDR_SIZE: usize = 2;
// TLV maximum length.
pub const TLV_MAX_LEN: usize = 255;
// Maximum narrow metric.
pub const MAX_NARROW_METRIC: u32 = 63;

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

// Trait for TLV types whose payload is made up of multiple logical entries,
// which may span across multiple TLV instances.
pub trait EntryBasedTlv: From<Vec<Self::Entry>> {
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

// Trait for entries of IP reachability TLVs.
pub trait IpReachTlvEntry: Clone {
    type IpNetwork: Ord + Into<IpNetwork>;

    // Return the network prefix.
    fn prefix(&self) -> Self::IpNetwork;

    // Return the reachability metric.
    fn metric(&self) -> u32;

    // Add a value to the metric, ensuring it stays within valid bounds.
    fn metric_add(&mut self, value: u32);

    // Return whether the up/down bit is set.
    fn up_down(&self) -> bool;

    // Return the value of the specified prefix attribute flag, if present.
    fn prefix_attr_flags_get(&self, flag: PrefixAttrFlags) -> Option<bool>;

    // Set the specified prefix attribute flag, if supported.
    //
    // If the Prefix Attribute Flags sub-TLV is not present, it will be created.
    fn prefix_attr_flags_set(&mut self, flag: PrefixAttrFlags);

    // Returns a mutable iterator over the Prefix-SIDs associated with this
    // reachability entry.
    fn prefix_sids_mut(&mut self) -> impl Iterator<Item = &mut PrefixSidStlv>;
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct AreaAddressesTlv {
    pub list: Vec<AreaAddr>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct NeighborsTlv {
    pub list: Vec<[u8; 6]>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PaddingTlv {
    pub length: u8,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AuthenticationTlv {
    ClearText(Vec<u8>),
    HmacMd5([u8; 16]),
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspBufferSizeTlv {
    pub size: u16,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct DynamicHostnameTlv {
    pub hostname: String,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ProtocolsSupportedTlv {
    pub list: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4AddressesTlv {
    pub list: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6AddressesTlv {
    pub list: Vec<Ipv6Addr>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspEntriesTlv {
    pub list: Vec<LspEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct LspEntry {
    #[cfg_attr(
        feature = "testing",
        serde(default, skip_serializing_if = "serde_lsp_rem_lifetime_filter")
    )]
    pub rem_lifetime: u16,
    pub lsp_id: LspId,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub seqno: u32,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub cksum: u16,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct IsReachTlv {
    pub list: Vec<IsReach>,
}

#[derive(Clone, Debug, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Deserialize, Serialize)]
pub struct IsReach {
    pub metric: u8,
    pub metric_delay: Option<u8>,
    pub metric_expense: Option<u8>,
    pub metric_error: Option<u8>,
    pub neighbor: LanId,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReachTlv {
    pub list: Vec<ExtIsReach>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReach {
    pub neighbor: LanId,
    pub metric: u32,
    pub sub_tlvs: ExtIsReachStlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct ExtIsReachStlvs {
    pub admin_group: Option<subtlvs::neighbor::AdminGroupStlv>,
    pub ipv4_interface_addr: Vec<subtlvs::neighbor::Ipv4InterfaceAddrStlv>,
    pub ipv4_neighbor_addr: Vec<subtlvs::neighbor::Ipv4NeighborAddrStlv>,
    pub max_link_bw: Option<subtlvs::neighbor::MaxLinkBwStlv>,
    pub max_resv_link_bw: Option<subtlvs::neighbor::MaxResvLinkBwStlv>,
    pub unreserved_bw: Option<subtlvs::neighbor::UnreservedBwStlv>,
    pub te_default_metric: Option<subtlvs::neighbor::TeDefaultMetricStlv>,
    pub adj_sids: Vec<subtlvs::neighbor::AdjSidStlv>,
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4ReachTlv {
    pub list: Vec<Ipv4Reach>,
}

#[derive(Clone, Debug, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4Reach {
    pub up_down: bool,
    pub ie_bit: bool,
    pub metric: u8,
    pub metric_delay: Option<u8>,
    pub metric_expense: Option<u8>,
    pub metric_error: Option<u8>,
    pub prefix: Ipv4Network,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIpv4ReachTlv {
    pub list: Vec<ExtIpv4Reach>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ExtIpv4Reach {
    pub metric: u32,
    pub up_down: bool,
    pub prefix: Ipv4Network,
    pub sub_tlvs: Ipv4ReachStlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    BTreeMap => #[serde(default, skip_serializing_if = "BTreeMap::is_empty")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4ReachStlvs {
    pub prefix_attr_flags: Option<PrefixAttrFlagsStlv>,
    pub ipv4_source_rid: Option<Ipv4SourceRidStlv>,
    pub ipv6_source_rid: Option<Ipv6SourceRidStlv>,
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSidStlv>,
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6ReachTlv {
    pub list: Vec<Ipv6Reach>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6Reach {
    pub metric: u32,
    pub up_down: bool,
    pub external: bool,
    pub prefix: Ipv6Network,
    pub sub_tlvs: Ipv6ReachStlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    BTreeMap => #[serde(default, skip_serializing_if = "BTreeMap::is_empty")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6ReachStlvs {
    pub prefix_attr_flags: Option<PrefixAttrFlagsStlv>,
    pub ipv4_source_rid: Option<Ipv4SourceRidStlv>,
    pub ipv6_source_rid: Option<Ipv6SourceRidStlv>,
    pub prefix_sids: BTreeMap<IgpAlgoType, PrefixSidStlv>,
    pub bier: Vec<BierInfoStlv>,
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4RouterIdTlv(Ipv4Addr);

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6RouterIdTlv(Ipv6Addr);

#[derive(Clone, Debug, Default, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct RouterCapTlv {
    pub router_id: Option<Ipv4Addr>,
    pub flags: RouterCapFlags,
    pub sub_tlvs: RouterCapStlvs,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct RouterCapFlags: u8 {
        const S = 0x01;
        const D = 0x02;
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct RouterCapStlvs {
    pub sr_cap: Option<SrCapabilitiesStlv>,
    pub sr_algo: Option<SrAlgoStlv>,
    pub srlb: Option<SrLocalBlockStlv>,
    pub unknown: Vec<UnknownTlv>,
}

#[derive(Clone, Debug, PartialEq)]
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

impl EntryBasedTlv for AreaAddressesTlv {
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

impl EntryBasedTlv for NeighborsTlv {
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

// ===== impl AuthenticationTlv =====

impl AuthenticationTlv {
    pub const MIN_LEN: usize = 1;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if (tlv_len as usize) < Self::MIN_LEN {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        // Parse authentication type.
        let auth_type = buf.get_u8();
        let Some(auth_type) = AuthenticationType::from_u8(auth_type) else {
            return Err(DecodeError::AuthUnsupportedType(auth_type));
        };

        match auth_type {
            AuthenticationType::ClearText => {
                if buf.remaining() == 0 {
                    return Err(DecodeError::InvalidTlvLength(tlv_len));
                }

                // Parse password.
                let mut passwd_bytes = [0; 255];
                let passwd_len = tlv_len as usize - 1;
                buf.copy_to_slice(&mut passwd_bytes[..passwd_len]);
                let passwd = Vec::from(&passwd_bytes[..passwd_len]);
                Ok(AuthenticationTlv::ClearText(passwd))
            }
            AuthenticationType::HmacMd5 => {
                if buf.remaining() != CryptoAlgo::HmacMd5.digest_size() as usize
                {
                    return Err(DecodeError::InvalidTlvLength(tlv_len));
                }

                // Parse HMAC digest.
                let mut digest = [0; 16];
                buf.copy_to_slice(&mut digest);
                Ok(AuthenticationTlv::HmacMd5(digest))
            }
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Authentication);
        match self {
            AuthenticationTlv::ClearText(passwd) => {
                buf.put_u8(AuthenticationType::ClearText as u8);
                buf.put_slice(passwd);
            }
            AuthenticationTlv::HmacMd5(digest) => {
                buf.put_u8(AuthenticationType::HmacMd5 as u8);
                buf.put_slice(digest);
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

// ===== impl LspBufferSizeTlv =====

impl LspBufferSizeTlv {
    const SIZE: usize = 2;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let size = buf.get_u16();

        Ok(LspBufferSizeTlv { size })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::LspBufferSize);
        buf.put_u16(self.size);
        tlv_encode_end(buf, start_pos);
    }
}

impl Tlv for LspBufferSizeTlv {
    fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }
}

// ===== impl DynamicHostnameTlv =====

impl DynamicHostnameTlv {
    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len == 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let mut hostname_bytes = [0; 255];
        buf.copy_to_slice(&mut hostname_bytes[..tlv_len as usize]);
        let hostname =
            String::from_utf8_lossy(&hostname_bytes[..tlv_len as usize])
                .to_string();

        Ok(DynamicHostnameTlv { hostname })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::DynamicHostname);
        buf.put_slice(self.hostname.as_bytes());
        tlv_encode_end(buf, start_pos);
    }
}

impl Tlv for DynamicHostnameTlv {
    fn len(&self) -> usize {
        TLV_HDR_SIZE + self.hostname.len()
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

impl EntryBasedTlv for Ipv4AddressesTlv {
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

impl EntryBasedTlv for Ipv6AddressesTlv {
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
    pub const MAX_SIZE: usize =
        TLV_HDR_SIZE + Self::MAX_ENTRIES * Self::ENTRY_SIZE;

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

impl EntryBasedTlv for LspEntriesTlv {
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

impl EntryBasedTlv for IsReachTlv {
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
        use subtlvs::neighbor::{
            AdjSidStlv, AdminGroupStlv, Ipv4InterfaceAddrStlv,
            Ipv4NeighborAddrStlv, MaxLinkBwStlv, MaxResvLinkBwStlv,
            TeDefaultMetricStlv, UnreservedBwStlv,
        };

        let mut list = vec![];

        while buf.remaining() >= Self::ENTRY_MIN_SIZE {
            let neighbor = LanId::decode(buf);
            let metric = buf.get_u24();

            // Parse Sub-TLVs.
            let mut sub_tlvs = ExtIsReachStlvs::default();
            let mut sub_tlvs_len = buf.get_u8();
            while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                // Parse TLV type.
                let stlv_type = buf.get_u8();
                sub_tlvs_len -= 1;
                let stlv_etype = NeighborStlvType::from_u8(stlv_type);

                // Parse and validate TLV length.
                let stlv_len = buf.get_u8();
                sub_tlvs_len -= 1;
                if stlv_len as usize > buf.remaining() {
                    return Err(DecodeError::InvalidTlvLength(stlv_len));
                }

                // Parse Sub-TLV value.
                let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
                sub_tlvs_len -= stlv_len;
                match stlv_etype {
                    Some(NeighborStlvType::AdminGroup) => {
                        let stlv =
                            AdminGroupStlv::decode(stlv_len, &mut buf_stlv)?;
                        sub_tlvs.admin_group = Some(stlv);
                    }
                    Some(NeighborStlvType::Ipv4InterfaceAddress) => {
                        let stlv = Ipv4InterfaceAddrStlv::decode(
                            stlv_len,
                            &mut buf_stlv,
                        )?;
                        sub_tlvs.ipv4_interface_addr.push(stlv);
                    }
                    Some(NeighborStlvType::Ipv4NeighborAddress) => {
                        let stlv = Ipv4NeighborAddrStlv::decode(
                            stlv_len,
                            &mut buf_stlv,
                        )?;
                        sub_tlvs.ipv4_neighbor_addr.push(stlv);
                    }
                    Some(NeighborStlvType::MaxLinkBandwidth) => {
                        let stlv =
                            MaxLinkBwStlv::decode(stlv_len, &mut buf_stlv)?;
                        sub_tlvs.max_link_bw = Some(stlv);
                    }
                    Some(NeighborStlvType::MaxResvLinkBandwidth) => {
                        let stlv =
                            MaxResvLinkBwStlv::decode(stlv_len, &mut buf_stlv)?;
                        sub_tlvs.max_resv_link_bw = Some(stlv);
                    }
                    Some(NeighborStlvType::UnreservedBandwidth) => {
                        let stlv =
                            UnreservedBwStlv::decode(stlv_len, &mut buf_stlv)?;
                        sub_tlvs.unreserved_bw = Some(stlv);
                    }
                    Some(NeighborStlvType::TeDefaultMetric) => {
                        let stlv = TeDefaultMetricStlv::decode(
                            stlv_len,
                            &mut buf_stlv,
                        )?;
                        sub_tlvs.te_default_metric = Some(stlv);
                    }
                    Some(NeighborStlvType::AdjacencySid) => {
                        if let Some(stlv) =
                            AdjSidStlv::decode(stlv_len, false, &mut buf_stlv)?
                        {
                            sub_tlvs.adj_sids.push(stlv);
                        }
                    }
                    Some(NeighborStlvType::LanAdjacencySid) => {
                        if let Some(stlv) =
                            AdjSidStlv::decode(stlv_len, true, &mut buf_stlv)?
                        {
                            sub_tlvs.adj_sids.push(stlv);
                        }
                    }
                    _ => {
                        // Save unknown Sub-TLV.
                        sub_tlvs.unknown.push(UnknownTlv::new(
                            stlv_type, stlv_len, buf_stlv,
                        ));
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
            let subtlvs_len_pos = buf.len();
            buf.put_u8(0);
            if let Some(stlv) = &entry.sub_tlvs.admin_group {
                stlv.encode(buf);
            }
            for stlv in &entry.sub_tlvs.ipv4_interface_addr {
                stlv.encode(buf);
            }
            for stlv in &entry.sub_tlvs.ipv4_neighbor_addr {
                stlv.encode(buf);
            }
            if let Some(stlv) = &entry.sub_tlvs.max_link_bw {
                stlv.encode(buf);
            }
            if let Some(stlv) = &entry.sub_tlvs.max_resv_link_bw {
                stlv.encode(buf);
            }
            if let Some(stlv) = &entry.sub_tlvs.unreserved_bw {
                stlv.encode(buf);
            }
            if let Some(stlv) = &entry.sub_tlvs.te_default_metric {
                stlv.encode(buf);
            }
            for stlv in &entry.sub_tlvs.adj_sids {
                stlv.encode(buf);
            }
            // Rewrite Sub-TLVs length field.
            buf[subtlvs_len_pos] = (buf.len() - 1 - subtlvs_len_pos) as u8;
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl EntryBasedTlv for ExtIsReachTlv {
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
    const METRIC_UP_DOWN_BIT: u8 = 0x80;
    const METRIC_IE_BIT: u8 = 0x40;
    const METRIC_MASK: u8 = 0x3F;

    pub(crate) fn decode(
        tlv_len: u8,
        buf: &mut Bytes,
        external: bool,
    ) -> DecodeResult<Self> {
        let mut list = vec![];

        // Validate the TLV length.
        if tlv_len as usize % Self::ENTRY_SIZE != 0 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        while buf.remaining() >= Self::ENTRY_SIZE {
            let metric = buf.get_u8();
            let up_down = metric & Self::METRIC_UP_DOWN_BIT != 0;
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

            // Per RFC 5302 Section 3.3, ignore internal reachability
            // information with external metric type.
            if ie_bit && !external {
                continue;
            }
            // Ignore prefixes with non-contiguous subnet masks.
            let Ok(prefix) = Ipv4Network::with_netmask(addr, mask) else {
                continue;
            };

            let entry = Ipv4Reach {
                up_down,
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
            if entry.up_down {
                metric |= Self::METRIC_UP_DOWN_BIT;
            }
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

impl EntryBasedTlv for Ipv4ReachTlv {
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

impl IpReachTlvEntry for Ipv4Reach {
    type IpNetwork = Ipv4Network;

    fn prefix(&self) -> Ipv4Network {
        self.prefix
    }

    fn metric(&self) -> u32 {
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

    fn metric_add(&mut self, value: u32) {
        self.metric =
            std::cmp::min(self.metric as u32 + value, MAX_NARROW_METRIC) as u8;
    }

    fn up_down(&self) -> bool {
        self.up_down
    }

    fn prefix_attr_flags_get(&self, _flag: PrefixAttrFlags) -> Option<bool> {
        // TLVs 128 and 130 don't support Sub-TLVs.
        None
    }

    fn prefix_attr_flags_set(&mut self, _flag: PrefixAttrFlags) {
        // TLVs 128 and 130 don't support Sub-TLVs.
    }

    fn prefix_sids_mut(&mut self) -> impl Iterator<Item = &mut PrefixSidStlv> {
        // TLVs 128 and 130 don't support Sub-TLVs.
        std::iter::empty()
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
            let mut sub_tlvs = Ipv4ReachStlvs::default();
            if subtlvs {
                let mut sub_tlvs_len = buf.get_u8();
                while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                    // Parse TLV type.
                    let stlv_type = buf.get_u8();
                    sub_tlvs_len -= 1;
                    let stlv_etype = PrefixStlvType::from_u8(stlv_type);

                    // Parse and validate TLV length.
                    let stlv_len = buf.get_u8();
                    sub_tlvs_len -= 1;
                    if stlv_len as usize > buf.remaining() {
                        return Err(DecodeError::InvalidTlvLength(stlv_len));
                    }

                    // Parse Sub-TLV value.
                    let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
                    sub_tlvs_len -= stlv_len;
                    match stlv_etype {
                        Some(PrefixStlvType::PrefixAttributeFlags) => {
                            let stlv = PrefixAttrFlagsStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.prefix_attr_flags = Some(stlv);
                        }
                        Some(PrefixStlvType::Ipv4SourceRouterId) => {
                            let stlv = Ipv4SourceRidStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.ipv4_source_rid = Some(stlv);
                        }
                        Some(PrefixStlvType::Ipv6SourceRouterId) => {
                            let stlv = Ipv6SourceRidStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.ipv6_source_rid = Some(stlv);
                        }
                        Some(PrefixStlvType::PrefixSid) => {
                            if let Some(stlv) =
                                PrefixSidStlv::decode(stlv_len, &mut buf_stlv)?
                            {
                                sub_tlvs.prefix_sids.insert(stlv.algo, stlv);
                            }
                        }
                        _ => {
                            // Save unknown Sub-TLV.
                            sub_tlvs.unknown.push(UnknownTlv::new(
                                stlv_type, stlv_len, buf_stlv,
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
            let has_subtlvs = entry.sub_tlvs.prefix_attr_flags.is_some()
                || entry.sub_tlvs.ipv4_source_rid.is_some()
                || entry.sub_tlvs.ipv6_source_rid.is_some();
            if has_subtlvs {
                control |= Self::CONTROL_SUBTLVS;
            }
            control |= plen;
            buf.put_u8(control);

            // Encode prefix (variable length).
            let plen_wire = prefix_wire_len(plen);
            buf.put(&entry.prefix.ip().octets()[0..plen_wire]);

            // Encode Sub-TLVs.
            if has_subtlvs {
                let subtlvs_len_pos = buf.len();
                buf.put_u8(0);

                if let Some(stlv) = &entry.sub_tlvs.prefix_attr_flags {
                    stlv.encode(buf);
                }
                if let Some(stlv) = &entry.sub_tlvs.ipv4_source_rid {
                    stlv.encode(buf);
                }
                if let Some(stlv) = &entry.sub_tlvs.ipv6_source_rid {
                    stlv.encode(buf);
                }
                for stlv in entry.sub_tlvs.prefix_sids.values() {
                    stlv.encode(buf);
                }

                // Rewrite Sub-TLVs length field.
                buf[subtlvs_len_pos] = (buf.len() - 1 - subtlvs_len_pos) as u8;
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl EntryBasedTlv for ExtIpv4ReachTlv {
    type Entry = ExtIpv4Reach;

    fn entries(&self) -> impl Iterator<Item = &ExtIpv4Reach> {
        self.list.iter()
    }

    fn entry_len(entry: &ExtIpv4Reach) -> usize {
        let plen = entry.prefix.prefix();
        Self::ENTRY_MIN_SIZE + prefix_wire_len(plen) + entry.sub_tlvs.len()
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

// ===== impl ExtIpv4Reach =====

impl IpReachTlvEntry for ExtIpv4Reach {
    type IpNetwork = Ipv4Network;

    fn prefix(&self) -> Ipv4Network {
        self.prefix
    }

    fn metric(&self) -> u32 {
        self.metric
    }

    fn metric_add(&mut self, value: u32) {
        self.metric = self.metric.saturating_add(value);
    }

    fn up_down(&self) -> bool {
        self.up_down
    }

    fn prefix_attr_flags_get(&self, flag: PrefixAttrFlags) -> Option<bool> {
        self.sub_tlvs
            .prefix_attr_flags
            .as_ref()
            .map(|stlv| stlv.get().contains(flag))
    }

    fn prefix_attr_flags_set(&mut self, flag: PrefixAttrFlags) {
        self.sub_tlvs
            .prefix_attr_flags
            .get_or_insert_default()
            .set(flag);
    }

    fn prefix_sids_mut(&mut self) -> impl Iterator<Item = &mut PrefixSidStlv> {
        self.sub_tlvs.prefix_sids.values_mut()
    }
}

// ===== impl Ipv4ReachStlvs =====

impl Ipv4ReachStlvs {
    fn len(&self) -> usize {
        let mut len = 0;

        if self.prefix_attr_flags.is_some()
            || self.ipv4_source_rid.is_some()
            || self.ipv6_source_rid.is_some()
            || !self.prefix_sids.is_empty()
        {
            len += 1;
        }
        if let Some(stlv) = &self.prefix_attr_flags {
            len += stlv.len();
        }
        if let Some(stlv) = &self.ipv4_source_rid {
            len += stlv.len();
        }
        if let Some(stlv) = &self.ipv6_source_rid {
            len += stlv.len();
        }
        for stlv in self.prefix_sids.values() {
            len += stlv.len();
        }

        len
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
            let mut sub_tlvs = Ipv6ReachStlvs::default();
            if subtlvs {
                let mut sub_tlvs_len = buf.get_u8();
                while sub_tlvs_len >= TLV_HDR_SIZE as u8 {
                    // Parse TLV type.
                    let stlv_type = buf.get_u8();
                    sub_tlvs_len -= 1;
                    let stlv_etype = PrefixStlvType::from_u8(stlv_type);

                    // Parse and validate TLV length.
                    let stlv_len = buf.get_u8();
                    sub_tlvs_len -= 1;
                    if stlv_len as usize > buf.remaining() {
                        return Err(DecodeError::InvalidTlvLength(stlv_len));
                    }

                    // Parse Sub-TLV value.
                    let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
                    sub_tlvs_len -= stlv_len;
                    match stlv_etype {
                        Some(PrefixStlvType::PrefixAttributeFlags) => {
                            let stlv = PrefixAttrFlagsStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.prefix_attr_flags = Some(stlv);
                        }
                        Some(PrefixStlvType::Ipv4SourceRouterId) => {
                            let stlv = Ipv4SourceRidStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.ipv4_source_rid = Some(stlv);
                        }
                        Some(PrefixStlvType::Ipv6SourceRouterId) => {
                            let stlv = Ipv6SourceRidStlv::decode(
                                stlv_len,
                                &mut buf_stlv,
                            )?;
                            sub_tlvs.ipv6_source_rid = Some(stlv);
                        }
                        Some(PrefixStlvType::PrefixSid) => {
                            if let Some(stlv) =
                                PrefixSidStlv::decode(stlv_len, &mut buf_stlv)?
                            {
                                sub_tlvs.prefix_sids.insert(stlv.algo, stlv);
                            }
                        }
                        Some(PrefixStlvType::BierInfo) => {
                            let stlv =
                                BierInfoStlv::decode(stlv_len, &mut buf_stlv)?;
                            sub_tlvs.bier.push(stlv);
                        }
                        _ => {
                            // Save unknown Sub-TLV.
                            sub_tlvs.unknown.push(UnknownTlv::new(
                                stlv_type, stlv_len, buf_stlv,
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
            let has_subtlvs = entry.sub_tlvs.prefix_attr_flags.is_some()
                || entry.sub_tlvs.ipv4_source_rid.is_some()
                || entry.sub_tlvs.ipv6_source_rid.is_some()
                || !entry.sub_tlvs.bier.is_empty();
            if has_subtlvs {
                flags |= Self::FLAG_SUBTLVS;
            }
            buf.put_u8(flags);

            // Encode prefix length.
            let plen = entry.prefix.prefix();
            buf.put_u8(plen);

            // Encode prefix (variable length).
            let plen_wire = prefix_wire_len(plen);
            buf.put(&entry.prefix.ip().octets()[0..plen_wire]);

            // Encode Sub-TLVs.
            //
            // Enforce RFC5308 Section 2: "If the Sub-TLV bit is set to 0, then
            // the octets of Sub-TLVs are not present. Otherwise, the bit is 1
            // and the octet following the prefix will contain the length of the
            // Sub-TLV portion of the structure."
            if has_subtlvs {
                let subtlvs_len_pos = buf.len();
                buf.put_u8(0);

                if let Some(stlv) = &entry.sub_tlvs.prefix_attr_flags {
                    stlv.encode(buf);
                }
                if let Some(stlv) = &entry.sub_tlvs.ipv4_source_rid {
                    stlv.encode(buf);
                }
                if let Some(stlv) = &entry.sub_tlvs.ipv6_source_rid {
                    stlv.encode(buf);
                }
                for stlv in entry.sub_tlvs.prefix_sids.values() {
                    stlv.encode(buf);
                }
                for stlv in &entry.sub_tlvs.bier {
                    stlv.encode(buf);
                }

                // Rewrite Sub-TLVs length field.
                buf[subtlvs_len_pos] = (buf.len() - 1 - subtlvs_len_pos) as u8;
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl EntryBasedTlv for Ipv6ReachTlv {
    type Entry = Ipv6Reach;

    fn entries(&self) -> impl Iterator<Item = &Ipv6Reach> {
        self.list.iter()
    }

    fn entry_len(entry: &Ipv6Reach) -> usize {
        let plen = entry.prefix.prefix();
        Self::ENTRY_MIN_SIZE + prefix_wire_len(plen) + entry.sub_tlvs.len()
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

// ===== impl Ipv6Reach =====

impl IpReachTlvEntry for Ipv6Reach {
    type IpNetwork = Ipv6Network;

    fn prefix(&self) -> Ipv6Network {
        self.prefix
    }

    fn metric(&self) -> u32 {
        self.metric
    }

    fn metric_add(&mut self, value: u32) {
        self.metric = self.metric.saturating_add(value);
    }

    fn up_down(&self) -> bool {
        self.up_down
    }

    fn prefix_attr_flags_get(&self, flag: PrefixAttrFlags) -> Option<bool> {
        self.sub_tlvs
            .prefix_attr_flags
            .as_ref()
            .map(|stlv| stlv.get().contains(flag))
    }

    fn prefix_attr_flags_set(&mut self, flag: PrefixAttrFlags) {
        self.sub_tlvs
            .prefix_attr_flags
            .get_or_insert_default()
            .set(flag);
    }

    fn prefix_sids_mut(&mut self) -> impl Iterator<Item = &mut PrefixSidStlv> {
        self.sub_tlvs.prefix_sids.values_mut()
    }
}

// ===== impl Ipv6ReachStlvs =====

impl Ipv6ReachStlvs {
    fn len(&self) -> usize {
        let mut len = 0;

        if self.prefix_attr_flags.is_some()
            || self.ipv4_source_rid.is_some()
            || self.ipv6_source_rid.is_some()
            || !self.prefix_sids.is_empty()
            || !self.bier.is_empty()
        {
            len += 1;
        }
        if let Some(stlv) = &self.prefix_attr_flags {
            len += stlv.len();
        }
        if let Some(stlv) = &self.ipv4_source_rid {
            len += stlv.len();
        }
        if let Some(stlv) = &self.ipv6_source_rid {
            len += stlv.len();
        }
        for stlv in self.prefix_sids.values() {
            len += stlv.len();
        }
        for stlv in self.bier.iter() {
            len += stlv.len();
        }

        len
    }
}

// ===== impl Ipv4RouterIdTlv =====

impl Ipv4RouterIdTlv {
    const SIZE: usize = 4;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv4();

        Ok(Ipv4RouterIdTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Ipv4RouterId);
        buf.put_ipv4(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv4Addr {
        &self.0
    }
}

impl Tlv for Ipv4RouterIdTlv {
    fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }
}

// ===== impl Ipv6RouterIdTlv =====

impl Ipv6RouterIdTlv {
    const SIZE: usize = 16;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if tlv_len as usize != Self::SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let addr = buf.get_ipv6();

        Ok(Ipv6RouterIdTlv(addr))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::Ipv6RouterId);
        buf.put_ipv6(&self.0);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn get(&self) -> &Ipv6Addr {
        &self.0
    }
}

impl Tlv for Ipv6RouterIdTlv {
    fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }
}

// ===== impl RouterCapTlv =====

impl RouterCapTlv {
    const MIN_SIZE: usize = 5;

    pub(crate) fn decode(tlv_len: u8, buf: &mut Bytes) -> DecodeResult<Self> {
        // Validate the TLV length.
        if (tlv_len as usize) < Self::MIN_SIZE {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let router_id = buf.get_opt_ipv4();
        let flags = buf.get_u8();
        let flags = RouterCapFlags::from_bits_truncate(flags);

        // Parse Sub-TLVs.
        let mut sub_tlvs = RouterCapStlvs::default();
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let stlv_type = buf.get_u8();
            let stlv_etype = RouterCapStlvType::from_u8(stlv_type);

            // Parse and validate TLV length.
            let stlv_len = buf.get_u8();
            if stlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(stlv_len));
            }

            // Parse Sub-TLV value.
            let mut buf_stlv = buf.copy_to_bytes(stlv_len as usize);
            match stlv_etype {
                Some(RouterCapStlvType::SrCapability) => {
                    if sub_tlvs.sr_cap.is_some() {
                        continue;
                    }
                    let stlv =
                        SrCapabilitiesStlv::decode(stlv_len, &mut buf_stlv)?;
                    sub_tlvs.sr_cap = Some(stlv);
                }
                Some(RouterCapStlvType::SrAlgorithm) => {
                    if sub_tlvs.sr_algo.is_some() {
                        continue;
                    }
                    let stlv = SrAlgoStlv::decode(stlv_len, &mut buf_stlv)?;
                    sub_tlvs.sr_algo = Some(stlv);
                }
                Some(RouterCapStlvType::SrLocalBlock) => {
                    if sub_tlvs.srlb.is_some() {
                        continue;
                    }
                    let stlv =
                        SrLocalBlockStlv::decode(stlv_len, &mut buf_stlv)?;
                    sub_tlvs.srlb = Some(stlv);
                }
                _ => {
                    // Save unknown Sub-TLV.
                    sub_tlvs
                        .unknown
                        .push(UnknownTlv::new(stlv_type, stlv_len, buf_stlv));
                }
            }
        }

        Ok(RouterCapTlv {
            router_id,
            flags,
            sub_tlvs,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, TlvType::RouterCapability);
        // Encode Router ID.
        buf.put_ipv4(&self.router_id.unwrap_or(Ipv4Addr::UNSPECIFIED));
        // Encode flags.
        buf.put_u8(self.flags.bits());
        // Encode Sub-TLVs.
        if let Some(stlv) = &self.sub_tlvs.sr_cap {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.sub_tlvs.sr_algo {
            stlv.encode(buf);
        }
        if let Some(stlv) = &self.sub_tlvs.srlb {
            stlv.encode(buf);
        }
        tlv_encode_end(buf, start_pos);
    }
}

impl Tlv for RouterCapTlv {
    fn len(&self) -> usize {
        let mut len = TLV_HDR_SIZE + Self::MIN_SIZE;

        if let Some(stlv) = &self.sub_tlvs.sr_cap {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.sr_algo {
            len += stlv.len();
        }
        if let Some(stlv) = &self.sub_tlvs.srlb {
            len += stlv.len();
        }

        len
    }
}

// ===== blanket implementations =====

impl<T: EntryBasedTlv> Tlv for T {
    fn len(&self) -> usize {
        self.len()
    }
}

// ===== helper functions =====

// Calculates the number of bytes required to encode a prefix.
const fn prefix_wire_len(len: u8) -> usize {
    (len as usize).div_ceil(8)
}

// ===== global functions =====

pub(crate) fn tlv_encode_start(
    buf: &mut BytesMut,
    tlv_type: impl ToPrimitive,
) -> usize {
    let start_pos = buf.len();
    buf.put_u8(tlv_type.to_u8().unwrap());
    // The TLV length will be rewritten later.
    buf.put_u8(0);
    start_pos
}

pub(crate) fn tlv_encode_end(buf: &mut BytesMut, start_pos: usize) {
    // Rewrite TLV length.
    buf[start_pos + 1] = (buf.len() - start_pos - TLV_HDR_SIZE) as u8;
}

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
    T: EntryBasedTlv,
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
