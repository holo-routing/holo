//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::{Ipv4AddrExt, Ipv6AddrExt};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::debug::Debug;
use crate::neighbor::PeerType;
use crate::packet::consts::{
    Afi, AsPathSegmentType, AttrFlags, AttrType, Origin, Safi,
};
use crate::packet::error::{AttrError, UpdateMessageError};
use crate::packet::message::{
    decode_ipv4_prefix, decode_ipv6_prefix, encode_ipv4_prefix,
    encode_ipv6_prefix, DecodeCxt, EncodeCxt, MpReachNlri, MpUnreachNlri,
    ReachNlri,
};

pub const ATTR_MIN_LEN: u16 = 3;
pub const ATTR_MIN_LEN_EXT: u16 = 4;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Attrs {
    pub base: BaseAttrs,
    pub comm: Option<Comms>,
    pub ext_comm: Option<ExtComms>,
    pub extv6_comm: Option<Extv6Comms>,
    pub large_comm: Option<LargeComms>,
    pub unknown: Vec<UnknownAttr>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct BaseAttrs {
    pub origin: Origin,
    pub as_path: AsPath,
    pub as4_path: Option<AsPath>,
    pub nexthop: Option<IpAddr>,
    pub ll_nexthop: Option<Ipv6Addr>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub aggregator: Option<Aggregator>,
    pub as4_aggregator: Option<Aggregator>,
    pub atomic_aggregate: bool,
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Option<ClusterList>,
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct AsPath {
    pub segments: VecDeque<AsPathSegment>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct AsPathSegment {
    pub seg_type: AsPathSegmentType,
    pub members: VecDeque<u32>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct Aggregator {
    pub asn: u32,
    pub identifier: Ipv4Addr,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct ClusterList(pub BTreeSet<Ipv4Addr>);

// Re-exports for convenience.
pub type Comm = holo_utils::bgp::Comm;
pub type ExtComm = holo_utils::bgp::ExtComm;
pub type Extv6Comm = holo_utils::bgp::Extv6Comm;
pub type LargeComm = holo_utils::bgp::LargeComm;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct CommList<T: CommType>(pub BTreeSet<T>);

pub trait CommType:
    Clone + std::fmt::Debug + Eq + Ord + PartialEq + PartialOrd
{
    const TYPE: AttrType;
    const LENGTH: usize;

    fn encode(&self, buf: &mut BytesMut);
    fn decode(buf: &mut Bytes) -> Self;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct UnknownAttr {
    pub attr_type: u8,
    pub flags: AttrFlags,
    pub length: u16,
    pub value: Bytes,
}

// Useful type definitions.
pub type Comms = CommList<Comm>;
pub type ExtComms = CommList<ExtComm>;
pub type Extv6Comms = CommList<Extv6Comm>;
pub type LargeComms = CommList<LargeComm>;

// ===== impl Attrs =====

impl Attrs {
    pub(crate) fn encode(
        &self,
        buf: &mut BytesMut,
        reach: &Option<ReachNlri>,
        mp_reach: &Option<MpReachNlri>,
        mp_unreach: &Option<MpUnreachNlri>,
        cxt: &EncodeCxt,
    ) {
        // Check whether the 4-octet AS number capability has been negotiated.
        let four_byte_asn_cap = cxt
            .capabilities
            .iter()
            .any(|cap| cap.is_four_octet_as_number());

        // RFC 7606 - Section 5.1:
        // "The MP_REACH_NLRI or MP_UNREACH_NLRI attribute (if present) SHALL
        // be encoded as the very first path attribute in an UPDATE message".
        if let Some(mp_reach) = mp_reach {
            mp_reach.encode(buf);
        }
        if let Some(mp_unreach) = mp_unreach {
            mp_unreach.encode(buf);
        }

        // RFC 4271 - Section 5:
        // "The sender of an UPDATE message SHOULD order path attributes within
        // the UPDATE message in ascending order of attribute type".

        // ORIGIN attribute.
        origin::encode(self.base.origin, buf);

        // AS_PATH attribute.
        self.base.as_path.encode(
            buf,
            AttrFlags::TRANSITIVE,
            AttrType::AsPath,
            four_byte_asn_cap,
        );

        // NEXT_HOP attribute.
        if let Some(reach) = reach {
            nexthop::encode(reach.nexthop, buf);
        }

        // MULTI_EXIT_DISC attribute.
        if let Some(metric) = self.base.med {
            med::encode(metric, buf);
        }

        // LOCAL_PREF attribute.
        if let Some(local_pref) = self.base.local_pref {
            local_pref::encode(local_pref, buf);
        }

        // ATOMIC_AGGREGATE attribute.
        if self.base.atomic_aggregate {
            atomic_aggregate::encode(buf);
        }

        // AGGREGATOR attribute.
        if let Some(aggregator) = &self.base.aggregator {
            aggregator.encode(
                buf,
                AttrFlags::TRANSITIVE | AttrFlags::OPTIONAL,
                AttrType::Aggregator,
                four_byte_asn_cap,
            );
        }

        // COMMUNITIES attribute.
        if let Some(comm) = &self.comm {
            comm.encode(buf);
        }

        // ORIGINATOR_ID attribute.
        if let Some(originator_id) = self.base.originator_id {
            originator_id::encode(originator_id, buf);
        }

        // CLUSTER_LIST attribute.
        if let Some(cluster_list) = &self.base.cluster_list {
            cluster_list.encode(buf);
        }

        // EXTENDED COMMUNITIES attribute.
        if let Some(ext_comm) = &self.ext_comm {
            ext_comm.encode(buf);
        }

        // AS4_PATH attribute.
        if let Some(as4_path) = &self.base.as4_path {
            as4_path.encode(
                buf,
                AttrFlags::TRANSITIVE | AttrFlags::OPTIONAL,
                AttrType::As4Path,
                true,
            );
        }

        // AS4_AGGREGATOR attribute.
        if let Some(as4_aggregator) = &self.base.as4_aggregator {
            as4_aggregator.encode(
                buf,
                AttrFlags::TRANSITIVE | AttrFlags::OPTIONAL,
                AttrType::As4Aggregator,
                true,
            );
        }

        // IPv6 Address Specific Extended Community attribute.
        if let Some(extv6_comm) = &self.extv6_comm {
            extv6_comm.encode(buf);
        }

        // LARGE_COMMUNITY attribute.
        if let Some(large_comm) = &self.large_comm {
            large_comm.encode(buf);
        }
    }

    pub(crate) fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        nexthop: &mut Option<Ipv4Addr>,
        nlri_present: bool,
        mp_unreach: &mut Option<MpUnreachNlri>,
        mp_reach: &mut Option<MpReachNlri>,
    ) -> Result<Option<Self>, UpdateMessageError> {
        let mut origin = None;
        let mut as_path = None;
        let mut as4_path = None;
        let mut med = None;
        let mut local_pref = None;
        let mut aggregator = None;
        let mut as4_aggregator = None;
        let mut atomic_aggregate = false;
        let mut originator_id = None;
        let mut cluster_list = None;
        let mut comm = None;
        let mut ext_comm = None;
        let mut extv6_comm = None;
        let mut large_comm = None;
        let mut unknown = vec![];
        let mut withdraw = false;

        // Check whether the 4-octet AS number capability has been negotiated.
        let four_byte_asn_cap = cxt
            .capabilities
            .iter()
            .any(|cap| cap.is_four_octet_as_number());

        // List of parsed attributes.
        let mut attr_list = HashSet::new();

        // Parse attributes.
        while buf.remaining() > 0 {
            if buf.remaining() < 2 {
                withdraw = true;
                break;
            }

            // Parse attribute flags.
            let attr_flags = buf.get_u8();
            let mut attr_flags = AttrFlags::from_bits_truncate(attr_flags);

            // Parse attribute type.
            let attr_type_raw = buf.get_u8();
            let attr_type = AttrType::from_u8(attr_type_raw);

            // Parse attribute length.
            let attr_len = if attr_flags.contains(AttrFlags::EXTENDED) {
                if buf.remaining() < 2 {
                    withdraw = true;
                    break;
                }
                buf.get_u16() as usize
            } else {
                if buf.remaining() < 1 {
                    withdraw = true;
                    break;
                }
                buf.get_u8() as usize
            };
            if attr_len > buf.remaining() {
                withdraw = true;
                break;
            }
            let mut buf = buf.copy_to_bytes(attr_len);

            // RFC 7606 - Section 3.c:
            // "If the value of either the Optional or Transitive bits in the
            // Attribute Flags is in conflict with their specified values, then
            // the attribute MUST be treated as malformed and the
            // "treat-as-withdraw" approach used".
            if let Some(attr_type) = attr_type
                && (attr_flags & (AttrFlags::OPTIONAL | AttrFlags::TRANSITIVE))
                    != attribute_flags(attr_type)
            {
                withdraw = true;
                continue;
            }

            // RFC 7606 - Section 3.g:
            // "If the MP_REACH_NLRI attribute or the MP_UNREACH_NLRI attribute
            // appears more than once in the UPDATE message, then a NOTIFICATION
            // message MUST be sent with the Error Subcode "Malformed Attribute
            // List". If any other attribute (whether recognized or
            // unrecognized) appears more than once in an UPDATE message, then
            // all the occurrences of the attribute other than the first one
            // SHALL be discarded and the UPDATE message will continue to be
            // processed".
            if !attr_list.insert(attr_type_raw) {
                if matches!(
                    attr_type,
                    Some(AttrType::MpReachNlri | AttrType::MpUnreachNlri)
                ) {
                    return Err(UpdateMessageError::MalformedAttributeList);
                } else {
                    continue;
                }
            }

            // Parse attribute value.
            match attr_type {
                // Known attribute.
                Some(attr_type) => {
                    if let Err(error) = match attr_type {
                        AttrType::Origin => {
                            origin::decode(&mut buf, &mut origin)
                        }
                        AttrType::AsPath => AsPath::decode(
                            &mut buf,
                            cxt,
                            attr_type,
                            four_byte_asn_cap,
                            &mut as_path,
                        ),
                        AttrType::Nexthop => nexthop::decode(&mut buf, nexthop),
                        AttrType::Med => med::decode(&mut buf, &mut med),
                        AttrType::LocalPref => {
                            local_pref::decode(&mut buf, cxt, &mut local_pref)
                        }
                        AttrType::AtomicAggregate => atomic_aggregate::decode(
                            &mut buf,
                            &mut atomic_aggregate,
                        ),
                        AttrType::Aggregator => Aggregator::decode(
                            &mut buf,
                            attr_type,
                            four_byte_asn_cap,
                            &mut aggregator,
                        ),
                        AttrType::Communities => {
                            Comms::decode(&mut buf, &mut comm)
                        }
                        AttrType::OriginatorId => originator_id::decode(
                            &mut buf,
                            cxt,
                            &mut originator_id,
                        ),
                        AttrType::ClusterList => ClusterList::decode(
                            &mut buf,
                            cxt,
                            &mut cluster_list,
                        ),
                        AttrType::MpReachNlri => {
                            MpReachNlri::decode(&mut buf, mp_reach)
                        }
                        AttrType::MpUnreachNlri => {
                            MpUnreachNlri::decode(&mut buf, mp_unreach)
                        }
                        AttrType::ExtCommunities => {
                            ExtComms::decode(&mut buf, &mut ext_comm)
                        }
                        AttrType::As4Path => AsPath::decode(
                            &mut buf,
                            cxt,
                            attr_type,
                            four_byte_asn_cap,
                            &mut as4_path,
                        ),
                        AttrType::As4Aggregator => Aggregator::decode(
                            &mut buf,
                            attr_type,
                            four_byte_asn_cap,
                            &mut as4_aggregator,
                        ),
                        AttrType::Extv6Community => {
                            Extv6Comms::decode(&mut buf, &mut extv6_comm)
                        }
                        AttrType::LargeCommunity => {
                            LargeComms::decode(&mut buf, &mut large_comm)
                        }
                    } {
                        // Log malformed attribute.
                        Debug::NbrAttrError(attr_type, error).log();

                        // Process malformed attribute.
                        match error {
                            AttrError::Discard => continue,
                            AttrError::Withdraw => withdraw = true,
                            AttrError::Reset => {
                                return Err(
                                    UpdateMessageError::OptionalAttributeError,
                                )
                            }
                        }
                    }
                }
                // Unknown attribute.
                None => {
                    // RFC 4271 - Section 6.3:
                    // "If any of the well-known mandatory attributes are not
                    // recognized, then the Error Subcode MUST be set to
                    // Unrecognized Well-known Attribute.  The Data field MUST
                    // contain the unrecognized attribute (type, length, and
                    // value)".
                    if !attr_flags.contains(AttrFlags::OPTIONAL) {
                        return Err(
                            UpdateMessageError::UnrecognizedWellKnownAttribute,
                        );
                    }

                    // RFC 4271 - Section 9:
                    // "If an optional non-transitive attribute is unrecognized,
                    // it is quietly ignored".
                    if !attr_flags.contains(AttrFlags::TRANSITIVE) {
                        continue;
                    }

                    // RFC 4271 - Section 9:
                    // "If an optional transitive attribute is unrecognized, the
                    // Partial bit in the attribute flags octet is set to 1, and
                    // the attribute is retained for propagation to other BGP
                    // speakers".
                    attr_flags.insert(AttrFlags::PARTIAL);
                    let attr_value = buf.copy_to_bytes(attr_len);
                    unknown.push(UnknownAttr::new(
                        attr_type_raw,
                        attr_flags,
                        attr_len as u16,
                        attr_value,
                    ));
                }
            }
        }

        // Check for missing well-known attributes.
        //
        // RFC 7606 - Section 3.d:
        // "If any of the well-known mandatory attributes are not present in
        //  an UPDATE message, then "treat-as-withdraw" MUST be used".
        let mut attrs = None;
        if !withdraw
            && let Some(origin) = origin
            && let Some(as_path) = as_path
            && (local_pref.is_some() || cxt.peer_type == PeerType::External)
            && (nexthop.is_some() || !nlri_present)
        {
            attrs = Some(Attrs {
                base: BaseAttrs {
                    origin,
                    as_path,
                    as4_path,
                    nexthop: None,
                    ll_nexthop: None,
                    med,
                    local_pref,
                    aggregator,
                    as4_aggregator,
                    atomic_aggregate,
                    originator_id,
                    cluster_list,
                },
                comm,
                ext_comm,
                extv6_comm,
                large_comm,
                unknown,
            });
        }
        Ok(attrs)
    }

    pub(crate) fn length(&self) -> u16 {
        let mut length = 0;

        length += origin::length();
        length += self.base.as_path.length();
        if self.base.med.is_some() {
            length += med::length();
        }
        if self.base.local_pref.is_some() {
            length += local_pref::length();
        }
        if self.base.atomic_aggregate {
            length += atomic_aggregate::length();
        }
        if let Some(aggregator) = &self.base.aggregator {
            length += aggregator.length();
        }
        if let Some(comm) = &self.comm {
            length += comm.length();
        }
        if self.base.originator_id.is_some() {
            length += originator_id::length();
        }
        if let Some(cluster_list) = &self.base.cluster_list {
            length += cluster_list.length();
        }
        if let Some(ext_comm) = &self.ext_comm {
            length += ext_comm.length();
        }
        if let Some(as4_path) = &self.base.as4_path {
            length += as4_path.length();
        }
        if let Some(as4_aggregator) = &self.base.as4_aggregator {
            length += as4_aggregator.length();
        }
        if let Some(extv6_comm) = &self.extv6_comm {
            length += extv6_comm.length();
        }
        if let Some(large_comm) = &self.large_comm {
            length += large_comm.length();
        }

        length
    }
}

// ===== ORIGIN attribute =====

mod origin {
    use super::*;
    const LEN: u8 = 1;

    pub(super) fn encode(origin: Origin, buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::TRANSITIVE.bits());
        buf.put_u8(AttrType::Origin as u8);
        buf.put_u8(LEN);
        buf.put_u8(origin as u8);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        origin: &mut Option<Origin>,
    ) -> Result<(), AttrError> {
        if buf.remaining() != LEN as usize {
            return Err(AttrError::Withdraw);
        }

        let value = buf.get_u8();
        match Origin::from_u8(value) {
            Some(value) => {
                *origin = Some(value);
                Ok(())
            }
            None => Err(AttrError::Withdraw),
        }
    }

    pub(super) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== impl AsPath =====

impl AsPath {
    fn encode(
        &self,
        buf: &mut BytesMut,
        mut attr_flags: AttrFlags,
        attr_type: AttrType,
        four_byte_asns: bool,
    ) {
        attr_flags.insert(AttrFlags::EXTENDED);
        buf.put_u8(attr_flags.bits());
        buf.put_u8(attr_type as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u16(0);

        // Encode attribute data.
        for segment in &self.segments {
            segment.encode(buf, four_byte_asns);
        }

        // Rewrite attribute length.
        let attr_len = (buf.len() - start_pos - 2) as u16;
        buf[start_pos..start_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    }

    fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        attr_type: AttrType,
        four_byte_asn_cap: bool,
        as_path: &mut Option<AsPath>,
    ) -> Result<(), AttrError> {
        if attr_type == AttrType::As4Path && four_byte_asn_cap {
            return Err(AttrError::Discard);
        }

        let four_byte_asns =
            four_byte_asn_cap || attr_type == AttrType::As4Path;

        // Decode AS Path segments.
        let mut segments = VecDeque::new();
        while buf.remaining() > 0 {
            let segment =
                AsPathSegment::decode(buf, attr_type, four_byte_asns)?;
            segments.push_back(segment);
        }
        let value = AsPath { segments };

        // First AS check for eBGP peers.
        if attr_type == AttrType::AsPath
            && cxt.peer_type == PeerType::External
            && value
                .segments
                .iter()
                .find(|segment| segment.seg_type == AsPathSegmentType::Sequence)
                .and_then(|segment| segment.members.front().copied())
                != Some(cxt.peer_as)
        {
            return Err(AttrError::Withdraw);
        }

        *as_path = Some(value);
        Ok(())
    }

    pub(super) fn length(&self) -> u16 {
        ATTR_MIN_LEN_EXT
            + self
                .segments
                .iter()
                .map(|segment| segment.length())
                .sum::<u16>()
    }

    pub(crate) fn path_length(&self) -> u32 {
        self.segments
            .iter()
            .map(|segment| match segment.seg_type {
                AsPathSegmentType::Set => 1,
                AsPathSegmentType::Sequence => segment.members.len(),
                // RFC 5065 - Section 5.3:
                // "When comparing routes using AS_PATH length, CONFED_SEQUENCE
                // and CONFED_SETs SHOULD NOT be counted".
                AsPathSegmentType::ConfedSequence
                | AsPathSegmentType::ConfedSet => 0,
            })
            .sum::<usize>() as u32
    }

    pub(crate) fn first(&self) -> Option<u32> {
        self.segments
            .front()
            .filter(|segment| segment.seg_type == AsPathSegmentType::Sequence)
            .and_then(|segment| segment.members.front().copied())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.segments
            .iter()
            .flat_map(|segment| segment.members.iter().copied())
    }

    pub(crate) fn prepend(&mut self, asn: u32) {
        if let Some(segment) = self.segments.front_mut()
            && segment.seg_type == AsPathSegmentType::Sequence
            && segment.members.len() < 255
        {
            segment.members.push_front(asn);
        } else {
            self.segments.push_front(AsPathSegment {
                seg_type: AsPathSegmentType::Sequence,
                members: [asn].into(),
            });
        }
    }

    pub(crate) fn replace(&mut self, from: u32, to: u32) {
        for segment in self.segments.iter_mut() {
            for member in segment.members.iter_mut() {
                if *member == from {
                    *member = to;
                }
            }
        }
    }

    pub(crate) fn contains(&self, asn: u32) -> bool {
        self.segments.iter().any(|segment| segment.contains(asn))
    }
}

impl AsPathSegment {
    const MIN_LEN: u16 = 2;

    fn encode(&self, buf: &mut BytesMut, four_byte_asns: bool) {
        buf.put_u8(self.seg_type as u8);
        buf.put_u8(self.members.len() as u8);
        for member in &self.members {
            encode_asn(buf, *member, four_byte_asns);
        }
    }

    fn decode(
        buf: &mut Bytes,
        attr_type: AttrType,
        four_byte_asns: bool,
    ) -> Result<Self, AttrError> {
        // Decode segment type.
        let seg_type = buf.get_u8();
        let Some(seg_type) = AsPathSegmentType::from_u8(seg_type) else {
            if attr_type == AttrType::AsPath {
                return Err(AttrError::Withdraw);
            } else {
                return Err(AttrError::Discard);
            }
        };

        // Decode segment length.
        let seg_len = buf.get_u8();
        if seg_len == 0 {
            if attr_type == AttrType::AsPath {
                return Err(AttrError::Withdraw);
            } else {
                return Err(AttrError::Discard);
            }
        }

        // Decode segment members.
        let members = (0..seg_len as usize)
            .map(|_| decode_asn(buf, four_byte_asns))
            .collect();
        let segment = AsPathSegment { seg_type, members };

        // RFC 7607's AS 0 processing.
        if segment.contains(0) {
            if attr_type == AttrType::AsPath {
                return Err(AttrError::Withdraw);
            } else {
                return Err(AttrError::Discard);
            }
        }

        Ok(segment)
    }

    pub(super) fn length(&self) -> u16 {
        // Assume four-byte ASNs for practical purposes.
        Self::MIN_LEN + self.members.len() as u16 * 4
    }

    fn contains(&self, asn: u32) -> bool {
        self.members.iter().any(|member| asn == *member)
    }
}

// ===== NEXT_HOP attribute =====

pub(crate) mod nexthop {
    use super::*;
    const LEN: u8 = 4;

    pub(super) fn encode(addr: Ipv4Addr, buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::TRANSITIVE.bits());
        buf.put_u8(AttrType::Nexthop as u8);
        buf.put_u8(LEN);
        buf.put_ipv4(&addr);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        nexthop: &mut Option<Ipv4Addr>,
    ) -> Result<(), AttrError> {
        if buf.remaining() != LEN as usize {
            return Err(AttrError::Withdraw);
        }

        let value = buf.get_ipv4();
        *nexthop = Some(value);
        Ok(())
    }

    pub(crate) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== MULTI_EXIT_DISC attribute =====

mod med {
    use super::*;
    const LEN: u8 = 4;

    pub(super) fn encode(metric: u32, buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::OPTIONAL.bits());
        buf.put_u8(AttrType::Med as u8);
        buf.put_u8(LEN);
        buf.put_u32(metric);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        med: &mut Option<u32>,
    ) -> Result<(), AttrError> {
        if buf.remaining() != LEN as usize {
            return Err(AttrError::Withdraw);
        }

        let value = buf.get_u32();
        *med = Some(value);
        Ok(())
    }

    pub(super) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== LOCAL_PREF attribute =====

mod local_pref {
    use super::*;
    const LEN: u8 = 4;

    pub(super) fn encode(local_pref: u32, buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::TRANSITIVE.bits());
        buf.put_u8(AttrType::LocalPref as u8);
        buf.put_u8(LEN);
        buf.put_u32(local_pref);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        local_pref: &mut Option<u32>,
    ) -> Result<(), AttrError> {
        if cxt.peer_type == PeerType::External {
            return Err(AttrError::Discard);
        }

        if buf.remaining() != LEN as usize {
            return Err(AttrError::Withdraw);
        }

        let value = buf.get_u32();
        *local_pref = Some(value);
        Ok(())
    }

    pub(super) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== ATOMIC_AGGREGATE attribute =====

mod atomic_aggregate {
    use super::*;
    const LEN: u8 = 0;

    pub(super) fn encode(buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::TRANSITIVE.bits());
        buf.put_u8(AttrType::AtomicAggregate as u8);
        buf.put_u8(LEN);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        atomic_aggregate: &mut bool,
    ) -> Result<(), AttrError> {
        if buf.remaining() != LEN as usize {
            return Err(AttrError::Discard);
        }

        *atomic_aggregate = true;
        Ok(())
    }

    pub(super) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== impl Aggregator =====

impl Aggregator {
    fn encode(
        &self,
        buf: &mut BytesMut,
        attr_flags: AttrFlags,
        attr_type: AttrType,
        four_byte_asns: bool,
    ) {
        buf.put_u8(attr_flags.bits());
        buf.put_u8(attr_type as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u8(0);

        // Encode attribute data.
        encode_asn(buf, self.asn, four_byte_asns);
        buf.put_ipv4(&self.identifier);

        // Rewrite attribute length.
        let attr_len = buf.len() - start_pos - 1;
        buf[start_pos] = attr_len as u8;
    }

    fn decode(
        buf: &mut Bytes,
        attr_type: AttrType,
        four_byte_asn_cap: bool,
        aggregator: &mut Option<Self>,
    ) -> Result<(), AttrError> {
        if attr_type == AttrType::As4Aggregator && four_byte_asn_cap {
            return Err(AttrError::Discard);
        }

        let four_byte_asns =
            four_byte_asn_cap || attr_type == AttrType::As4Aggregator;
        let len = if four_byte_asns { 8 } else { 6 };
        if buf.remaining() != len {
            return Err(AttrError::Discard);
        }

        let asn = decode_asn(buf, four_byte_asns);
        let identifier = buf.get_ipv4();

        // RFC 7607's AS 0 processing.
        if asn == 0 {
            return Err(AttrError::Discard);
        }

        *aggregator = Some(Aggregator { asn, identifier });
        Ok(())
    }

    pub(super) fn length(&self) -> u16 {
        // Assume four-byte ASN for practical purposes.
        ATTR_MIN_LEN + 4 + Ipv4Addr::LENGTH as u16
    }
}

// ===== ORIGINATOR_ID attribute =====

mod originator_id {
    use super::*;
    const LEN: u8 = 4;

    pub(super) fn encode(originator_id: Ipv4Addr, buf: &mut BytesMut) {
        buf.put_u8(AttrFlags::OPTIONAL.bits());
        buf.put_u8(AttrType::OriginatorId as u8);
        buf.put_u8(LEN);
        buf.put_ipv4(&originator_id);
    }

    pub(super) fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        originator_id: &mut Option<Ipv4Addr>,
    ) -> Result<(), AttrError> {
        if cxt.peer_type == PeerType::External {
            return Err(AttrError::Discard);
        }

        if buf.remaining() != LEN as usize {
            return Err(AttrError::Withdraw);
        }

        let value = buf.get_ipv4();
        *originator_id = Some(value);
        Ok(())
    }

    pub(super) fn length() -> u16 {
        ATTR_MIN_LEN + LEN as u16
    }
}

// ===== impl ClusterList =====

impl ClusterList {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((AttrFlags::OPTIONAL | AttrFlags::EXTENDED).bits());
        buf.put_u8(AttrType::ClusterList as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u16(0);

        // Encode attribute data.
        for cluster_id in &self.0 {
            buf.put_ipv4(cluster_id);
        }

        // Rewrite attribute length.
        let attr_len = (buf.len() - start_pos - 2) as u16;
        buf[start_pos..start_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    }

    fn decode(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        cluster_list: &mut Option<Self>,
    ) -> Result<(), AttrError> {
        if cxt.peer_type == PeerType::External {
            return Err(AttrError::Discard);
        }

        if buf.remaining() == 0 || buf.remaining() % 4 != 0 {
            return Err(AttrError::Withdraw);
        }

        let mut list = BTreeSet::new();
        while buf.remaining() > 0 {
            let cluster_id = buf.get_ipv4();
            list.insert(cluster_id);
        }

        *cluster_list = Some(ClusterList(list));
        Ok(())
    }

    fn length(&self) -> u16 {
        ATTR_MIN_LEN_EXT + (self.0.len() * Ipv4Addr::LENGTH) as u16
    }
}

// ===== impl MpReachNlri =====

impl MpReachNlri {
    pub const MIN_LEN: u16 = 5;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((AttrFlags::OPTIONAL | AttrFlags::EXTENDED).bits());
        buf.put_u8(AttrType::MpReachNlri as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u16(0);

        // Encode attribute data.
        match self {
            MpReachNlri::Ipv4Unicast { prefixes, nexthop } => {
                buf.put_u16(Afi::Ipv4 as u16);
                buf.put_u8(Safi::Unicast as u8);
                buf.put_u8(Ipv4Addr::LENGTH as u8);
                buf.put_ipv4(nexthop);
                buf.put_u8(0);
                for prefix in prefixes {
                    encode_ipv4_prefix(buf, prefix);
                }
            }
            MpReachNlri::Ipv6Unicast {
                prefixes,
                nexthop,
                ll_nexthop,
            } => {
                buf.put_u16(Afi::Ipv6 as u16);
                buf.put_u8(Safi::Unicast as u8);
                if let Some(ll_nexthop) = ll_nexthop {
                    buf.put_u8((Ipv6Addr::LENGTH * 2) as u8);
                    buf.put_ipv6(nexthop);
                    buf.put_ipv6(ll_nexthop);
                } else {
                    buf.put_u8(Ipv6Addr::LENGTH as u8);
                    buf.put_ipv6(nexthop);
                }
                buf.put_u8(0);
                for prefix in prefixes {
                    encode_ipv6_prefix(buf, prefix);
                }
            }
        }

        // Rewrite attribute length.
        let attr_len = (buf.len() - start_pos - 2) as u16;
        buf[start_pos..start_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    }

    fn decode(
        buf: &mut Bytes,
        mp_reach: &mut Option<Self>,
    ) -> Result<(), AttrError> {
        if buf.remaining() < Self::MIN_LEN as usize {
            return Err(AttrError::Reset);
        }

        // Parse AFI.
        let afi = buf.get_u16();
        let Some(afi) = Afi::from_u16(afi) else {
            // Ignore unknown AFI.
            return Err(AttrError::Discard);
        };

        // Parse SAFI.
        let safi = buf.get_u8();
        if Safi::from_u8(safi) != Some(Safi::Unicast) {
            // Ignore unsupported SAFI.
            return Err(AttrError::Discard);
        };

        match afi {
            Afi::Ipv4 => {
                let mut prefixes = Vec::new();

                // Parse nexthop.
                let nexthop_len = buf.get_u8();
                if nexthop_len as usize != Ipv4Addr::LENGTH
                    || nexthop_len as usize > buf.remaining()
                {
                    return Err(AttrError::Reset);
                }
                let nexthop = buf.get_ipv4();

                // Parse prefixes.
                let _reserved = buf.get_u8();
                while buf.remaining() > 0 {
                    if let Some(prefix) =
                        decode_ipv4_prefix(buf).map_err(|_| AttrError::Reset)?
                    {
                        prefixes.push(prefix);
                    }
                }

                *mp_reach =
                    Some(MpReachNlri::Ipv4Unicast { prefixes, nexthop });
            }
            Afi::Ipv6 => {
                let mut prefixes = Vec::new();
                let mut ll_nexthop = None;

                // Parse nexthops(s).
                let nexthop_len = buf.get_u8() as usize;
                if (nexthop_len != Ipv6Addr::LENGTH
                    && nexthop_len != Ipv6Addr::LENGTH * 2)
                    || nexthop_len > buf.remaining()
                {
                    return Err(AttrError::Reset);
                }
                let nexthop = buf.get_ipv6();
                if nexthop_len == Ipv6Addr::LENGTH * 2 {
                    ll_nexthop = Some(buf.get_ipv6());
                }

                // Parse prefixes.
                let _reserved = buf.get_u8();
                while buf.remaining() > 0 {
                    if let Some(prefix) =
                        decode_ipv6_prefix(buf).map_err(|_| AttrError::Reset)?
                    {
                        prefixes.push(prefix);
                    }
                }

                *mp_reach = Some(MpReachNlri::Ipv6Unicast {
                    prefixes,
                    nexthop,
                    ll_nexthop,
                });
            }
        }

        Ok(())
    }
}

// ===== impl MpUnreachNlri =====

impl MpUnreachNlri {
    pub const MIN_LEN: u16 = 3;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((AttrFlags::OPTIONAL | AttrFlags::EXTENDED).bits());
        buf.put_u8(AttrType::MpUnreachNlri as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u16(0);

        // Encode attribute data.
        match self {
            MpUnreachNlri::Ipv4Unicast { prefixes } => {
                buf.put_u16(Afi::Ipv4 as u16);
                buf.put_u8(Safi::Unicast as u8);
                for prefix in prefixes {
                    encode_ipv4_prefix(buf, prefix);
                }
            }
            MpUnreachNlri::Ipv6Unicast { prefixes } => {
                buf.put_u16(Afi::Ipv6 as u16);
                buf.put_u8(Safi::Unicast as u8);
                for prefix in prefixes {
                    encode_ipv6_prefix(buf, prefix);
                }
            }
        }

        // Rewrite attribute length.
        let attr_len = (buf.len() - start_pos - 2) as u16;
        buf[start_pos..start_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    }

    fn decode(
        buf: &mut Bytes,
        mp_unreach: &mut Option<Self>,
    ) -> Result<(), AttrError> {
        if buf.remaining() < Self::MIN_LEN as usize {
            return Err(AttrError::Reset);
        }

        // Parse AFI.
        let afi = buf.get_u16();
        let Some(afi) = Afi::from_u16(afi) else {
            // Ignore unknown AFI.
            return Err(AttrError::Discard);
        };

        // Parse SAFI.
        let safi = buf.get_u8();
        if Safi::from_u8(safi) != Some(Safi::Unicast) {
            // Ignore unsupported SAFI.
            return Err(AttrError::Discard);
        };

        // Parse prefixes.
        match afi {
            Afi::Ipv4 => {
                let mut prefixes = Vec::new();

                while buf.remaining() > 0 {
                    if let Some(prefix) =
                        decode_ipv4_prefix(buf).map_err(|_| AttrError::Reset)?
                    {
                        prefixes.push(prefix);
                    }
                }

                *mp_unreach = Some(MpUnreachNlri::Ipv4Unicast { prefixes });
            }
            Afi::Ipv6 => {
                let mut prefixes = Vec::new();

                while buf.remaining() > 0 {
                    if let Some(prefix) =
                        decode_ipv6_prefix(buf).map_err(|_| AttrError::Reset)?
                    {
                        prefixes.push(prefix);
                    }
                }

                *mp_unreach = Some(MpUnreachNlri::Ipv6Unicast { prefixes });
            }
        }

        Ok(())
    }
}

// ===== impl Comm =====

impl CommType for Comm {
    const TYPE: AttrType = AttrType::Communities;
    const LENGTH: usize = 4;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    fn decode(buf: &mut Bytes) -> Self {
        let value = buf.get_u32();
        Self(value)
    }
}

// ===== impl ExtComm =====

impl CommType for ExtComm {
    const TYPE: AttrType = AttrType::ExtCommunities;
    const LENGTH: usize = 8;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.0);
    }

    fn decode(buf: &mut Bytes) -> Self {
        let mut value = [0; 8];
        buf.copy_to_slice(&mut value);
        Self(value)
    }
}

// ===== impl Extv6Comm =====

impl CommType for Extv6Comm {
    const TYPE: AttrType = AttrType::Extv6Community;
    const LENGTH: usize = 20;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_ipv6(&self.0);
        buf.put_u32(self.1);
    }

    fn decode(buf: &mut Bytes) -> Self {
        let addr = buf.get_ipv6();
        let local = buf.get_u32();
        Self(addr, local)
    }
}

// ===== impl LargeComm =====

impl CommType for LargeComm {
    const TYPE: AttrType = AttrType::LargeCommunity;
    const LENGTH: usize = 12;

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.0);
    }

    fn decode(buf: &mut Bytes) -> Self {
        let mut value = [0; 12];
        buf.copy_to_slice(&mut value);
        Self(value)
    }
}

// ===== impl CommList =====

impl<T: CommType> CommList<T> {
    fn encode(&self, buf: &mut BytesMut) {
        let attr_flags =
            AttrFlags::TRANSITIVE | AttrFlags::OPTIONAL | AttrFlags::EXTENDED;
        buf.put_u8(attr_flags.bits());
        buf.put_u8(T::TYPE as u8);

        // The length field will be initialized later.
        let start_pos = buf.len();
        buf.put_u16(0);

        // Encode attribute data.
        for value in &self.0 {
            value.encode(buf);
        }

        // Rewrite attribute length.
        let attr_len = (buf.len() - start_pos - 2) as u16;
        buf[start_pos..start_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    }

    fn decode(
        buf: &mut Bytes,
        comm: &mut Option<Self>,
    ) -> Result<(), AttrError> {
        if buf.remaining() == 0 || buf.remaining() % T::LENGTH != 0 {
            return Err(AttrError::Withdraw);
        }

        let mut list = BTreeSet::new();
        while buf.remaining() >= T::LENGTH {
            let value = T::decode(buf);
            list.insert(value);
        }

        *comm = Some(CommList(list));
        Ok(())
    }

    fn length(&self) -> u16 {
        ATTR_MIN_LEN_EXT + (self.0.len() * T::LENGTH) as u16
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }
}

// ===== helper functions =====

fn attribute_flags(attr_type: AttrType) -> AttrFlags {
    match attr_type {
        // Well-known.
        AttrType::Origin
        | AttrType::AsPath
        | AttrType::Nexthop
        | AttrType::LocalPref
        | AttrType::AtomicAggregate => AttrFlags::TRANSITIVE,

        // Optional non-transitive.
        AttrType::Med
        | AttrType::OriginatorId
        | AttrType::ClusterList
        | AttrType::MpReachNlri
        | AttrType::MpUnreachNlri => AttrFlags::OPTIONAL,

        // Optional transitive.
        AttrType::Aggregator
        | AttrType::Communities
        | AttrType::ExtCommunities
        | AttrType::As4Path
        | AttrType::As4Aggregator
        | AttrType::Extv6Community
        | AttrType::LargeCommunity => {
            AttrFlags::TRANSITIVE | AttrFlags::OPTIONAL
        }
    }
}

fn encode_asn(buf: &mut BytesMut, asn: u32, four_byte_asns: bool) {
    if four_byte_asns {
        buf.put_u32(asn)
    } else {
        buf.put_u16(asn as u16)
    }
}

fn decode_asn(buf: &mut Bytes, four_byte_asns: bool) -> u32 {
    if four_byte_asns {
        buf.get_u32()
    } else {
        buf.get_u16() as u32
    }
}
