//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bytes::TLS_BUF;
use holo_utils::ip::AddressFamily;
use holo_utils::mpls::Label;
use holo_utils::sr::Sid;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::lsdb::{LSA_MAX_AGE, LSA_RESERVED_SEQ_NO};
use crate::packet::error::{DecodeError, DecodeResult, LsaValidationError};
use crate::packet::tlv::{AdjSidFlags, GrReason, PrefixSidFlags};
use crate::version::Version;

// OSPF LSA.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Lsa<V: Version> {
    // LSA raw bytes.
    #[cfg_attr(feature = "testing", serde(default, skip_serializing))]
    pub raw: Bytes,
    // LSA header.
    pub hdr: V::LsaHdr,
    // LSA body.
    pub body: V::LsaBody,
    // Time the LSA was created or received. When combined with the Age field
    // in the LSA header, the actual LSA age can be determined.
    #[serde(skip)]
    pub base_time: Option<Instant>,
}

// OSPF LSA key. It serves both as a global LSA identifier and as a key to store
// LSAs in an LSDB.
//
// Please be aware that modifying the order of the fields will impact operations
// such as iterating over LSDBs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, new)]
#[derive(Deserialize, Serialize)]
pub struct LsaKey<T: LsaTypeVersion> {
    // LSA type.
    #[serde(bound = "T: LsaTypeVersion")]
    pub lsa_type: T,
    // LSA advertising router.
    pub adv_rtr: Ipv4Addr,
    // LSA ID.
    pub lsa_id: Ipv4Addr,
}

// OSPF LSA scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LsaScope {
    Link,
    Area,
    As,
    Unknown,
}

// OSPF version-specific code.
pub trait LsaVersion<V: Version> {
    type LsaType: LsaTypeVersion;
    type LsaHdr: LsaHdrVersion<V>;
    type LsaBody: LsaBodyVersion<V>;
    type LsaRouterFlags: LsaRouterFlagsVersion;
    type LsaRouterLink;
    type PrefixOptions: PrefixOptionsVersion;
    type PrefixSid: PrefixSidVersion;
    type AdjSid: AdjSidVersion;

    // Return LSA type for inter-area network LSAs.
    fn type3_summary(extended_lsa: bool) -> Self::LsaType;

    // Return LSA type for inter-area router LSAs.
    fn type4_summary(extended_lsa: bool) -> Self::LsaType;
}

// OSPF version-specific code.
pub trait LsaTypeVersion
where
    Self: Send
        + Sync
        + Clone
        + Copy
        + Ord
        + PartialOrd
        + std::fmt::Debug
        + std::fmt::Display
        + std::hash::Hash
        + Into<u16>
        + Serialize
        + DeserializeOwned,
{
    // Return the scope associated to the LSA type.
    fn scope(&self) -> LsaScope;

    // Return whether the LSA type, as seen from the Graceful Restart
    // perspective, corresponds to topology-related information (types 1-5,
    // 7).
    fn is_gr_topology_info(&self) -> bool;
}

// OSPF version-specific code.
pub trait LsaHdrVersion<V: Version>
where
    Self: Send
        + Sync
        + Clone
        + Copy
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned,
{
    const LENGTH: u16;

    fn new(
        age: u16,
        options: Option<V::PacketOptions>,
        lsa_type: V::LsaType,
        lsa_id: Ipv4Addr,
        adv_rtr: Ipv4Addr,
        seq_no: u32,
    ) -> Self;

    fn decode(buf: &mut Bytes) -> DecodeResult<Self>;

    fn encode(&self, buf: &mut BytesMut);

    fn lsa_type(&self) -> V::LsaType;

    fn lsa_id(&self) -> Ipv4Addr;

    fn age(&self) -> u16;

    fn set_age(&mut self, age: u16);

    fn is_maxage(&self) -> bool {
        self.age() == LSA_MAX_AGE
    }

    fn options(&self) -> Option<V::PacketOptions>;

    fn adv_rtr(&self) -> Ipv4Addr;

    fn seq_no(&self) -> u32;

    fn set_cksum(&mut self, value: u16);

    fn cksum(&self) -> u16;

    fn key(&self) -> LsaKey<V::LsaType> {
        LsaKey {
            lsa_type: self.lsa_type(),
            adv_rtr: self.adv_rtr(),
            lsa_id: self.lsa_id(),
        }
    }

    fn length(&self) -> u16;

    fn set_length(&mut self, length: u16);
}

// OSPF version-specific code.
pub trait LsaBodyVersion<V: Version>
where
    Self: Send + Sync + Clone + std::fmt::Debug + Serialize + DeserializeOwned,
{
    fn decode(
        af: AddressFamily,
        lsa_type: V::LsaType,
        lsa_id: Ipv4Addr,
        buf: &mut Bytes,
    ) -> DecodeResult<Self>;
    fn encode(&self, buf: &mut BytesMut);
    fn lsa_type(&self) -> V::LsaType;
    fn is_unknown(&self) -> bool;
    fn validate(&self, hdr: &V::LsaHdr) -> Result<(), LsaValidationError>;
    fn as_grace(&self) -> Option<(u32, GrReason, Option<V::NetIpAddr>)>;
}

// OSPF version-specific code.
pub trait LsaRouterFlagsVersion
where
    Self: Send + Sync + Clone + std::fmt::Debug + Serialize + DeserializeOwned,
{
    fn is_abr(&self) -> bool;
    fn is_asbr(&self) -> bool;
}

// OSPF version-specific code.
pub trait PrefixOptionsVersion
where
    Self: Send
        + Sync
        + Clone
        + Copy
        + Default
        + Eq
        + PartialEq
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned,
{
}

// OSPF version-specific code.
pub trait PrefixSidVersion
where
    Self: Send + Sync + Clone + Copy + Eq + PartialEq + std::fmt::Debug,
{
    fn flags(&self) -> PrefixSidFlags;

    fn flags_mut(&mut self) -> &mut PrefixSidFlags;

    fn sid(&self) -> Sid;
}

// OSPF version-specific code.
pub trait AdjSidVersion
where
    Self: Send + Sync + Clone + Copy + Eq + PartialEq + std::fmt::Debug,
{
    fn new(label: Label, weight: u8, nbr_router_id: Option<Ipv4Addr>) -> Self;

    fn flags(&self) -> AdjSidFlags;

    fn sid(&self) -> Sid;
}

// ===== impl Lsa =====

impl<V> Lsa<V>
where
    V: Version,
{
    // LSA maximum length
    //
    // Opt for a conservative value to avoid packet fragmentation even in
    // low-MTU links.
    pub const MAX_LENGTH: usize = 1024;

    pub fn new(
        age: u16,
        options: Option<V::PacketOptions>,
        lsa_id: Ipv4Addr,
        adv_rtr: Ipv4Addr,
        seq_no: u32,
        body: V::LsaBody,
    ) -> Self {
        // Build LSA header (the length and checksum are computed later).
        let hdr = V::LsaHdr::new(
            age,
            options,
            body.lsa_type(),
            lsa_id,
            adv_rtr,
            seq_no,
        );

        // Build full LSA and encode it.
        let mut lsa = Lsa {
            raw: Default::default(),
            hdr,
            body,
            base_time: lsa_base_time(),
        };
        lsa.encode();
        lsa
    }

    // Returns the current LSA age.
    pub(crate) fn age(&self) -> u16 {
        match self.base_time {
            Some(base_time) => {
                let elapsed = u16::try_from(base_time.elapsed().as_secs())
                    .unwrap_or(u16::MAX);
                std::cmp::min(
                    self.hdr.age().saturating_add(elapsed),
                    LSA_MAX_AGE,
                )
            }
            None => self.hdr.age(),
        }
    }

    // Updates the LSA age.
    pub(crate) fn set_age(&mut self, age: u16) {
        // Update header.
        self.hdr.set_age(age);

        // Update raw data.
        let mut raw = BytesMut::from(self.raw.as_ref());
        raw[0..2].copy_from_slice(&age.to_be_bytes());
        self.raw = raw.freeze();

        // Update base time.
        self.base_time = lsa_base_time();
    }

    // Sets the LSA age to MaxAge.
    pub(crate) fn set_maxage(&mut self) {
        self.set_age(LSA_MAX_AGE);
    }

    // Decodes LSA from a bytes buffer.
    pub fn decode(af: AddressFamily, buf: &mut Bytes) -> DecodeResult<Self> {
        // Decode LSA header.
        let buf_orig = buf.clone();
        if buf.remaining() < V::LsaHdr::LENGTH as usize {
            return Err(DecodeError::InvalidLength(buf.len() as u16));
        }
        let hdr = V::LsaHdr::decode(buf)?;
        let lsa_len = hdr.length();
        if lsa_len < V::LsaHdr::LENGTH {
            return Err(DecodeError::InvalidLsaLength);
        }
        let lsa_body_len = lsa_len - V::LsaHdr::LENGTH;

        // Decode LSA body.
        if buf.remaining() < lsa_body_len as usize {
            return Err(DecodeError::InvalidLsaLength);
        }
        let mut buf_lsa = buf.copy_to_bytes(lsa_body_len as usize);
        let body =
            V::LsaBody::decode(af, hdr.lsa_type(), hdr.lsa_id(), &mut buf_lsa)?;

        Ok(Lsa {
            raw: buf_orig.slice(0..lsa_len as usize),
            hdr,
            body,
            base_time: lsa_base_time(),
        })
    }

    // Encodes LSA into a bytes buffer.
    pub(crate) fn encode(&mut self) {
        // Encode LSA in network byte order.
        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            self.hdr.encode(&mut buf);
            self.body.encode(&mut buf);

            // Rewrite LSA length.
            let lsa_len = buf.len() as u16;
            buf[18..20].copy_from_slice(&lsa_len.to_be_bytes());
            self.hdr.set_length(lsa_len);

            // Compute LSA checksum.
            let cksum = Self::checksum(&buf[2..(lsa_len as usize)]);
            buf[16..18].copy_from_slice(&cksum);
            self.hdr.set_cksum(u16::from_be_bytes(cksum));

            // Store LSA raw data.
            self.raw = buf.clone().freeze();
        });
    }

    pub(crate) fn validate(&self) -> Result<(), LsaValidationError> {
        // Validate LSA header.
        if self.hdr.age() > LSA_MAX_AGE {
            return Err(LsaValidationError::InvalidLsaAge);
        }
        if self.hdr.seq_no() == LSA_RESERVED_SEQ_NO {
            return Err(LsaValidationError::InvalidLsaSeqNo);
        }
        if !self.is_checksum_valid() {
            return Err(LsaValidationError::InvalidChecksum);
        }

        // Validate LSA body.
        self.body.validate(&self.hdr)?;

        Ok(())
    }

    fn checksum(data: &[u8]) -> [u8; 2] {
        let checksum = fletcher::calc_fletcher16(data);
        let mut checkbyte0 = (checksum & 0x00FF) as i32;
        let mut checkbyte1 = ((checksum >> 8) & 0x00FF) as i32;

        // Adjust checksum value using scaling factor.
        let sop = data.len() as u16 - 15;
        let mut x = (sop as i32 * checkbyte0 - checkbyte1) % 255;
        if x <= 0 {
            x += 255;
        }
        checkbyte1 = 510 - checkbyte0 - x;
        if checkbyte1 > 255 {
            checkbyte1 -= 255;
        }
        checkbyte0 = x;
        [checkbyte0 as u8, checkbyte1 as u8]
    }

    // Checks if the checksum is valid.
    fn is_checksum_valid(&self) -> bool {
        // Skip checksum validation in testing mode if the checksum field is set
        // to zero.
        #[cfg(feature = "testing")]
        {
            if self.hdr.cksum() == 0 {
                return true;
            }
        }

        // Skip the Age field.
        fletcher::calc_fletcher16(&self.raw[2..(self.hdr.length() as usize)])
            == 0
    }
}

// ===== helper functions =====

fn lsa_base_time() -> Option<Instant> {
    #[cfg(not(feature = "testing"))]
    {
        Some(Instant::now())
    }
    #[cfg(feature = "testing")]
    {
        None
    }
}

// ===== global functions =====

// When serializing an LSA header in testing mode, skip the age field as it's
// unimportant and non-deterministic, with one exception: when the LSA age is
// MaxAge. It's important to differentiate this specific case for more precise
// testing.
pub fn serde_lsa_age_filter(age: &u16) -> bool {
    *age != 3600
}
