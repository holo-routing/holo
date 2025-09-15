//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cell::{RefCell, RefMut};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::TLS_BUF;
use holo_utils::crypto::{CryptoAlgo, HMAC_APAD};
use holo_utils::keychain::Key;
use holo_utils::mac_addr::MacAddr;
use holo_yang::ToYang;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use tracing::debug_span;

use crate::packet::auth::AuthMethod;
use crate::packet::consts::{
    IDRP_DISCRIMINATOR, MtId, PduType, SYSTEM_ID_LEN, TlvType, VERSION,
    VERSION_PROTO_EXT,
};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::subtlvs::capability::{SrAlgoStlv, SrCapabilitiesStlv};
use crate::packet::tlv::{
    AreaAddressesTlv, AuthenticationTlv, DynamicHostnameTlv, ExtendedSeqNum,
    ExtendedSeqNumTlv, Ipv4AddressesTlv, Ipv4Reach, Ipv4ReachTlv,
    Ipv4RouterIdTlv, Ipv6AddressesTlv, Ipv6Reach, Ipv6ReachTlv,
    Ipv6RouterIdTlv, IsReach, IsReachTlv, LegacyIpv4Reach, LegacyIpv4ReachTlv,
    LegacyIsReach, LegacyIsReachTlv, LspBufferSizeTlv, LspEntriesTlv, LspEntry,
    MtFlags, MultiTopologyEntry, MultiTopologyTlv, NeighborsTlv, PaddingTlv,
    ProtocolsSupportedTlv, PurgeOriginatorIdTlv, RouterCapTlv, TLV_HDR_SIZE,
    TLV_MAX_LEN, ThreeWayAdjTlv, Tlv, UnknownTlv, tlv_entries_split,
    tlv_take_max,
};
use crate::packet::{
    AreaAddr, LanId, LevelNumber, LevelType, LspId, SystemId, auth,
};

// IS-IS PDU.
#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Pdu {
    Hello(Hello),
    Lsp(Lsp),
    Snp(Snp),
}

// IS-IS PDU common header.
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Header {
    pub pdu_type: PduType,
    pub max_area_addrs: u8,
}

// IS-IS Hello PDU.
#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Hello {
    pub hdr: Header,
    pub circuit_type: LevelType,
    pub source: SystemId,
    pub holdtime: u16,
    pub variant: HelloVariant,
    pub tlvs: HelloTlvs,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum HelloVariant {
    Lan { priority: u8, lan_id: LanId },
    P2P { local_circuit_id: u8 },
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct HelloTlvs {
    pub protocols_supported: Option<ProtocolsSupportedTlv>,
    pub area_addrs: Vec<AreaAddressesTlv>,
    pub multi_topology: Vec<MultiTopologyTlv>,
    pub neighbors: Vec<NeighborsTlv>,
    pub three_way_adj: Option<ThreeWayAdjTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
    pub ext_seqnum: Option<ExtendedSeqNumTlv>,
    pub padding: Vec<PaddingTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// IS-IS Link State PDU.
#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Lsp {
    pub hdr: Header,
    #[cfg_attr(
        feature = "testing",
        serde(default, skip_serializing_if = "serde_lsp_rem_lifetime_filter")
    )]
    pub rem_lifetime: u16,
    // Remaining lifetime of this LSP at the time it was received.
    #[serde(skip)]
    pub rcvd_rem_lifetime: Option<u16>,
    pub lsp_id: LspId,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub seqno: u32,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub cksum: u16,
    pub flags: LspFlags,
    pub tlvs: LspTlvs,
    #[cfg_attr(feature = "testing", serde(skip_serializing))]
    pub raw: Bytes,
    // Time the LSP was created or received. When combined with the Remaining
    // Lifetime field, the actual LSP remaining lifetime can be determined.
    #[serde(skip)]
    pub base_time: Option<Instant>,
}

// IS-IS LSP flags field.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct LspFlags: u8 {
        const P = 0x80;
        const ATT = 0x40;
        const OL = 0x04;
        const IS_TYPE2 = 0x02;
        const IS_TYPE1 = 0x01;
    }
}
#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct LspTlvs {
    pub auth: Option<AuthenticationTlv>,
    pub protocols_supported: Option<ProtocolsSupportedTlv>,
    pub router_cap: Vec<RouterCapTlv>,
    pub area_addrs: Vec<AreaAddressesTlv>,
    pub multi_topology: Vec<MultiTopologyTlv>,
    pub purge_originator_id: Option<PurgeOriginatorIdTlv>,
    pub hostname: Option<DynamicHostnameTlv>,
    pub lsp_buf_size: Option<LspBufferSizeTlv>,
    pub is_reach: Vec<LegacyIsReachTlv>,
    pub ext_is_reach: Vec<IsReachTlv>,
    pub mt_is_reach: Vec<IsReachTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv4_internal_reach: Vec<LegacyIpv4ReachTlv>,
    pub ipv4_external_reach: Vec<LegacyIpv4ReachTlv>,
    pub ext_ipv4_reach: Vec<Ipv4ReachTlv>,
    pub mt_ipv4_reach: Vec<Ipv4ReachTlv>,
    pub ipv4_router_id: Option<Ipv4RouterIdTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
    pub ipv6_reach: Vec<Ipv6ReachTlv>,
    pub mt_ipv6_reach: Vec<Ipv6ReachTlv>,
    pub ipv6_router_id: Option<Ipv6RouterIdTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// IS-IS Sequence Numbers PDU.
#[derive(Clone, Debug, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Snp {
    pub hdr: Header,
    pub source: LanId,
    pub summary: Option<(LspId, LspId)>,
    pub tlvs: SnpTlvs,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[serde_with::apply(
    Option => #[serde(default, skip_serializing_if = "Option::is_none")],
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct SnpTlvs {
    pub lsp_entries: Vec<LspEntriesTlv>,
    pub ext_seqnum: Option<ExtendedSeqNumTlv>,
    pub unknown: Vec<UnknownTlv>,
}

// ===== impl Pdu =====

impl Pdu {
    // Decodes IS-IS PDU from a bytes buffer.
    pub fn decode(
        mut buf: Bytes,
        hello_auth: Option<&AuthMethod>,
        global_auth: Option<&AuthMethod>,
    ) -> DecodeResult<Self> {
        let buf_orig = BytesMut::from(buf.clone());

        // Decode PDU common header.
        let hdr = Header::decode(&mut buf)?;

        // Decode PDU-specific fields.
        let pdu = match hdr.pdu_type {
            PduType::HelloLanL1 | PduType::HelloLanL2 | PduType::HelloP2P => {
                Pdu::Hello(Hello::decode(hdr, &mut buf, buf_orig, hello_auth)?)
            }
            PduType::LspL1 | PduType::LspL2 => {
                Pdu::Lsp(Lsp::decode(hdr, &mut buf, buf_orig, global_auth)?)
            }
            PduType::CsnpL1
            | PduType::CsnpL2
            | PduType::PsnpL1
            | PduType::PsnpL2 => {
                Pdu::Snp(Snp::decode(hdr, &mut buf, buf_orig, global_auth)?)
            }
        };

        Ok(pdu)
    }

    // Encodes IS-IS PDU into a bytes buffer.
    pub fn encode(&self, auth: Option<&Key>) -> Bytes {
        match self {
            Pdu::Hello(pdu) => pdu.encode(auth),
            Pdu::Lsp(pdu) => pdu.raw.clone(),
            Pdu::Snp(pdu) => pdu.encode(auth),
        }
    }

    // Returns the IS-IS PDU type.
    pub const fn pdu_type(&self) -> PduType {
        match self {
            Pdu::Hello(pdu) => pdu.hdr.pdu_type,
            Pdu::Lsp(pdu) => pdu.hdr.pdu_type,
            Pdu::Snp(pdu) => pdu.hdr.pdu_type,
        }
    }

    // Validates the PDU authentication.
    fn decode_auth_validate(
        mut buf_orig: BytesMut,
        is_lsp: bool,
        auth: &AuthMethod,
        tlv_auth: Option<(AuthenticationTlv, usize)>,
    ) -> DecodeResult<AuthenticationTlv> {
        // Get authentication TLV.
        let Some(tlv_auth) = tlv_auth else {
            return Err(DecodeError::AuthTypeMismatch);
        };

        match &tlv_auth {
            // Clear-text authentication.
            (AuthenticationTlv::ClearText(passwd), _) => {
                // Get authentication key.
                let auth_key = auth
                    .get_key_accept_any()
                    .ok_or(DecodeError::AuthKeyNotFound)?;

                // Check for authentication type mismatch.
                if auth_key.algo != CryptoAlgo::ClearText {
                    return Err(DecodeError::AuthTypeMismatch);
                }

                // Validate the received password.
                if *passwd != auth_key.string {
                    return Err(DecodeError::AuthError);
                }
            }
            // HMAC-MD5 authentication.
            (AuthenticationTlv::HmacMd5(tlv_digest), tlv_offset) => {
                // Get authentication key.
                let auth_key = auth
                    .get_key_accept_any()
                    .ok_or(DecodeError::AuthKeyNotFound)?;

                // Check for authentication type mismatch.
                if auth_key.algo != CryptoAlgo::HmacMd5 {
                    return Err(DecodeError::AuthTypeMismatch);
                }

                // If processing an LSP, zero out the Checksum and Remaining
                // Lifetime fields.
                if is_lsp {
                    buf_orig[Lsp::REM_LIFETIME_RANGE].fill(0);
                    buf_orig[Lsp::CKSUM_RANGE].fill(0);
                }

                // Zero out the digest field before computing the new digest.
                let digest_size = auth_key.algo.digest_size() as usize;
                let digest_offset = tlv_offset + 1;
                buf_orig[digest_offset..digest_offset + digest_size].fill(0);

                // Compute the expected message digest.
                let digest = auth::message_digest(
                    &buf_orig,
                    auth_key.algo,
                    &auth_key.string,
                );

                // Validate the received digest.
                if *tlv_digest != *digest {
                    return Err(DecodeError::AuthError);
                }
            }
            // Cryptographic authentication.
            (
                AuthenticationTlv::Cryptographic {
                    key_id,
                    digest: tlv_digest,
                },
                tlv_offset,
            ) => {
                // Get authentication key.
                let auth_key = auth
                    .get_key_accept(*key_id)
                    .ok_or(DecodeError::AuthKeyNotFound)?;

                // Check for authentication type mismatch.
                if !matches!(
                    auth_key.algo,
                    CryptoAlgo::HmacSha1
                        | CryptoAlgo::HmacSha256
                        | CryptoAlgo::HmacSha384
                        | CryptoAlgo::HmacSha512
                ) {
                    return Err(DecodeError::AuthTypeMismatch);
                }

                // If processing an LSP, zero out the Checksum and Remaining
                // Lifetime fields.
                if is_lsp {
                    buf_orig[Lsp::REM_LIFETIME_RANGE].fill(0);
                    buf_orig[Lsp::CKSUM_RANGE].fill(0);
                }

                // Initialize the digest field with Apad (0x878FE1F3...).
                let digest_size = auth_key.algo.digest_size() as usize;
                let digest_offset = tlv_offset + 3;
                buf_orig[digest_offset..digest_offset + digest_size]
                    .copy_from_slice(&HMAC_APAD[..digest_size]);

                // Compute the expected message digest.
                let digest = auth::message_digest(
                    &buf_orig,
                    auth_key.algo,
                    &auth_key.string,
                );

                // Validate the received digest.
                if *tlv_digest != *digest {
                    return Err(DecodeError::AuthError);
                }
            }
        }

        Ok(tlv_auth.0)
    }

    // Returns an Authentication TLV for encoding a PDU with the given key.
    fn encode_auth_tlv(auth_key: &Key) -> Option<AuthenticationTlv> {
        match auth_key.algo {
            CryptoAlgo::ClearText => {
                let tlv = AuthenticationTlv::ClearText(auth_key.string.clone());
                Some(tlv)
            }
            CryptoAlgo::HmacMd5 => {
                // RFC 5304: HMAC-MD5 digest is initialized to zero.
                let tlv = AuthenticationTlv::HmacMd5([0; 16]);
                Some(tlv)
            }
            CryptoAlgo::HmacSha1
            | CryptoAlgo::HmacSha256
            | CryptoAlgo::HmacSha384
            | CryptoAlgo::HmacSha512 => {
                // RFC 5310: Digest is initialized using Apad (0x878FE1F3...).
                let tlv = AuthenticationTlv::Cryptographic {
                    key_id: auth_key.id as u16,
                    digest: HMAC_APAD[..auth_key.algo.digest_size() as usize]
                        .to_vec(),
                };
                Some(tlv)
            }
            _ => None,
        }
    }

    // Calculates the length of the Authentication TLV for a given key.
    pub(crate) fn auth_tlv_len(auth_key: &Key) -> usize {
        let mut len = TLV_HDR_SIZE + AuthenticationTlv::MIN_LEN;
        match auth_key.algo {
            CryptoAlgo::ClearText => {
                // Add length of the clear-text key, limited to TLV max.
                len += std::cmp::min(auth_key.string.len(), TLV_MAX_LEN);
            }
            CryptoAlgo::HmacMd5 => {
                // Add the digest size for HMAC-MD5.
                len += auth_key.algo.digest_size() as usize;
            }
            _ => {
                // Add 2 bytes for the Key ID, plus the digest size.
                len += 2;
                len += auth_key.algo.digest_size() as usize;
            }
        }
        len
    }
}

// ===== impl Header =====

impl Header {
    const LEN: u8 = 8;

    pub const fn new(pdu_type: PduType) -> Self {
        Header {
            pdu_type,
            max_area_addrs: 0,
        }
    }

    // Decodes IS-IS PDU header from a bytes buffer.
    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let packet_len = buf.len();

        // Ensure the packet has enough data for the fixed-length IS-IS header.
        if packet_len < Self::LEN as _ {
            return Err(DecodeError::IncompletePdu);
        }

        // Parse IDRP discriminator.
        let idrp_discr = buf.try_get_u8()?;
        if idrp_discr != IDRP_DISCRIMINATOR {
            return Err(DecodeError::InvalidIrdpDiscriminator(idrp_discr));
        }

        // Parse length of fixed header.
        let fixed_header_length = buf.try_get_u8()?;

        // Parse version/protocol ID extension.
        let version_proto_ext = buf.try_get_u8()?;
        if version_proto_ext != VERSION_PROTO_EXT {
            return Err(DecodeError::InvalidVersion(version_proto_ext));
        }

        // Parse ID length.
        let id_len = buf.try_get_u8()?;
        if id_len != 0 && id_len != SYSTEM_ID_LEN {
            return Err(DecodeError::InvalidIdLength(id_len));
        }

        // Parse PDU type.
        let pdu_type = buf.try_get_u8()?;
        let pdu_type = match PduType::from_u8(pdu_type) {
            Some(pdu_type) => pdu_type,
            None => return Err(DecodeError::UnknownPduType(pdu_type)),
        };

        // Additional sanity checks.
        if fixed_header_length != Self::fixed_header_length(pdu_type) {
            return Err(DecodeError::InvalidHeaderLength(fixed_header_length));
        }
        if packet_len < fixed_header_length as _ {
            return Err(DecodeError::IncompletePdu);
        }

        // Parse version.
        let version = buf.try_get_u8()?;
        if version != VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Parse reserved field.
        let _reserved = buf.try_get_u8()?;

        // Parse maximum area addresses.
        let max_area_addrs = buf.try_get_u8()?;

        Ok(Header {
            pdu_type,
            max_area_addrs,
        })
    }

    // Encodes IS-IS PDU header into a bytes buffer.
    fn encode(&self, buf: &mut BytesMut) {
        // Encode IDRP discriminator.
        buf.put_u8(IDRP_DISCRIMINATOR);
        // Encode length of fixed header.
        buf.put_u8(Self::fixed_header_length(self.pdu_type));
        // Encode version/protocol ID extension.
        buf.put_u8(VERSION_PROTO_EXT);
        // Encode ID length (use default value).
        buf.put_u8(0);
        // Encode PDU type.
        buf.put_u8(self.pdu_type as u8);
        // Encode version.
        buf.put_u8(VERSION);
        // Encode reserved field.
        buf.put_u8(0);
        // Encode maximum area addresses.
        buf.put_u8(self.max_area_addrs);
    }

    // Returns the length of the fixed header for a given PDU type.
    const fn fixed_header_length(pdu_type: PduType) -> u8 {
        match pdu_type {
            PduType::HelloLanL1 | PduType::HelloLanL2 => Hello::HEADER_LEN_LAN,
            PduType::HelloP2P => Hello::HEADER_LEN_P2P,
            PduType::LspL1 | PduType::LspL2 => Lsp::HEADER_LEN,
            PduType::CsnpL1 | PduType::CsnpL2 => Snp::CSNP_HEADER_LEN,
            PduType::PsnpL1 | PduType::PsnpL2 => Snp::PSNP_HEADER_LEN,
        }
    }
}

// ===== impl Hello =====

impl Hello {
    const HEADER_LEN_LAN: u8 = 27;
    const HEADER_LEN_P2P: u8 = 20;
    const CIRCUIT_TYPE_MASK: u8 = 0x03;
    const PRIORITY_MASK: u8 = 0x7F;

    pub fn new(
        level_type: LevelType,
        circuit_type: LevelType,
        source: SystemId,
        holdtime: u16,
        variant: HelloVariant,
        tlvs: HelloTlvs,
    ) -> Self {
        let pdu_type = match level_type {
            LevelType::L1 => PduType::HelloLanL1,
            LevelType::L2 => PduType::HelloLanL2,
            LevelType::All => PduType::HelloP2P,
        };
        Hello {
            hdr: Header::new(pdu_type),
            circuit_type,
            source,
            holdtime,
            variant,
            tlvs,
        }
    }

    fn decode(
        hdr: Header,
        buf: &mut Bytes,
        buf_orig: BytesMut,
        auth: Option<&AuthMethod>,
    ) -> DecodeResult<Self> {
        // Parse circuit type.
        let circuit_type = buf.try_get_u8()? & Self::CIRCUIT_TYPE_MASK;
        let circuit_type = match circuit_type {
            1 if hdr.pdu_type != PduType::HelloLanL2 => LevelType::L1,
            2 if hdr.pdu_type != PduType::HelloLanL1 => LevelType::L2,
            3 => LevelType::All,
            _ => {
                return Err(DecodeError::InvalidHelloCircuitType(circuit_type));
            }
        };

        // Parse source ID.
        let source = SystemId::decode(buf)?;

        // Parse holding time.
        let holdtime = buf.try_get_u16()?;
        if holdtime == 0 {
            return Err(DecodeError::InvalidHelloHoldtime(holdtime));
        }

        // Parse PDU length.
        let pdu_len = buf.try_get_u16()?;
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse custom fields.
        let variant = if hdr.pdu_type == PduType::HelloP2P {
            // Parse local circuit ID.
            let local_circuit_id = buf.try_get_u8()?;

            HelloVariant::P2P { local_circuit_id }
        } else {
            // Parse priority.
            let priority = buf.try_get_u8()? & Self::PRIORITY_MASK;
            // Parse LAN ID.
            let lan_id = LanId::decode(buf)?;

            HelloVariant::Lan { priority, lan_id }
        };

        // Parse top-level TLVs.
        let span = debug_span!("Hello", source = %source.to_yang());
        let _span_guard = span.enter();
        let mut tlvs = HelloTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.try_get_u8()?;
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.try_get_u8()?;
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let span = debug_span!("TLV", r#type = tlv_type, length = tlv_len);
            let _span_guard = span.enter();
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    match AreaAddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.area_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::MultiTopology) => {
                    match MultiTopologyTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.multi_topology.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Neighbors)
                    if hdr.pdu_type != PduType::HelloP2P =>
                {
                    match NeighborsTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.neighbors.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ThreeWayAdj)
                    if hdr.pdu_type == PduType::HelloP2P =>
                {
                    if tlvs.three_way_adj.is_some() {
                        continue;
                    }
                    match ThreeWayAdjTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.three_way_adj = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Padding) => {
                    match PaddingTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.padding.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    match AuthenticationTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlv_auth = Some((tlv, tlv_offset)),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ExtendedSeqNum) => {
                    if tlvs.ext_seqnum.is_some() {
                        return Err(DecodeError::MultipleEsnTlvs);
                    }
                    match ExtendedSeqNumTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ext_seqnum = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    match ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.protocols_supported = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv4Addresses) => {
                    match Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv4_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv6Addresses) => {
                    match Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv6_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                _ => {
                    // Save unknown top-level TLV.
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, buf_tlv));
                }
            }
        }

        // Validate the PDU authentication.
        if let Some(auth) = auth {
            Pdu::decode_auth_validate(buf_orig, false, auth, tlv_auth)?;
        }

        Ok(Hello {
            hdr,
            circuit_type,
            source,
            holdtime,
            variant,
            tlvs,
        })
    }

    fn encode(&self, auth_key: Option<&Key>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            let circuit_type = match self.circuit_type {
                LevelType::L1 => 1,
                LevelType::L2 => 2,
                LevelType::All => 3,
            };
            buf.put_u8(circuit_type);
            self.source.encode(&mut buf);
            buf.put_u16(self.holdtime);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);

            match self.variant {
                HelloVariant::Lan { priority, lan_id } => {
                    buf.put_u8(priority);
                    lan_id.encode(&mut buf);
                }
                HelloVariant::P2P { local_circuit_id } => {
                    buf.put_u8(local_circuit_id);
                }
            }

            // Encode Authentication TLV.
            let auth = auth_key.and_then(|auth_key| {
                let auth_tlv = Pdu::encode_auth_tlv(auth_key)?;
                let auth_tlv_pos = buf.len();
                auth_tlv.encode(&mut buf);
                Some((auth_key, auth_tlv_pos))
            });

            // Encode other TLVs.
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.multi_topology {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.neighbors {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.three_way_adj {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.ext_seqnum {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.padding {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos, auth, None)
        })
    }

    pub(crate) fn add_padding(&mut self, max_size: u16) {
        // Compute the total length of existing TLVs.
        let mut total_tlv_len = 0;
        if let Some(tlv) = &self.tlvs.protocols_supported {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.area_addrs {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.multi_topology {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.neighbors {
            total_tlv_len += tlv.len();
        }
        if let Some(tlv) = &self.tlvs.three_way_adj {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.ipv4_addrs {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.ipv6_addrs {
            total_tlv_len += tlv.len();
        }
        if let Some(tlv) = &self.tlvs.ext_seqnum {
            total_tlv_len += tlv.len();
        }

        // Calculate the total padding required.
        let mut rem_padding = max_size as usize
            - Header::fixed_header_length(self.hdr.pdu_type) as usize
            - total_tlv_len;

        // Add as many Padding TLVs as necessary.
        while rem_padding >= 2 {
            let padding_len =
                std::cmp::min(rem_padding - TLV_HDR_SIZE, TLV_MAX_LEN);
            self.tlvs.padding.push(PaddingTlv {
                length: padding_len as u8,
            });
            rem_padding -= TLV_HDR_SIZE + padding_len;
        }
    }
}

impl HelloTlvs {
    pub(crate) fn new(
        protocols_supported: impl IntoIterator<Item = u8>,
        area_addrs: impl IntoIterator<Item = AreaAddr>,
        multi_topology: impl IntoIterator<Item = MultiTopologyEntry>,
        neighbors: impl IntoIterator<Item = MacAddr>,
        three_way_adj: Option<ThreeWayAdjTlv>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
        ext_seqnum: Option<ExtendedSeqNum>,
    ) -> Self {
        HelloTlvs {
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            area_addrs: tlv_entries_split(area_addrs),
            multi_topology: tlv_entries_split(multi_topology),
            neighbors: tlv_entries_split(neighbors),
            three_way_adj,
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            ext_seqnum: ext_seqnum.map(ExtendedSeqNumTlv::new),
            padding: Default::default(),
            unknown: Default::default(),
        }
    }

    // Returns an iterator over all supported protocols from the TLV of type 129.
    pub(crate) fn protocols_supported(&self) -> impl Iterator<Item = u8> + '_ {
        self.protocols_supported
            .iter()
            .flat_map(|tlv| tlv.list.iter())
            .copied()
    }

    // Returns an iterator over all area addresses from TLVs of type 1.
    pub(crate) fn area_addrs(&self) -> impl Iterator<Item = &AreaAddr> {
        self.area_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all multi-topology entries from TLVs of type
    // 229.
    pub(crate) fn multi_topology(
        &self,
    ) -> impl Iterator<Item = &MultiTopologyEntry> {
        self.multi_topology.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns the set of MT IDs from TLVs of type 229.
    //
    // If no multi-topology TLVs are present, the default MT ID 0 (Standard)
    // is returned.
    pub(crate) fn topologies(&self) -> BTreeSet<u16> {
        let topologies = self
            .multi_topology()
            .map(|mt| mt.mt_id)
            .collect::<BTreeSet<_>>();
        if topologies.is_empty() {
            return [MtId::Standard as u16].into();
        }
        topologies
    }

    // Returns an iterator over all IS neighbors from TLVs of type 6.
    pub(crate) fn neighbors(&self) -> impl Iterator<Item = &MacAddr> {
        self.neighbors.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 addresses from TLVs of type 132.
    pub(crate) fn ipv4_addrs(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.ipv4_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 addresses from TLVs of type 232.
    pub(crate) fn ipv6_addrs(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.ipv6_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }
}

// ===== impl Lsp =====

impl Lsp {
    pub const HEADER_LEN: u8 = 27;
    const REM_LIFETIME_RANGE: std::ops::Range<usize> = 10..12;
    const CKSUM_RANGE: std::ops::Range<usize> = 24..26;

    pub fn new(
        level: LevelNumber,
        rem_lifetime: u16,
        lsp_id: LspId,
        seqno: u32,
        flags: LspFlags,
        tlvs: LspTlvs,
        auth: Option<&Key>,
    ) -> Self {
        let pdu_type = match level {
            LevelNumber::L1 => PduType::LspL1,
            LevelNumber::L2 => PduType::LspL2,
        };
        let mut lsp = Lsp {
            hdr: Header::new(pdu_type),
            rem_lifetime,
            rcvd_rem_lifetime: None,
            lsp_id,
            seqno,
            cksum: 0,
            flags,
            tlvs,
            raw: Default::default(),
            base_time: lsp_base_time(),
        };
        lsp.encode(auth);
        lsp
    }

    fn decode(
        hdr: Header,
        buf: &mut Bytes,
        buf_orig: BytesMut,
        auth: Option<&AuthMethod>,
    ) -> DecodeResult<Self> {
        // Parse PDU length.
        let pdu_len = buf.try_get_u16()?;
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse remaining lifetime.
        let rem_lifetime = buf.try_get_u16()?;

        // Parse LSP ID.
        let lsp_id = LspId::decode(buf)?;

        // Parse sequence number.
        let seqno = buf.try_get_u32()?;

        // Parse checksum.
        let cksum = buf.try_get_u16()?;

        // Parse flags.
        let flags = buf.try_get_u8()?;
        let flags = LspFlags::from_bits_truncate(flags);

        // Parse top-level TLVs.
        let span = debug_span!("LSP", lsp_id = %lsp_id.to_yang(), seqno);
        let _span_guard = span.enter();
        let mut tlvs = LspTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.try_get_u8()?;
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.try_get_u8()?;
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let span = debug_span!("TLV", r#type = tlv_type, length = tlv_len);
            let _span_guard = span.enter();
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    match AreaAddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.area_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::MultiTopology) => {
                    match MultiTopologyTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.multi_topology.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    match AuthenticationTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlv_auth = Some((tlv, tlv_offset)),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::PurgeOriginatorId) => {
                    if tlvs.purge_originator_id.is_some() {
                        continue;
                    }
                    match PurgeOriginatorIdTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.purge_originator_id = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::DynamicHostname) => {
                    match DynamicHostnameTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.hostname = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::LspBufferSize) => {
                    match LspBufferSizeTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.lsp_buf_size = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::IsReach) => {
                    match LegacyIsReachTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.is_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ExtIsReach) => {
                    match IsReachTlv::decode(false, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ext_is_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::MtIsReach) => {
                    match IsReachTlv::decode(true, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => {
                            // The TLV MUST be ignored if the ID is zero.
                            if tlv.mt_id != Some(0) {
                                tlvs.mt_is_reach.push(tlv);
                            }
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv4InternalReach) => {
                    match LegacyIpv4ReachTlv::decode(
                        tlv_len,
                        &mut buf_tlv,
                        false,
                    ) {
                        Ok(tlv) => tlvs.ipv4_internal_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    match ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.protocols_supported = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv4ExternalReach) => {
                    match LegacyIpv4ReachTlv::decode(
                        tlv_len,
                        &mut buf_tlv,
                        true,
                    ) {
                        Ok(tlv) => tlvs.ipv4_external_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv4Addresses) => {
                    match Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv4_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ExtIpv4Reach) => {
                    match Ipv4ReachTlv::decode(false, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ext_ipv4_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::MtIpv4Reach) => {
                    match Ipv4ReachTlv::decode(true, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => {
                            // The TLV MUST be ignored if the ID is zero.
                            if tlv.mt_id != Some(0) {
                                tlvs.mt_ipv4_reach.push(tlv);
                            }
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv4RouterId) => {
                    if tlvs.ipv4_router_id.is_some() {
                        continue;
                    }
                    match Ipv4RouterIdTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv4_router_id = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv6Addresses) => {
                    match Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv6_addrs.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv6Reach) => {
                    match Ipv6ReachTlv::decode(false, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv6_reach.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::MtIpv6Reach) => {
                    match Ipv6ReachTlv::decode(true, tlv_len, &mut buf_tlv) {
                        Ok(tlv) => {
                            // The TLV MUST be ignored if the ID is zero.
                            if tlv.mt_id != Some(0) {
                                tlvs.mt_ipv6_reach.push(tlv);
                            }
                        }
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::Ipv6RouterId) => {
                    if tlvs.ipv6_router_id.is_some() {
                        continue;
                    }
                    match Ipv6RouterIdTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ipv6_router_id = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::RouterCapability) => {
                    match RouterCapTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.router_cap.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                _ => {
                    // Save unknown top-level TLV.
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, buf_tlv));
                }
            }
        }

        // Validate the PDU authentication.
        if let Some(auth) = auth {
            let tlv_auth =
                Pdu::decode_auth_validate(buf_orig, true, auth, tlv_auth)?;
            tlvs.auth = Some(tlv_auth);
        }

        Ok(Lsp {
            hdr,
            rem_lifetime,
            rcvd_rem_lifetime: None,
            lsp_id,
            seqno,
            cksum,
            flags,
            tlvs,
            raw: Default::default(),
            base_time: lsp_base_time(),
        })
    }

    pub(crate) fn encode(&mut self, auth_key: Option<&Key>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);
            // The remaining lifetime will be initialized later.
            buf.put_u16(0);
            self.lsp_id.encode(&mut buf);
            buf.put_u32(self.seqno);
            // The checksum will be initialized later.
            buf.put_u16(0);
            buf.put_u8(self.flags.bits());

            // Encode Authentication TLV.
            let auth = auth_key.and_then(|auth_key| {
                let auth_tlv = Pdu::encode_auth_tlv(auth_key)?;
                let auth_tlv_pos = buf.len();
                auth_tlv.encode(&mut buf);
                self.tlvs.auth = Some(auth_tlv);
                Some((auth_key, auth_tlv_pos))
            });

            // Encode other TLVs.
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.router_cap {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.multi_topology {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.purge_originator_id {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.hostname {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.lsp_buf_size {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.is_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ext_is_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.mt_is_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_internal_reach {
                tlv.encode(TlvType::Ipv4InternalReach, &mut buf);
            }
            for tlv in &self.tlvs.ipv4_external_reach {
                tlv.encode(TlvType::Ipv4ExternalReach, &mut buf);
            }
            for tlv in &self.tlvs.ext_ipv4_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.mt_ipv4_reach {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.ipv4_router_id {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_reach {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.mt_ipv6_reach {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.ipv6_router_id {
                tlv.encode(&mut buf);
            }

            // Store LSP raw data.
            let bytes = pdu_encode_end(buf, len_pos, auth, Some(self));
            self.raw = bytes.clone();
            bytes
        })
    }

    // Computes the LSP checksum.
    fn checksum(data: &[u8]) -> [u8; 2] {
        let checksum = fletcher::calc_fletcher16(data);
        let mut checkbyte0 = (checksum & 0x00FF) as i32;
        let mut checkbyte1 = ((checksum >> 8) & 0x00FF) as i32;

        // Adjust checksum value using scaling factor.
        let sop = data.len() as u16 - 13;
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

    // Checks if the LSP checksum is valid.
    pub(crate) fn is_checksum_valid(&self) -> bool {
        // Skip checksum validation in testing mode if the checksum field is set
        // to zero.
        #[cfg(feature = "testing")]
        {
            if self.cksum == 0 {
                return true;
            }
        }

        // RFC 3719 - Section 7:
        // "An implementation SHOULD treat all LSPs with a zero checksum and a
        // non-zero remaining lifetime as if they had as checksum error".
        if self.cksum == 0 {
            return self.rem_lifetime == 0;
        }

        // Skip everything before (and including) the Remaining Lifetime field.
        fletcher::calc_fletcher16(&self.raw[12..]) == 0
    }

    // Returns whether the LSP has expired (i.e., its remaining lifetime has
    // reached zero).
    pub(crate) fn is_expired(&self) -> bool {
        self.rem_lifetime == 0
    }

    // Returns the current LSP remaining lifetime.
    //
    // This value is computed by subtracting the elapsed time since the LSP was
    // received or originated from its initial lifetime.
    pub(crate) fn rem_lifetime(&self) -> u16 {
        let mut rem_lifetime = self.rem_lifetime;

        if let Some(base_time) = self.base_time {
            let elapsed = u16::try_from(base_time.elapsed().as_secs())
                .unwrap_or(u16::MAX);
            rem_lifetime = rem_lifetime.saturating_sub(elapsed);
        }

        rem_lifetime
    }

    // Updates the LSP remaining lifetime.
    pub(crate) fn set_rem_lifetime(&mut self, rem_lifetime: u16) {
        // Update Remaining Lifetime field.
        self.rem_lifetime = rem_lifetime;

        // Update raw data.
        #[cfg(not(feature = "testing"))]
        {
            let mut raw = BytesMut::from(self.raw.as_ref());
            raw[Self::REM_LIFETIME_RANGE]
                .copy_from_slice(&rem_lifetime.to_be_bytes());
            self.raw = raw.freeze();
        }

        // Update base time.
        self.base_time = lsp_base_time();
    }

    // Converts the LSP into an LSP Entry for use in an SNP.
    pub(crate) fn as_snp_entry(&self) -> LspEntry {
        LspEntry {
            rem_lifetime: self.rem_lifetime,
            lsp_id: self.lsp_id,
            seqno: self.seqno,
            cksum: self.cksum,
        }
    }

    // Checks if the ATTACH bit is set for the given topology ID.
    pub(crate) fn att_bit(&self, mt_id: MtId) -> bool {
        if mt_id == MtId::Standard {
            return self.flags.contains(LspFlags::ATT);
        }

        if let Some(mt) = self
            .tlvs
            .multi_topology()
            .find(|mt| mt.mt_id == mt_id as u16)
        {
            return mt.flags.contains(MtFlags::ATT);
        }

        false
    }

    // Checks if the OVERLOAD bit is set for the given topology ID.
    pub(crate) fn overload_bit(&self, mt_id: MtId) -> bool {
        if mt_id == MtId::Standard {
            return self.flags.contains(LspFlags::OL);
        }

        if let Some(mt) = self
            .tlvs
            .multi_topology()
            .find(|mt| mt.mt_id == mt_id as u16)
        {
            return mt.flags.contains(MtFlags::OL);
        }

        false
    }
}

impl LspTlvs {
    pub(crate) fn new(
        protocols_supported: impl IntoIterator<Item = u8>,
        router_cap: Vec<RouterCapTlv>,
        area_addrs: impl IntoIterator<Item = AreaAddr>,
        multi_topology: impl IntoIterator<Item = MultiTopologyEntry>,
        hostname: Option<String>,
        lsp_buf_size: Option<u16>,
        is_reach: impl IntoIterator<Item = LegacyIsReach>,
        ext_is_reach: impl IntoIterator<Item = IsReach>,
        mt_is_reach: impl IntoIterator<Item = IsReach>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv4_internal_reach: impl IntoIterator<Item = LegacyIpv4Reach>,
        ipv4_external_reach: impl IntoIterator<Item = LegacyIpv4Reach>,
        ext_ipv4_reach: impl IntoIterator<Item = Ipv4Reach>,
        mt_ipv4_reach: impl IntoIterator<Item = Ipv4Reach>,
        ipv4_router_id: Option<Ipv4Addr>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
        ipv6_reach: impl IntoIterator<Item = Ipv6Reach>,
        mt_ipv6_reach: impl IntoIterator<Item = Ipv6Reach>,
        ipv6_router_id: Option<Ipv6Addr>,
    ) -> Self {
        LspTlvs {
            auth: None,
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            router_cap,
            area_addrs: tlv_entries_split(area_addrs),
            multi_topology: tlv_entries_split(multi_topology),
            purge_originator_id: None,
            hostname: hostname.map(|hostname| DynamicHostnameTlv { hostname }),
            lsp_buf_size: lsp_buf_size.map(|size| LspBufferSizeTlv { size }),
            is_reach: tlv_entries_split(is_reach),
            ext_is_reach: tlv_entries_split(ext_is_reach),
            mt_is_reach: tlv_entries_split(mt_is_reach)
                .into_iter()
                .map(|mut tlv: IsReachTlv| {
                    tlv.mt_id = Some(MtId::Ipv6Unicast as u16);
                    tlv
                })
                .collect(),
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv4_internal_reach: tlv_entries_split(ipv4_internal_reach),
            ipv4_external_reach: tlv_entries_split(ipv4_external_reach),
            ext_ipv4_reach: tlv_entries_split(ext_ipv4_reach),
            mt_ipv4_reach: tlv_entries_split(mt_ipv4_reach),
            ipv4_router_id: ipv4_router_id.map(Ipv4RouterIdTlv::new),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            ipv6_reach: tlv_entries_split(ipv6_reach),
            mt_ipv6_reach: tlv_entries_split(mt_ipv6_reach)
                .into_iter()
                .map(|mut tlv: Ipv6ReachTlv| {
                    tlv.mt_id = Some(MtId::Ipv6Unicast as u16);
                    tlv
                })
                .collect(),
            ipv6_router_id: ipv6_router_id.map(Ipv6RouterIdTlv::new),
            unknown: Default::default(),
        }
    }

    pub(crate) fn next_chunk(&mut self, max_len: usize) -> Option<Self> {
        let mut rem_len = max_len;
        let protocols_supported = self.protocols_supported.take();
        if let Some(protocols_supported) = &protocols_supported {
            rem_len -= protocols_supported.len();
        }
        let router_cap = tlv_take_max(&mut self.router_cap, &mut rem_len);
        let area_addrs = tlv_take_max(&mut self.area_addrs, &mut rem_len);
        let multi_topology =
            tlv_take_max(&mut self.multi_topology, &mut rem_len);
        let hostname = self.hostname.take();
        if let Some(hostname) = &hostname {
            rem_len -= hostname.len();
        }
        let lsp_buf_size = self.lsp_buf_size.take();
        if let Some(lsp_buf_size) = &lsp_buf_size {
            rem_len -= lsp_buf_size.len();
        }
        let ipv4_router_id = self.ipv4_router_id.take();
        if let Some(ipv4_router_id) = &ipv4_router_id {
            rem_len -= ipv4_router_id.len();
        }
        let ipv6_router_id = self.ipv6_router_id.take();
        if let Some(ipv6_router_id) = &ipv6_router_id {
            rem_len -= ipv6_router_id.len();
        }
        let is_reach = tlv_take_max(&mut self.is_reach, &mut rem_len);
        let ext_is_reach = tlv_take_max(&mut self.ext_is_reach, &mut rem_len);
        let mt_is_reach = tlv_take_max(&mut self.mt_is_reach, &mut rem_len);
        let ipv4_addrs = tlv_take_max(&mut self.ipv4_addrs, &mut rem_len);
        let ipv4_internal_reach =
            tlv_take_max(&mut self.ipv4_internal_reach, &mut rem_len);
        let ipv4_external_reach =
            tlv_take_max(&mut self.ipv4_external_reach, &mut rem_len);
        let ext_ipv4_reach =
            tlv_take_max(&mut self.ext_ipv4_reach, &mut rem_len);
        let mt_ipv4_reach = tlv_take_max(&mut self.mt_ipv4_reach, &mut rem_len);
        let ipv6_addrs = tlv_take_max(&mut self.ipv6_addrs, &mut rem_len);
        let ipv6_reach = tlv_take_max(&mut self.ipv6_reach, &mut rem_len);
        let mt_ipv6_reach = tlv_take_max(&mut self.mt_ipv6_reach, &mut rem_len);
        if rem_len == max_len {
            return None;
        }

        Some(LspTlvs {
            auth: None,
            protocols_supported,
            router_cap,
            area_addrs,
            multi_topology,
            purge_originator_id: None,
            hostname,
            lsp_buf_size,
            is_reach,
            ext_is_reach,
            mt_is_reach,
            ipv4_addrs,
            ipv4_internal_reach,
            ipv4_external_reach,
            ext_ipv4_reach,
            mt_ipv4_reach,
            ipv4_router_id,
            ipv6_addrs,
            ipv6_reach,
            mt_ipv6_reach,
            ipv6_router_id,
            unknown: Default::default(),
        })
    }

    pub(crate) fn add_purge_originator_id(
        &mut self,
        system_id: SystemId,
        system_id_rcvd: Option<SystemId>,
        hostname: Option<String>,
    ) {
        self.purge_originator_id = Some(PurgeOriginatorIdTlv {
            system_id,
            system_id_rcvd,
        });
        self.hostname =
            hostname.map(|hostname| DynamicHostnameTlv { hostname });
    }

    // Returns whether the TLVs are valid in a purged LSP.
    //
    // RFC 5304 specifies that a purged LSP (Remaining Lifetime == 0) MUST NOT
    // contain any TLVs other than the Authentication TLV.
    //
    // RFC 6233 generalizes this rule: a purge MUST NOT include any TLV not
    // explicitly allowed in a purge, as listed in the IANA IS-IS TLV Codepoints
    // registry. It also introduces an exception: if a purge includes the Purge
    // Originator Identification TLV and does not include the Authentication
    // TLV, it is acceptable regardless of which other TLVs are present.
    //
    // The stricter rules for the authentication case are necessary to protect
    // against a hostile system receiving an LSP, setting its Remaining Lifetime
    // to zero, and flooding it, thereby initiating a purge without knowing the
    // authentication password.
    pub(crate) fn valid_purge_tlvs(&mut self) -> bool {
        if self.auth.is_none() && self.purge_originator_id.is_some() {
            return true;
        }

        self.protocols_supported.is_none()
            && self.router_cap.is_empty()
            && self.area_addrs.is_empty()
            && self.multi_topology.is_empty()
            && self.lsp_buf_size.is_none()
            && self.is_reach.is_empty()
            && self.ext_is_reach.is_empty()
            && self.mt_is_reach.is_empty()
            && self.ipv4_addrs.is_empty()
            && self.ipv4_internal_reach.is_empty()
            && self.ipv4_external_reach.is_empty()
            && self.ext_ipv4_reach.is_empty()
            && self.mt_ipv4_reach.is_empty()
            && self.ipv4_router_id.is_none()
            && self.ipv6_addrs.is_empty()
            && self.ipv6_reach.is_empty()
            && self.mt_ipv6_reach.is_empty()
            && self.ipv6_router_id.is_none()
    }

    // Returns an iterator over all supported protocols from the TLV of type 129.
    pub(crate) fn protocols_supported(&self) -> impl Iterator<Item = u8> + '_ {
        self.protocols_supported
            .iter()
            .flat_map(|tlv| tlv.list.iter())
            .copied()
    }

    // Returns an iterator over all area addresses from TLVs of type 1.
    pub(crate) fn area_addrs(&self) -> impl Iterator<Item = &AreaAddr> {
        self.area_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all multi-topology entries from TLVs of type
    // 229.
    pub(crate) fn multi_topology(
        &self,
    ) -> impl Iterator<Item = &MultiTopologyEntry> {
        self.multi_topology.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over mutable references to multi-topology entries
    // from TLVs of type 229.
    pub(crate) fn multi_topology_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut MultiTopologyEntry> {
        self.multi_topology
            .iter_mut()
            .flat_map(|tlv| tlv.list.iter_mut())
    }

    // Returns the dynamic hostname (TLV type 137).
    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_ref().map(|tlv| tlv.hostname.as_str())
    }

    // Returns the maximum sized LSP which may be generated (TLV type 14).
    pub(crate) fn lsp_buf_size(&self) -> Option<u16> {
        self.lsp_buf_size.as_ref().map(|tlv| tlv.size)
    }

    // Returns an iterator over all IS neighbors from TLVs of type 2.
    pub(crate) fn is_reach(&self) -> impl Iterator<Item = &LegacyIsReach> {
        self.is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 22.
    pub(crate) fn ext_is_reach(&self) -> impl Iterator<Item = &IsReach> {
        self.ext_is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 222.
    pub(crate) fn mt_is_reach(&self) -> impl Iterator<Item = (u16, &IsReach)> {
        self.mt_is_reach.iter().flat_map(|tlv| {
            tlv.list.iter().map(|reach| (tlv.mt_id.unwrap(), reach))
        })
    }

    // Returns an iterator over all IS neighbors from TLVs of type 222 with the
    // specified MT ID.
    pub(crate) fn mt_is_reach_by_id(
        &self,
        mt_id: MtId,
    ) -> impl Iterator<Item = &IsReach> {
        self.mt_is_reach
            .iter()
            .filter(move |tlv| tlv.mt_id.unwrap() == mt_id as u16)
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 addresses from TLVs of type 132.
    pub(crate) fn ipv4_addrs(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.ipv4_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 internal reachability entries from TLVs
    // of type 128.
    pub(crate) fn ipv4_internal_reach(
        &self,
    ) -> impl Iterator<Item = &LegacyIpv4Reach> {
        self.ipv4_internal_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 external reachability entries from TLVs
    // of type 130.
    pub(crate) fn ipv4_external_reach(
        &self,
    ) -> impl Iterator<Item = &LegacyIpv4Reach> {
        self.ipv4_external_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 reachability entries from TLVs of
    // type 135.
    pub(crate) fn ext_ipv4_reach(&self) -> impl Iterator<Item = &Ipv4Reach> {
        self.ext_ipv4_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 reachability entries from TLVs of
    // type 235.
    pub(crate) fn mt_ipv4_reach(
        &self,
    ) -> impl Iterator<Item = (u16, &Ipv4Reach)> {
        self.mt_ipv4_reach.iter().flat_map(|tlv| {
            tlv.list.iter().map(|reach| (tlv.mt_id.unwrap(), reach))
        })
    }

    // Returns an iterator over all IPv6 addresses from TLVs of type 232.
    pub(crate) fn ipv6_addrs(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.ipv6_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 reachability entries from TLVs of
    // type 236.
    pub(crate) fn ipv6_reach(&self) -> impl Iterator<Item = &Ipv6Reach> {
        self.ipv6_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv6 reachability entries from TLVs of
    // type 237.
    pub(crate) fn mt_ipv6_reach(
        &self,
    ) -> impl Iterator<Item = (u16, &Ipv6Reach)> {
        self.mt_ipv6_reach.iter().flat_map(|tlv| {
            tlv.list.iter().map(|reach| (tlv.mt_id.unwrap(), reach))
        })
    }

    // Returns an iterator over all IPv6 reachability entries from TLVs of
    // type 237 with the specified MT ID.
    pub(crate) fn mt_ipv6_reach_by_id(
        &self,
        mt_id: MtId,
    ) -> impl Iterator<Item = &Ipv6Reach> {
        self.mt_ipv6_reach
            .iter()
            .filter(move |tlv| tlv.mt_id.unwrap() == mt_id as u16)
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns the first SR-Capabilities Sub-TLV found within any Router
    // Capabilities TLV.
    pub(crate) fn sr_cap(&self) -> Option<&SrCapabilitiesStlv> {
        self.router_cap
            .iter()
            .find_map(|router_cap| router_cap.sub_tlvs.sr_cap.as_ref())
    }

    // Returns the first SR-Algorithm Sub-TLV found within any Router
    // Capabilities TLV.
    pub(crate) fn sr_algos(&self) -> Option<&SrAlgoStlv> {
        self.router_cap
            .iter()
            .find_map(|router_cap| router_cap.sub_tlvs.sr_algo.as_ref())
    }
}

// In conformance tests, we only care whether the LSP Remaining Lifetime is
// zero or non-zero. Non-zero values can be skipped during serialization.
pub fn serde_lsp_rem_lifetime_filter(rem_lifetime: &u16) -> bool {
    *rem_lifetime != 0
}

// ===== impl Snp =====

impl Snp {
    pub const CSNP_HEADER_LEN: u8 = 33;
    pub const PSNP_HEADER_LEN: u8 = 17;

    pub fn new(
        level: LevelNumber,
        source: LanId,
        summary: Option<(LspId, LspId)>,
        tlvs: SnpTlvs,
    ) -> Self {
        let pdu_type = match (summary.is_some(), level) {
            (false, LevelNumber::L1) => PduType::PsnpL1,
            (false, LevelNumber::L2) => PduType::PsnpL2,
            (true, LevelNumber::L1) => PduType::CsnpL1,
            (true, LevelNumber::L2) => PduType::CsnpL2,
        };
        Snp {
            hdr: Header::new(pdu_type),
            source,
            summary,
            tlvs,
        }
    }

    fn decode(
        hdr: Header,
        buf: &mut Bytes,
        buf_orig: BytesMut,
        auth: Option<&AuthMethod>,
    ) -> DecodeResult<Self> {
        // Parse PDU length.
        let pdu_len = buf.try_get_u16()?;
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse source ID.
        let source = LanId::decode(buf)?;

        // Parse start and end LSP IDs.
        let mut summary = None;
        if matches!(hdr.pdu_type, PduType::CsnpL1 | PduType::CsnpL2) {
            let start_lsp_id = LspId::decode(buf)?;
            let end_lsp_id = LspId::decode(buf)?;
            summary = Some((start_lsp_id, end_lsp_id));
        }

        // Parse top-level TLVs.
        let span = debug_span!("SNP", source = %source.to_yang());
        let _span_guard = span.enter();
        let mut tlvs = SnpTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.try_get_u8()?;
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.try_get_u8()?;
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let span = debug_span!("TLV", r#type = tlv_type, length = tlv_len);
            let _span_guard = span.enter();
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    match AuthenticationTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlv_auth = Some((tlv, tlv_offset)),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::LspEntries) => {
                    match LspEntriesTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.lsp_entries.push(tlv),
                        Err(error) => error.log(),
                    }
                }
                Some(TlvType::ExtendedSeqNum) => {
                    if tlvs.ext_seqnum.is_some() {
                        return Err(DecodeError::MultipleEsnTlvs);
                    }
                    match ExtendedSeqNumTlv::decode(tlv_len, &mut buf_tlv) {
                        Ok(tlv) => tlvs.ext_seqnum = Some(tlv),
                        Err(error) => error.log(),
                    }
                }
                _ => {
                    // Save unknown top-level TLV.
                    tlvs.unknown
                        .push(UnknownTlv::new(tlv_type, tlv_len, buf_tlv));
                }
            }
        }

        // Validate the PDU authentication.
        if let Some(auth) = auth {
            Pdu::decode_auth_validate(buf_orig, false, auth, tlv_auth)?;
        }

        Ok(Snp {
            hdr,
            source,
            summary,
            tlvs,
        })
    }

    fn encode(&self, auth_key: Option<&Key>) -> Bytes {
        TLS_BUF.with(|buf| {
            let mut buf = pdu_encode_start(buf, &self.hdr);

            // The PDU length will be initialized later.
            let len_pos = buf.len();
            buf.put_u16(0);
            self.source.encode(&mut buf);

            if let Some((start_lsp_id, end_lsp_id)) = &self.summary {
                start_lsp_id.encode(&mut buf);
                end_lsp_id.encode(&mut buf);
            }

            // Encode Authentication TLV.
            let auth = auth_key.and_then(|auth_key| {
                let auth_tlv = Pdu::encode_auth_tlv(auth_key)?;
                let auth_tlv_pos = buf.len();
                auth_tlv.encode(&mut buf);
                Some((auth_key, auth_tlv_pos))
            });

            // Encode other TLVs.
            for tlv in &self.tlvs.lsp_entries {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.ext_seqnum {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos, auth, None)
        })
    }
}

impl SnpTlvs {
    pub(crate) fn new(
        lsp_entries: impl IntoIterator<Item = LspEntry>,
        ext_seqnum: Option<ExtendedSeqNum>,
    ) -> Self {
        // Fragment TLVs as necessary.
        let lsp_entries = lsp_entries
            .into_iter()
            .collect::<Vec<_>>()
            .chunks(LspEntriesTlv::MAX_ENTRIES)
            .map(|chunk| LspEntriesTlv {
                list: chunk.to_vec(),
            })
            .collect();

        SnpTlvs {
            lsp_entries,
            ext_seqnum: ext_seqnum.map(ExtendedSeqNumTlv::new),
            unknown: Default::default(),
        }
    }

    // Calculates the maximum number of LSP entries that can fit within the
    // given size.
    pub(crate) fn max_lsp_entries(
        mut size: usize,
        auth: Option<AuthMethod>,
        ext_seqnum: bool,
    ) -> usize {
        let mut lsp_entries = 0;

        // Reserve space for the authentication TLV.
        if let Some(auth) = auth
            && let Some(auth_key) = auth.get_key_send()
        {
            size -= Pdu::auth_tlv_len(auth_key);
        }

        // Reserve space for the ESN TLV.
        if ext_seqnum {
            size -= TLV_HDR_SIZE + ExtendedSeqNumTlv::SIZE;
        }

        // Calculate how many full TLVs fit in the available size.
        let full_tlvs = size / LspEntriesTlv::MAX_SIZE;

        // Update the remaining size after accounting for all full TLVs.
        size %= LspEntriesTlv::MAX_SIZE;

        // Add the number of LSP entries from all full TLVs.
        lsp_entries +=
            full_tlvs * (LspEntriesTlv::MAX_SIZE / LspEntriesTlv::ENTRY_SIZE);

        // Check if the remaining size has enough room for a partial TLV.
        if size >= (TLV_HDR_SIZE + LspEntriesTlv::ENTRY_SIZE) {
            // Add the number of LSP entries from the remaining partial TLV.
            lsp_entries += (size - TLV_HDR_SIZE) / LspEntriesTlv::ENTRY_SIZE;
        }

        lsp_entries
    }

    // Returns an iterator over all LSP entries from TLVs of type 9.
    pub(crate) fn lsp_entries(&self) -> impl Iterator<Item = &LspEntry> {
        self.lsp_entries.iter().flat_map(|tlv| tlv.list.iter())
    }
}

// ===== helper functions =====

fn lsp_base_time() -> Option<Instant> {
    #[cfg(not(feature = "testing"))]
    {
        Some(Instant::now())
    }
    #[cfg(feature = "testing")]
    {
        None
    }
}

fn pdu_encode_start<'a>(
    buf: &'a RefCell<BytesMut>,
    hdr: &Header,
) -> RefMut<'a, BytesMut> {
    let mut buf = buf.borrow_mut();
    buf.clear();
    hdr.encode(&mut buf);
    buf
}

fn pdu_encode_end(
    mut buf: RefMut<'_, BytesMut>,
    len_pos: usize,
    auth: Option<(&Key, usize)>,
    mut lsp: Option<&mut Lsp>,
) -> Bytes {
    // Initialize PDU length.
    let pkt_len = buf.len() as u16;
    buf[len_pos..len_pos + 2].copy_from_slice(&pkt_len.to_be_bytes());

    // Compute and update the authentication digest if needed.
    if let Some((auth_key, auth_tlv_pos)) = auth
        && auth_key.algo != CryptoAlgo::ClearText
    {
        let digest =
            auth::message_digest(&buf, auth_key.algo, &auth_key.string);
        let mut offset = auth_tlv_pos + 3;
        if auth_key.algo != CryptoAlgo::HmacMd5 {
            offset += 2;
        }
        buf[offset..offset + auth_key.algo.digest_size() as usize]
            .copy_from_slice(&digest);
        if let Some(lsp) = lsp.as_mut()
            && let Some(auth_tlv) = lsp.tlvs.auth.as_mut()
        {
            auth_tlv.update_digest(digest);
        }
    }

    if let Some(lsp) = lsp {
        // Initialize LSP remaining lifetime.
        buf[Lsp::REM_LIFETIME_RANGE]
            .copy_from_slice(&lsp.rem_lifetime.to_be_bytes());

        // Compute and initialize LSP checksum.
        let cksum = Lsp::checksum(&buf[12..]);
        buf[Lsp::CKSUM_RANGE].copy_from_slice(&cksum);
        lsp.cksum = u16::from_be_bytes(cksum);
    }

    buf.clone().freeze()
}
