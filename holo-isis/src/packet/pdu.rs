//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::cell::{RefCell, RefMut};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::TLS_BUF;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::keychain::Key;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::packet::auth::AuthMethod;
use crate::packet::consts::{
    IDRP_DISCRIMINATOR, LspFlags, PduType, SYSTEM_ID_LEN, TlvType, VERSION,
    VERSION_PROTO_EXT,
};
use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::subtlvs::capability::{SrAlgoStlv, SrCapabilitiesStlv};
use crate::packet::tlv::{
    AreaAddressesTlv, AuthenticationTlv, DynamicHostnameTlv, ExtIpv4Reach,
    ExtIpv4ReachTlv, ExtIsReach, ExtIsReachTlv, Ipv4AddressesTlv, Ipv4Reach,
    Ipv4ReachTlv, Ipv4RouterIdTlv, Ipv6AddressesTlv, Ipv6Reach, Ipv6ReachTlv,
    Ipv6RouterIdTlv, IsReach, IsReachTlv, LspBufferSizeTlv, LspEntriesTlv,
    LspEntry, NeighborsTlv, PaddingTlv, ProtocolsSupportedTlv, RouterCapTlv,
    TLV_HDR_SIZE, TLV_MAX_LEN, Tlv, UnknownTlv, tlv_entries_split,
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
    pub neighbors: Vec<NeighborsTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
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
    pub hostname: Option<DynamicHostnameTlv>,
    pub lsp_buf_size: Option<LspBufferSizeTlv>,
    pub is_reach: Vec<IsReachTlv>,
    pub ext_is_reach: Vec<ExtIsReachTlv>,
    pub ipv4_addrs: Vec<Ipv4AddressesTlv>,
    pub ipv4_internal_reach: Vec<Ipv4ReachTlv>,
    pub ipv4_external_reach: Vec<Ipv4ReachTlv>,
    pub ext_ipv4_reach: Vec<ExtIpv4ReachTlv>,
    pub ipv4_router_id: Option<Ipv4RouterIdTlv>,
    pub ipv6_addrs: Vec<Ipv6AddressesTlv>,
    pub ipv6_reach: Vec<Ipv6ReachTlv>,
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
    Vec => #[serde(default, skip_serializing_if = "Vec::is_empty")],
)]
#[derive(Deserialize, Serialize)]
pub struct SnpTlvs {
    pub lsp_entries: Vec<LspEntriesTlv>,
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

        // Get authentication key.
        let auth_key =
            auth.get_key_accept().ok_or(DecodeError::AuthKeyNotFound)?;

        match (&tlv_auth, auth_key.algo) {
            // Clear-text authentication.
            (
                (AuthenticationTlv::ClearText(passwd), _),
                CryptoAlgo::ClearText,
            ) => {
                // Validate the received password.
                if *passwd != auth_key.string {
                    return Err(DecodeError::AuthError);
                }
            }
            // HMAC-MD5 authentication.
            (
                (AuthenticationTlv::HmacMd5(tlv_digest), tlv_offset),
                CryptoAlgo::HmacMd5,
            ) => {
                // If processing an LSP, zero out the Checksum and Remaining
                // Lifetime fields.
                if is_lsp {
                    buf_orig[Lsp::REM_LIFETIME_RANGE].fill(0);
                    buf_orig[Lsp::CKSUM_RANGE].fill(0);
                }

                // Zero out the digest field before computing the new digest.
                let digest_offset = tlv_offset + 1;
                buf_orig[digest_offset..digest_offset + 16].fill(0);

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
            // Authentication type mismatch.
            _ => {
                return Err(DecodeError::AuthTypeMismatch);
            }
        }

        Ok(tlv_auth.0)
    }

    // Returns an Authentication TLV for encoding a PDU with the given key.
    // For HMAC-MD5, the digest is initialized to zero and will be computed
    // later.
    fn encode_auth_tlv(auth: &Key) -> Option<AuthenticationTlv> {
        match auth.algo {
            CryptoAlgo::ClearText => {
                let tlv = AuthenticationTlv::ClearText(auth.string.clone());
                Some(tlv)
            }
            CryptoAlgo::HmacMd5 => {
                let tlv = AuthenticationTlv::HmacMd5([0; 16]);
                Some(tlv)
            }
            _ => None,
        }
    }

    // Calculates the length of the Authentication TLV for a given key.
    pub(crate) fn auth_tlv_len(auth: &Key) -> usize {
        let mut len = TLV_HDR_SIZE + AuthenticationTlv::MIN_LEN;
        match auth.algo {
            CryptoAlgo::ClearText => {
                len += std::cmp::min(auth.string.len(), TLV_MAX_LEN);
            }
            _ => {
                len += auth.algo.digest_size() as usize;
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
        let idrp_discr = buf.get_u8();
        if idrp_discr != IDRP_DISCRIMINATOR {
            return Err(DecodeError::InvalidIrdpDiscriminator(idrp_discr));
        }

        // Parse length of fixed header.
        let fixed_header_length = buf.get_u8();

        // Parse version/protocol ID extension.
        let version_proto_ext = buf.get_u8();
        if version_proto_ext != VERSION_PROTO_EXT {
            return Err(DecodeError::InvalidVersion(version_proto_ext));
        }

        // Parse ID length.
        let id_len = buf.get_u8();
        if id_len != 0 && id_len != SYSTEM_ID_LEN {
            return Err(DecodeError::InvalidIdLength(id_len));
        }

        // Parse PDU type.
        let pdu_type = buf.get_u8();
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
        let version = buf.get_u8();
        if version != VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Parse reserved field.
        let _reserved = buf.get_u8();

        // Parse maximum area addresses.
        let max_area_addrs = buf.get_u8();

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
        let circuit_type = buf.get_u8() & Self::CIRCUIT_TYPE_MASK;
        let circuit_type = match circuit_type {
            1 if hdr.pdu_type != PduType::HelloLanL2 => LevelType::L1,
            2 if hdr.pdu_type != PduType::HelloLanL1 => LevelType::L2,
            3 => LevelType::All,
            _ => {
                return Err(DecodeError::InvalidHelloCircuitType(circuit_type));
            }
        };

        // Parse source ID.
        let source = SystemId::decode(buf);

        // Parse holding time.
        let holdtime = buf.get_u16();
        if holdtime == 0 {
            return Err(DecodeError::InvalidHelloHoldtime(holdtime));
        }

        // Parse PDU length.
        let pdu_len = buf.get_u16();
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse custom fields.
        let variant = if hdr.pdu_type == PduType::HelloP2P {
            // Parse local circuit ID.
            let local_circuit_id = buf.get_u8();

            HelloVariant::P2P { local_circuit_id }
        } else {
            // Parse priority.
            let priority = buf.get_u8() & Self::PRIORITY_MASK;
            // Parse LAN ID.
            let lan_id = LanId::decode(buf);

            HelloVariant::Lan { priority, lan_id }
        };

        // Parse top-level TLVs.
        let mut tlvs = HelloTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    let tlv = AreaAddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.area_addrs.push(tlv);
                }
                Some(TlvType::Neighbors)
                    if hdr.pdu_type != PduType::HelloP2P =>
                {
                    let tlv = NeighborsTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.neighbors.push(tlv);
                }
                Some(TlvType::Padding) => {
                    let tlv = PaddingTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.padding.push(tlv);
                }
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    let tlv = AuthenticationTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlv_auth = Some((tlv, tlv_offset));
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    let tlv =
                        ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.protocols_supported = Some(tlv);
                }
                Some(TlvType::Ipv4Addresses) => {
                    let tlv = Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_addrs.push(tlv);
                }
                Some(TlvType::Ipv6Addresses) => {
                    let tlv = Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_addrs.push(tlv);
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

    fn encode(&self, auth: Option<&Key>) -> Bytes {
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

            // Encode TLVs.
            let mut auth_tlv_pos = None;
            if let Some(auth) = auth
                && let Some(tlv) = Pdu::encode_auth_tlv(auth)
            {
                auth_tlv_pos = Some(buf.len());
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.neighbors {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv4_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.padding {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos, auth, auth_tlv_pos, None)
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
        for tlv in &self.tlvs.neighbors {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.ipv4_addrs {
            total_tlv_len += tlv.len();
        }
        for tlv in &self.tlvs.ipv6_addrs {
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
        neighbors: impl IntoIterator<Item = [u8; 6]>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
    ) -> Self {
        HelloTlvs {
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            area_addrs: tlv_entries_split(area_addrs),
            neighbors: tlv_entries_split(neighbors),
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            padding: Default::default(),
            unknown: Default::default(),
        }
    }

    // Returns an iterator over all area addresses from TLVs of type 1.
    pub(crate) fn area_addrs(&self) -> impl Iterator<Item = &AreaAddr> {
        self.area_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 6.
    pub(crate) fn neighbors(&self) -> impl Iterator<Item = &[u8; 6]> {
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
        let pdu_len = buf.get_u16();
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse remaining lifetime.
        let rem_lifetime = buf.get_u16();

        // Parse LSP ID.
        let lsp_id = LspId::decode(buf);

        // Parse sequence number.
        let seqno = buf.get_u32();

        // Parse checksum.
        let cksum = buf.get_u16();

        // Parse flags.
        let flags = buf.get_u8();
        let flags = LspFlags::from_bits_truncate(flags);

        // Parse top-level TLVs.
        let mut tlvs = LspTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::AreaAddresses) => {
                    let tlv = AreaAddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.area_addrs.push(tlv);
                }
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    let tlv = AuthenticationTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlv_auth = Some((tlv, tlv_offset));
                }
                Some(TlvType::DynamicHostname) => {
                    let tlv =
                        DynamicHostnameTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.hostname = Some(tlv);
                }
                Some(TlvType::LspBufferSize) => {
                    let tlv = LspBufferSizeTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.lsp_buf_size = Some(tlv);
                }
                Some(TlvType::IsReach) => {
                    let tlv = IsReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.is_reach.push(tlv);
                }
                Some(TlvType::ExtIsReach) => {
                    let tlv = ExtIsReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ext_is_reach.push(tlv);
                }
                Some(TlvType::Ipv4InternalReach) => {
                    let tlv =
                        Ipv4ReachTlv::decode(tlv_len, &mut buf_tlv, false)?;
                    tlvs.ipv4_internal_reach.push(tlv);
                }
                Some(TlvType::ProtocolsSupported) => {
                    if tlvs.protocols_supported.is_some() {
                        continue;
                    }
                    let tlv =
                        ProtocolsSupportedTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.protocols_supported = Some(tlv);
                }
                Some(TlvType::Ipv4ExternalReach) => {
                    let tlv =
                        Ipv4ReachTlv::decode(tlv_len, &mut buf_tlv, true)?;
                    tlvs.ipv4_external_reach.push(tlv);
                }
                Some(TlvType::Ipv4Addresses) => {
                    let tlv = Ipv4AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_addrs.push(tlv);
                }
                Some(TlvType::ExtIpv4Reach) => {
                    let tlv = ExtIpv4ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ext_ipv4_reach.push(tlv);
                }
                Some(TlvType::Ipv4RouterId) => {
                    if tlvs.ipv4_router_id.is_some() {
                        continue;
                    }
                    let tlv = Ipv4RouterIdTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv4_router_id = Some(tlv);
                }
                Some(TlvType::Ipv6Addresses) => {
                    let tlv = Ipv6AddressesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_addrs.push(tlv);
                }
                Some(TlvType::Ipv6Reach) => {
                    let tlv = Ipv6ReachTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_reach.push(tlv);
                }
                Some(TlvType::Ipv6RouterId) => {
                    if tlvs.ipv6_router_id.is_some() {
                        continue;
                    }
                    let tlv = Ipv6RouterIdTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.ipv6_router_id = Some(tlv);
                }
                Some(TlvType::RouterCapability) => {
                    let tlv = RouterCapTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.router_cap.push(tlv);
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
            lsp_id,
            seqno,
            cksum,
            flags,
            tlvs,
            raw: Default::default(),
            base_time: lsp_base_time(),
        })
    }

    fn encode(&mut self, auth: Option<&Key>) -> Bytes {
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

            // Encode TLVs.
            let mut auth_tlv_pos = None;
            if let Some(auth) = auth
                && let Some(tlv) = Pdu::encode_auth_tlv(auth)
            {
                auth_tlv_pos = Some(buf.len());
                tlv.encode(&mut buf);
                self.tlvs.auth = Some(tlv);
            }
            if let Some(tlv) = &self.tlvs.protocols_supported {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.router_cap {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.area_addrs {
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
            if let Some(tlv) = &self.tlvs.ipv4_router_id {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_addrs {
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.ipv6_reach {
                tlv.encode(&mut buf);
            }
            if let Some(tlv) = &self.tlvs.ipv6_router_id {
                tlv.encode(&mut buf);
            }

            // Store LSP raw data.
            let bytes =
                pdu_encode_end(buf, len_pos, auth, auth_tlv_pos, Some(self));
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
            raw[10..12].copy_from_slice(&rem_lifetime.to_be_bytes());
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
}

impl LspTlvs {
    pub(crate) fn new(
        protocols_supported: impl IntoIterator<Item = u8>,
        router_cap: Vec<RouterCapTlv>,
        area_addrs: impl IntoIterator<Item = AreaAddr>,
        hostname: Option<String>,
        lsp_buf_size: Option<u16>,
        is_reach: impl IntoIterator<Item = IsReach>,
        ext_is_reach: impl IntoIterator<Item = ExtIsReach>,
        ipv4_addrs: impl IntoIterator<Item = Ipv4Addr>,
        ipv4_internal_reach: impl IntoIterator<Item = Ipv4Reach>,
        ipv4_external_reach: impl IntoIterator<Item = Ipv4Reach>,
        ext_ipv4_reach: impl IntoIterator<Item = ExtIpv4Reach>,
        ipv4_router_id: Option<Ipv4Addr>,
        ipv6_addrs: impl IntoIterator<Item = Ipv6Addr>,
        ipv6_reach: impl IntoIterator<Item = Ipv6Reach>,
        ipv6_router_id: Option<Ipv6Addr>,
    ) -> Self {
        LspTlvs {
            auth: None,
            protocols_supported: Some(ProtocolsSupportedTlv::from(
                protocols_supported,
            )),
            router_cap,
            area_addrs: tlv_entries_split(area_addrs),
            hostname: hostname.map(|hostname| DynamicHostnameTlv { hostname }),
            lsp_buf_size: lsp_buf_size.map(|size| LspBufferSizeTlv { size }),
            is_reach: tlv_entries_split(is_reach),
            ext_is_reach: tlv_entries_split(ext_is_reach),
            ipv4_addrs: tlv_entries_split(ipv4_addrs),
            ipv4_internal_reach: tlv_entries_split(ipv4_internal_reach),
            ipv4_external_reach: tlv_entries_split(ipv4_external_reach),
            ext_ipv4_reach: tlv_entries_split(ext_ipv4_reach),
            ipv4_router_id: ipv4_router_id.map(Ipv4RouterIdTlv::new),
            ipv6_addrs: tlv_entries_split(ipv6_addrs),
            ipv6_reach: tlv_entries_split(ipv6_reach),
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
        let ipv4_addrs = tlv_take_max(&mut self.ipv4_addrs, &mut rem_len);
        let ipv4_internal_reach =
            tlv_take_max(&mut self.ipv4_internal_reach, &mut rem_len);
        let ipv4_external_reach =
            tlv_take_max(&mut self.ipv4_external_reach, &mut rem_len);
        let ext_ipv4_reach =
            tlv_take_max(&mut self.ext_ipv4_reach, &mut rem_len);
        let ipv6_addrs = tlv_take_max(&mut self.ipv6_addrs, &mut rem_len);
        let ipv6_reach = tlv_take_max(&mut self.ipv6_reach, &mut rem_len);
        if rem_len == max_len {
            return None;
        }

        Some(LspTlvs {
            auth: None,
            protocols_supported,
            router_cap,
            area_addrs,
            hostname,
            lsp_buf_size,
            is_reach,
            ext_is_reach,
            ipv4_addrs,
            ipv4_internal_reach,
            ipv4_external_reach,
            ext_ipv4_reach,
            ipv4_router_id,
            ipv6_addrs,
            ipv6_reach,
            ipv6_router_id,
            unknown: Default::default(),
        })
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

    // Returns the dynamic hostname (TLV type 137).
    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_ref().map(|tlv| tlv.hostname.as_str())
    }

    // Returns the maximum sized LSP which may be generated (TLV type 14).
    pub(crate) fn lsp_buf_size(&self) -> Option<u16> {
        self.lsp_buf_size.as_ref().map(|tlv| tlv.size)
    }

    // Returns an iterator over all IS neighbors from TLVs of type 2.
    pub(crate) fn is_reach(&self) -> impl Iterator<Item = &IsReach> {
        self.is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IS neighbors from TLVs of type 22.
    pub(crate) fn ext_is_reach(&self) -> impl Iterator<Item = &ExtIsReach> {
        self.ext_is_reach.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 addresses from TLVs of type 132.
    pub(crate) fn ipv4_addrs(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.ipv4_addrs.iter().flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 internal reachability entries from TLVs
    // of type 128.
    pub(crate) fn ipv4_internal_reach(
        &self,
    ) -> impl Iterator<Item = &Ipv4Reach> {
        self.ipv4_internal_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 external reachability entries from TLVs
    // of type 130.
    pub(crate) fn ipv4_external_reach(
        &self,
    ) -> impl Iterator<Item = &Ipv4Reach> {
        self.ipv4_external_reach
            .iter()
            .flat_map(|tlv| tlv.list.iter())
    }

    // Returns an iterator over all IPv4 reachability entries from TLVs of
    // type 135.
    pub(crate) fn ext_ipv4_reach(&self) -> impl Iterator<Item = &ExtIpv4Reach> {
        self.ext_ipv4_reach.iter().flat_map(|tlv| tlv.list.iter())
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
        let pdu_len = buf.get_u16();
        if pdu_len != buf_orig.len() as u16 {
            return Err(DecodeError::InvalidPduLength(pdu_len));
        }

        // Parse source ID.
        let source = LanId::decode(buf);

        // Parse start and end LSP IDs.
        let mut summary = None;
        if matches!(hdr.pdu_type, PduType::CsnpL1 | PduType::CsnpL2) {
            let start_lsp_id = LspId::decode(buf);
            let end_lsp_id = LspId::decode(buf);
            summary = Some((start_lsp_id, end_lsp_id));
        }

        // Parse top-level TLVs.
        let mut tlvs = SnpTlvs::default();
        let mut tlv_auth = None;
        while buf.remaining() >= TLV_HDR_SIZE {
            // Parse TLV type.
            let tlv_type = buf.get_u8();
            let tlv_etype = TlvType::from_u8(tlv_type);

            // Parse and validate TLV length.
            let tlv_len = buf.get_u8();
            if tlv_len as usize > buf.remaining() {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }

            // Parse TLV value.
            let tlv_offset = buf_orig.len() - buf.remaining();
            let mut buf_tlv = buf.copy_to_bytes(tlv_len as usize);
            match tlv_etype {
                Some(TlvType::Authentication) => {
                    if tlv_auth.is_some() {
                        continue;
                    }
                    let tlv = AuthenticationTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlv_auth = Some((tlv, tlv_offset));
                }
                Some(TlvType::LspEntries) => {
                    let tlv = LspEntriesTlv::decode(tlv_len, &mut buf_tlv)?;
                    tlvs.lsp_entries.push(tlv);
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

    fn encode(&self, auth: Option<&Key>) -> Bytes {
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

            // Encode TLVs.
            let mut auth_tlv_pos = None;
            if let Some(auth) = auth
                && let Some(tlv) = Pdu::encode_auth_tlv(auth)
            {
                auth_tlv_pos = Some(buf.len());
                tlv.encode(&mut buf);
            }
            for tlv in &self.tlvs.lsp_entries {
                tlv.encode(&mut buf);
            }

            pdu_encode_end(buf, len_pos, auth, auth_tlv_pos, None)
        })
    }
}

impl SnpTlvs {
    pub(crate) fn new(lsp_entries: impl IntoIterator<Item = LspEntry>) -> Self {
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
            unknown: Default::default(),
        }
    }

    // Calculates the maximum number of LSP entries that can fit within the
    // given size.
    pub(crate) const fn max_lsp_entries(mut size: usize) -> usize {
        let mut lsp_entries = 0;

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
    auth: Option<&Key>,
    auth_tlv_pos: Option<usize>,
    mut lsp: Option<&mut Lsp>,
) -> Bytes {
    // Initialize PDU length.
    let pkt_len = buf.len() as u16;
    buf[len_pos..len_pos + 2].copy_from_slice(&pkt_len.to_be_bytes());

    // Compute and update the authentication digest if needed.
    if let Some(auth) = auth
        && let Some(auth_tlv_pos) = auth_tlv_pos
        && auth.algo != CryptoAlgo::ClearText
    {
        let digest = auth::message_digest(&buf, auth.algo, &auth.string);
        let offset = auth_tlv_pos + 3;
        buf[offset..offset + auth.algo.digest_size() as usize]
            .copy_from_slice(&digest);
        if let Some(lsp) = lsp.as_mut() {
            lsp.tlvs.auth =
                Some(AuthenticationTlv::HmacMd5(digest.try_into().unwrap()));
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
