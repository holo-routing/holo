//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// OSPFv2 decode errors.
#[derive(Debug, Deserialize, Serialize)]
pub enum DecodeError {
    InvalidIpHdrLength(u16),
    InvalidVersion(u8),
    UnknownPacketType(u8),
    InvalidLength(u16),
    InvalidChecksum,
    InvalidRouterId(Ipv4Addr),
    UnsupportedAuthType(u16),
    InvalidLsaLength,
    UnknownRouterLinkType(u8),
    InvalidTlvLength(u16),
    MissingRequiredTlv(u16),
    InvalidIpPrefix,
    AuthTypeMismatch,
    AuthKeyIdNotFound(u32),
    AuthLenError(u16),
    AuthError,
    // OSPFv2
    InvalidExtPrefixRouteType(u8),
}

// OSPF LSA validation errors.
//
// Errors that prevent the LSA from being parsed correctly (e.g. invalid LSA
// length) cause the entire LS Update packet to be dropped.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum LsaValidationError {
    InvalidChecksum,
    InvalidLsaAge,
    InvalidLsaSeqNo,
    Ospfv2RouterLsaIdMismatch,
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidIpHdrLength(length) => {
                write!(f, "invalid IP header length: {}", length)
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "invalid packet version: {}", version)
            }
            DecodeError::UnknownPacketType(pkt_type) => {
                write!(f, "unknown packet type: {}", pkt_type)
            }
            DecodeError::InvalidLength(pkt_len) => {
                write!(f, "invalid packet length: {}", pkt_len)
            }
            DecodeError::InvalidChecksum => {
                write!(f, "invalid checksum")
            }
            DecodeError::InvalidRouterId(router_id) => {
                write!(f, "invalid router-id: {}", router_id)
            }
            DecodeError::UnsupportedAuthType(au_type) => {
                write!(f, "unsupported authentication type: {}", au_type)
            }
            DecodeError::InvalidLsaLength => {
                write!(f, "invalid LSA length")
            }
            DecodeError::UnknownRouterLinkType(link_type) => {
                write!(f, "unknown link type: {}", link_type)
            }
            DecodeError::InvalidTlvLength(tlv_len) => {
                write!(f, "invalid TLV length: {}", tlv_len)
            }
            DecodeError::MissingRequiredTlv(tlv_type) => {
                write!(f, "missing required TLV: {}", tlv_type)
            }
            DecodeError::InvalidIpPrefix => {
                write!(f, "invalid IP prefix")
            }
            DecodeError::AuthTypeMismatch => {
                write!(f, "authentication type mismatch")
            }
            DecodeError::AuthKeyIdNotFound(key_id) => {
                write!(f, "authentication Key ID not found: {}", key_id)
            }
            DecodeError::AuthLenError(length) => {
                write!(f, "invalid authentication data length: {}", length)
            }
            DecodeError::AuthError => {
                write!(f, "authentication failed")
            }
            DecodeError::InvalidExtPrefixRouteType(route_type) => {
                write!(f, "invalid extended prefix route type: {}", route_type)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// ===== impl LsaValidationError =====

impl std::fmt::Display for LsaValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsaValidationError::InvalidChecksum => {
                write!(f, "invalid LSA checksum")
            }
            LsaValidationError::InvalidLsaAge => {
                write!(f, "invalid LSA age")
            }
            LsaValidationError::InvalidLsaSeqNo => {
                write!(f, "invalid LSA sequence number")
            }
            LsaValidationError::Ospfv2RouterLsaIdMismatch => {
                write!(
                    f,
                    "Router-LSA's advertising router and LSA-ID are not equal"
                )
            }
        }
    }
}

impl std::error::Error for LsaValidationError {}
