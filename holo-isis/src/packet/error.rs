//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use bytes::TryGetError;
use serde::{Deserialize, Serialize};
use tracing::warn;

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;
pub type TlvDecodeResult<T> = Result<T, TlvDecodeError>;

// IS-IS message decoding errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ReadOutOfBounds,
    IncompletePdu,
    InvalidHeaderLength(u8),
    InvalidIrdpDiscriminator(u8),
    InvalidVersion(u8),
    InvalidIdLength(u8),
    UnknownPduType(u8),
    InvalidPduLength(u16),
    InvalidTlvLength(u8),
    AuthTypeMismatch,
    AuthKeyNotFound,
    AuthError,
    MultipleEsnTlvs,
    // Hello
    InvalidHelloCircuitType(u8),
    InvalidHelloHoldtime(u16),
}

// IS-IS TLV decoding errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum TlvDecodeError {
    ReadOutOfBounds,
    UnexpectedType(u8),
    InvalidLength(u8),
    InvalidAreaAddrLen(u8),
    AuthUnsupportedType(u8),
    InvalidThreeWayAdjState(u8),
    InvalidPrefixLength(u8),
    InvalidNumSystemIds(u8),
    ZeroExtendedSessionSeqNum,
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            DecodeError::IncompletePdu => {
                write!(f, "incomplete PDU")
            }
            DecodeError::InvalidHeaderLength(hdr_len) => {
                write!(f, "invalid header length: {hdr_len}")
            }
            DecodeError::InvalidIrdpDiscriminator(discriminator) => {
                write!(f, "invalid IDRP discriminator: {discriminator}")
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "invalid version: {version}")
            }
            DecodeError::InvalidIdLength(id_len) => {
                write!(f, "invalid ID length: {id_len}")
            }
            DecodeError::UnknownPduType(pdu_type) => {
                write!(f, "unknown PDU type: {pdu_type}")
            }
            DecodeError::InvalidPduLength(pdu_len) => {
                write!(f, "invalid PDU length: {pdu_len}")
            }
            DecodeError::InvalidTlvLength(tlv_len) => {
                write!(f, "invalid TLV length: {tlv_len}")
            }
            DecodeError::AuthTypeMismatch => {
                write!(f, "authentication type mismatch")
            }
            DecodeError::AuthKeyNotFound => {
                write!(f, "authentication key not found")
            }
            DecodeError::AuthError => {
                write!(f, "authentication failed")
            }
            DecodeError::MultipleEsnTlvs => {
                write!(f, "multiple ESN TLVs")
            }
            DecodeError::InvalidHelloCircuitType(circuit_type) => {
                write!(f, "invalid hello circuit type: {circuit_type}")
            }
            DecodeError::InvalidHelloHoldtime(holdtime) => {
                write!(f, "invalid hello holdtime: {holdtime}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<TryGetError> for DecodeError {
    fn from(_error: TryGetError) -> DecodeError {
        DecodeError::ReadOutOfBounds
    }
}

// ===== impl TlvDecodeError =====

impl TlvDecodeError {
    pub(crate) fn log(&self) {
        warn!("{}", self);
    }
}

impl std::fmt::Display for TlvDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvDecodeError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            TlvDecodeError::UnexpectedType(tlv_type) => {
                write!(f, "unexpected type: {tlv_type}")
            }
            TlvDecodeError::InvalidLength(tlv_len) => {
                write!(f, "invalid length: {tlv_len}")
            }
            TlvDecodeError::AuthUnsupportedType(auth_type) => {
                write!(f, "unsupported authentication type: {auth_type}")
            }
            TlvDecodeError::InvalidThreeWayAdjState(state) => {
                write!(f, "invalid adjacency three-way state: {state}")
            }
            TlvDecodeError::InvalidPrefixLength(prefix_len) => {
                write!(f, "invalid prefix length: {prefix_len}")
            }
            TlvDecodeError::InvalidAreaAddrLen(area_len) => {
                write!(f, "invalid area address length: {area_len}")
            }
            TlvDecodeError::InvalidNumSystemIds(num) => {
                write!(f, "invalid number of System IDs: {num}")
            }
            TlvDecodeError::ZeroExtendedSessionSeqNum => {
                write!(f, "extended session sequence number is zero")
            }
        }
    }
}

impl std::error::Error for TlvDecodeError {}

impl From<TryGetError> for TlvDecodeError {
    fn from(_error: TryGetError) -> TlvDecodeError {
        TlvDecodeError::ReadOutOfBounds
    }
}
