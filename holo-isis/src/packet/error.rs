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
use tracing::{Span, warn};

use crate::packet::consts::PduType;

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
    InvalidPduLength(PduType, u16),
    InvalidTlvLength {
        #[serde(skip)]
        span: Option<Span>,
        tlv_type: u8,
        tlv_len: u8,
        remaining: usize,
    },
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

impl DecodeError {
    pub(crate) fn log(&self) {
        match self {
            DecodeError::ReadOutOfBounds => {
                warn!("{}", self);
            }
            DecodeError::IncompletePdu => {
                warn!("{}", self);
            }
            DecodeError::InvalidHeaderLength(hdr_len) => {
                warn!(%hdr_len, "{}", self);
            }
            DecodeError::InvalidIrdpDiscriminator(discriminator) => {
                warn!(%discriminator, "{}", self);
            }
            DecodeError::InvalidVersion(version) => {
                warn!(%version, "{}", self);
            }
            DecodeError::InvalidIdLength(id_len) => {
                warn!(%id_len, "{}", self);
            }
            DecodeError::UnknownPduType(pdu_type) => {
                warn!(%pdu_type, "{}", self);
            }
            DecodeError::InvalidPduLength(pdu_type, pdu_len) => {
                warn!(?pdu_type, %pdu_len, "{}", self);
            }
            DecodeError::InvalidTlvLength {
                span,
                tlv_type,
                tlv_len,
                remaining,
            } => {
                let _span_guard = span.as_ref().map(|span| span.enter());
                warn!(tlv_type, tlv_len, remaining, "{}", self);
            }
            DecodeError::AuthTypeMismatch => {
                warn!("{}", self);
            }
            DecodeError::AuthKeyNotFound => {
                warn!("{}", self);
            }
            DecodeError::AuthError => {
                warn!("{}", self);
            }
            DecodeError::MultipleEsnTlvs => {
                warn!("{}", self);
            }
            DecodeError::InvalidHelloCircuitType(circuit_type) => {
                warn!(%circuit_type, "{}", self);
            }
            DecodeError::InvalidHelloHoldtime(holdtime) => {
                warn!(%holdtime, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            DecodeError::IncompletePdu => {
                write!(f, "incomplete PDU")
            }
            DecodeError::InvalidHeaderLength(..) => {
                write!(f, "invalid header length")
            }
            DecodeError::InvalidIrdpDiscriminator(..) => {
                write!(f, "invalid IDRP discriminator")
            }
            DecodeError::InvalidVersion(..) => {
                write!(f, "invalid version")
            }
            DecodeError::InvalidIdLength(..) => {
                write!(f, "invalid ID length")
            }
            DecodeError::UnknownPduType(..) => {
                write!(f, "unknown PDU type")
            }
            DecodeError::InvalidPduLength(..) => {
                write!(f, "invalid PDU length")
            }
            DecodeError::InvalidTlvLength { .. } => {
                write!(f, "invalid TLV length")
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
            DecodeError::InvalidHelloCircuitType(..) => {
                write!(f, "invalid hello circuit type")
            }
            DecodeError::InvalidHelloHoldtime(..) => {
                write!(f, "invalid hello holdtime")
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
