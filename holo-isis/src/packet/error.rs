//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use serde::{Deserialize, Serialize};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// IS-IS message decoding errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    IncompletePdu,
    InvalidHeaderLength(u8),
    InvalidIrdpDiscriminator(u8),
    InvalidVersion(u8),
    InvalidIdLength(u8),
    UnknownPduType(u8),
    InvalidPduLength(u16),
    UnexpectedTlvType(u8),
    InvalidTlvLength(u8),
    AuthUnsupportedType(u8),
    AuthTypeMismatch,
    AuthKeyNotFound,
    AuthError,
    // Hello
    InvalidHelloCircuitType(u8),
    InvalidHelloHoldtime(u16),
    // TLVs
    InvalidAreaAddrLen(u8),
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            DecodeError::UnexpectedTlvType(tlv_type) => {
                write!(f, "unexpected tlv type: {tlv_type}")
            }
            DecodeError::InvalidTlvLength(tlv_len) => {
                write!(f, "invalid TLV length: {tlv_len}")
            }
            DecodeError::AuthUnsupportedType(auth_type) => {
                write!(f, "unsupported authentication type: {auth_type}")
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
            DecodeError::InvalidHelloCircuitType(circuit_type) => {
                write!(f, "invalid hello circuit type: {circuit_type}")
            }
            DecodeError::InvalidHelloHoldtime(holdtime) => {
                write!(f, "invalid hello holdtime: {holdtime}")
            }
            DecodeError::InvalidAreaAddrLen(area_len) => {
                write!(f, "invalid area address length: {area_len}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}
