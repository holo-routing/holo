//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use bytes::{Bytes, TryGetError};
use serde::{Deserialize, Serialize};

use crate::packet::message::MessageDecodeInfo;
use crate::packet::tlv::{TlvDecodeInfo, TlvType};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// LDP decode errors.
#[derive(Debug, Deserialize, Serialize)]
pub enum DecodeError {
    ReadOutOfBounds,
    // PDU header
    IncompletePdu,
    InvalidPduLength(u16),
    InvalidVersion(u16),
    InvalidLsrId(Ipv4Addr),
    InvalidLabelSpace(u16),
    // Message (general errors)
    InvalidMessageLength(u16),
    UnknownMessage(MessageDecodeInfo, u16),
    MissingMsgParams(MessageDecodeInfo, TlvType),
    // TLV (general errors)
    InvalidTlvLength(u16),
    UnknownTlv(MessageDecodeInfo, u16, Bytes),
    InvalidTlvValue(TlvDecodeInfo),
    // Message-specific errors
    UnsupportedAf(TlvDecodeInfo, u16),
    UnknownFec(TlvDecodeInfo, u8),
    BadKeepaliveTime(TlvDecodeInfo, u16),
    McastTHello(TlvDecodeInfo, IpAddr),
    UcastLHello(TlvDecodeInfo, IpAddr),
    InvalidSrcAddr(TlvDecodeInfo, IpAddr),
    InvalidTransportAddr(TlvDecodeInfo, IpAddr),
    InvalidTransportPref(TlvDecodeInfo, u16),
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            DecodeError::IncompletePdu => {
                write!(f, "Incomplete PDU")
            }
            DecodeError::InvalidPduLength(len) => {
                write!(f, "Invalid PDU length: {len}")
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "Invalid LDP version: {version}")
            }
            DecodeError::InvalidLsrId(lsr_id) => {
                write!(f, "Invalid LSR-ID: {lsr_id}")
            }
            DecodeError::InvalidLabelSpace(lspace) => {
                write!(f, "Invalid label space: {lspace}")
            }
            DecodeError::InvalidMessageLength(len) => {
                write!(f, "Invalid message length: {len}")
            }
            DecodeError::UnknownMessage(_msgi, msg_type) => {
                write!(f, "Unknown message: {msg_type}")
            }
            DecodeError::MissingMsgParams(_msgi, tlv_type) => {
                write!(f, "Missing message parameters: {tlv_type}")
            }
            DecodeError::InvalidTlvLength(len) => {
                write!(f, "Invalid TLV length: {len}")
            }
            DecodeError::UnknownTlv(_msgi, tlv_type, _raw_tlv) => {
                write!(f, "Unknown TLV: {tlv_type}")
            }
            DecodeError::InvalidTlvValue(_tlvi) => {
                write!(f, "Invalid TLV value")
            }
            DecodeError::UnsupportedAf(_tlvi, af) => {
                write!(f, "Unsupported address family: {af}")
            }
            DecodeError::UnknownFec(_tlvi, fec) => {
                write!(f, "Unknown FEC type: {fec}")
            }
            DecodeError::BadKeepaliveTime(_tlvi, time) => {
                write!(f, "Invalid KeepAlive time: {time}")
            }
            DecodeError::McastTHello(_tlvi, addr) => {
                write!(f, "Multicast targeted hello from {addr}")
            }
            DecodeError::UcastLHello(_tlvi, addr) => {
                write!(f, "Unicast link hello from {addr}")
            }
            DecodeError::InvalidSrcAddr(_tlvi, addr) => {
                write!(f, "Invalid source address: {addr}")
            }
            DecodeError::InvalidTransportAddr(_tlvi, addr) => {
                write!(f, "Invalid transport address: {addr}")
            }
            DecodeError::InvalidTransportPref(_tlvi, trans_pref) => {
                write!(f, "Invalid transport preference: {trans_pref}")
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
