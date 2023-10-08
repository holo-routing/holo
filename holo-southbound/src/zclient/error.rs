//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use ipnetwork::IpNetworkError;
use tracing::{warn, warn_span};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// Zclient errors.
#[derive(Debug)]
pub enum Error {
    ZebraConnectError(std::io::Error),
    ZebraReadError(std::io::Error),
    ZebraDisconnected,
    DecodeError(DecodeError),
}

// ZAPI errors.
#[derive(Debug)]
pub enum DecodeError {
    IoError(std::io::Error),
    PartialMessage,
    VersionMismatch(u8, u8),
    MalformedMessage(String),
    MalformedPrefix(IpNetworkError),
    UnknownProtocol(u8),
    UnknownNexthopType(u8),
}

// ===== impl Error =====

impl Error {
    pub fn log(&self) {
        match self {
            Error::ZebraConnectError(error) => {
                warn_span!("southbound").in_scope(|| {
                    warn!(%error, "{}", self);
                });
            }
            Error::ZebraReadError(error) => {
                warn_span!("southbound").in_scope(|| {
                    warn!(%error, "{}", self);
                });
            }
            Error::ZebraDisconnected => {
                warn_span!("southbound").in_scope(|| {
                    warn!("{}", self);
                });
            }
            Error::DecodeError(error) => {
                warn_span!("southbound").in_scope(|| {
                    warn!(%error, "{}", self);
                });
            }
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ZebraConnectError(..) => {
                write!(f, "failed to connect to zebra")
            }
            Error::ZebraReadError(..) => {
                write!(f, "failed to read data from zebra")
            }
            Error::ZebraDisconnected => {
                write!(f, "disconnected from zebra")
            }
            Error::DecodeError(..) => {
                write!(f, "error parsing ZAPI message")
            }
        }
    }
}

impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Error {
        Error::DecodeError(error)
    }
}

// ===== impl DecodeError =====

impl std::error::Error for DecodeError {}

impl std::fmt::Display for DecodeError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::IoError(err) =>
                write!(f, "I/O error: {}", err),
            DecodeError::PartialMessage =>
                write!(f, "Incomplete message"),
            DecodeError::VersionMismatch(version, marker) =>
                write!(f, "version mismatch, marker {}, version {}", marker, version),
            DecodeError::MalformedMessage(err) =>
                write!(f, "{}", err),
            DecodeError::MalformedPrefix(err) =>
                write!(f, "malformed prefix: {}", err),
            DecodeError::UnknownProtocol(proto) =>
                write!(f, "unknown protocol: {}", proto),
            DecodeError::UnknownNexthopType(nhtype) =>
                write!(f, "unknown nexthop type: {}", nhtype),
        }
    }
}

impl From<std::io::Error> for DecodeError {
    fn from(error: std::io::Error) -> DecodeError {
        DecodeError::IoError(error)
    }
}

impl From<IpNetworkError> for DecodeError {
    fn from(error: IpNetworkError) -> DecodeError {
        DecodeError::MalformedPrefix(error)
    }
}
