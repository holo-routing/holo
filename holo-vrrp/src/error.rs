//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use tracing::{warn, warn_span};

// VRRP errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),

    // other errors
    VersionError,
    VridError,
    AddressListError(Vec<IpAddr>, Vec<IpAddr>),
    IntervalError
}

// VRRP I/O errors.
#[derive(Debug)]
pub enum IoError {
    ChecksumError(std::io::Error),
    PacketLengthError(std::io::Error),
    IpTtlError(std::io::Error)
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            },
            Error::VersionError => {
                warn_span!("virtual_router").in_scope(|| {
                    warn!("{}", self);
                });
            },
            Error::VridError => {
                warn_span!("virtual_router").in_scope(|| {
                    warn!("{}", self)
                });
            },
            Error::AddressListError(_, _) => {
                warn_span!("virtual_router").in_scope(|| {
                    warn!("{}", self)
                });
            },
            Error::IntervalError => {
                warn_span!("virtual_router").in_scope(|| {
                    warn!("{}", self)
                });
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::VersionError => {
                write!(f, "invalid version received")
            },
            Error::VridError => {
                write!(f, "virtual router id(VRID) not matching locally configured")
            },
            Error::AddressListError(..) => {
                write!(f, "received address list not matching local address list")
            },
            Error::IntervalError => {
                write!(f, "received advert interval not matching local configured advert interval")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            _ => None,
        }
    }
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Error {
        Error::IoError(error)
    }
}

// ===== impl IoError =====

impl IoError {
    pub(crate) fn log(&self) {
        match self {
            IoError::ChecksumError(error)
            | IoError::PacketLengthError(error)
            | IoError::IpTtlError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::ChecksumError(..) => {
                write!(f, "invalid VRRP checksum")
            },
            IoError::PacketLengthError(..) => {
                write!(f, "VRRP packet length not reaching minimum 50 bytes")
            },
            IoError::IpTtlError(..) => {
                write!(f, "VRRP pkt TTL must be 255")
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::ChecksumError(error)
            | IoError::PacketLengthError(error)
            | IoError::IpTtlError(error) => {
                Some(error)
            }
        }
    }
}

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
