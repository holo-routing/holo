//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::fmt::Debug;
use std::net::IpAddr;

use tracing::{error, warn};

use crate::packet::DecodeError;

// VRRP errors.
#[derive(Debug)]
pub enum Error {
    InstanceStartError(u8, IoError),
    GlobalError(IpAddr, GlobalError),
    VirtualRouterError(IpAddr, VirtualRouterError),
}

// VRRP I/O errors.
#[derive(Debug)]
pub enum IoError {
    SocketError(std::io::Error),
    MulticastJoinError(IpAddr, std::io::Error),
    MulticastLeaveError(IpAddr, std::io::Error),
    RecvError(std::io::Error),
    RecvMissingSourceAddr,
    SendError(std::io::Error),
}

// VRRP error that occurred for a packet before it reaches a VRRP router.
#[derive(Debug)]
pub enum GlobalError {
    ChecksumError,
    IpTtlError,
    VersionError,
    VridError,
}

// VRRP error that occurred after a packet reaches a VRRP router.
#[derive(Debug)]
pub enum VirtualRouterError {
    AddressListError,
    IntervalError,
    PacketLengthError,
    IpTtlError,
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::InstanceStartError(vrid, error) => {
                error!(%vrid, error = %with_source(error), "{}", self);
            }
            Error::GlobalError(source, error) => {
                warn!(?source, %error, "{}", self);
            }
            Error::VirtualRouterError(source, error) => {
                warn!(?source, %error, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InstanceStartError(..) => {
                write!(f, "failed to start VRRP instance")
            }
            Error::GlobalError(_, error) => std::fmt::Display::fmt(error, f),
            Error::VirtualRouterError(_, error) => {
                std::fmt::Display::fmt(error, f)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InstanceStartError(_, error) => Some(error),
            Error::GlobalError(_, error) => Some(error),
            Error::VirtualRouterError(_, error) => Some(error),
        }
    }
}

impl From<(IpAddr, DecodeError)> for Error {
    fn from((src, error): (IpAddr, DecodeError)) -> Error {
        match error {
            DecodeError::ChecksumError => {
                Error::GlobalError(src, GlobalError::ChecksumError)
            }
            DecodeError::PacketLengthError { .. } => Error::VirtualRouterError(
                src,
                VirtualRouterError::PacketLengthError,
            ),
            DecodeError::IpTtlError { .. } => {
                Error::VirtualRouterError(src, VirtualRouterError::IpTtlError)
            }
        }
    }
}

// ===== impl IoError =====

impl IoError {
    pub(crate) fn log(&self) {
        match self {
            IoError::SocketError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::MulticastJoinError(addr, error)
            | IoError::MulticastLeaveError(addr, error) => {
                warn!(?addr, error = %with_source(error), "{}", self);
            }
            IoError::RecvError(error) | IoError::SendError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::RecvMissingSourceAddr => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::SocketError(..) => {
                write!(f, "failed to create raw IP socket")
            }
            IoError::MulticastJoinError(..) => {
                write!(f, "failed to join multicast group")
            }
            IoError::MulticastLeaveError(..) => {
                write!(f, "failed to leave multicast group")
            }
            IoError::RecvError(..) => {
                write!(f, "failed to receive IP packet")
            }
            IoError::RecvMissingSourceAddr => {
                write!(
                    f,
                    "failed to retrieve source address from received packet"
                )
            }
            IoError::SendError(..) => {
                write!(f, "failed to send IP packet")
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::SocketError(error)
            | IoError::MulticastJoinError(_, error)
            | IoError::MulticastLeaveError(_, error)
            | IoError::RecvError(error)
            | IoError::SendError(error) => Some(error),
            _ => None,
        }
    }
}

// ===== impl GlobalError =====

impl std::fmt::Display for GlobalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GlobalError::ChecksumError => {
                write!(f, "incorrect checksum received")
            }
            GlobalError::IpTtlError => {
                write!(f, "invalid IP TTL received")
            }
            GlobalError::VersionError => {
                write!(f, "unsupported VRRP version received")
            }
            GlobalError::VridError => {
                write!(f, "invalid VRID received")
            }
        }
    }
}

impl std::error::Error for GlobalError {}

// ===== impl VirtualRouterError =====

impl std::fmt::Display for VirtualRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualRouterError::AddressListError => {
                write!(f, "address list mismatch")
            }
            VirtualRouterError::IntervalError => {
                write!(f, "advertisement interval mismatch")
            }
            VirtualRouterError::PacketLengthError => {
                write!(f, "invalid packet length")
            }
            VirtualRouterError::IpTtlError => {
                write!(f, "invalid IP packet TTL")
            }
        }
    }
}

impl std::error::Error for VirtualRouterError {}

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
