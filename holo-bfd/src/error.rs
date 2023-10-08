//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use tracing::warn;

use crate::network::PacketInfo;
use crate::packet::{DecodeError, PacketFlags};
use crate::session::SessionId;

// BFD errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    // Inter-task communication
    SessionIdNotFound(SessionId),
    // Packet input
    UdpInvalidSourceAddr(IpAddr),
    UdpPacketDecodeError(DecodeError),
    SessionNoMatch(PacketInfo, u32),
    VersionMismatch(u8),
    InvalidDetectMult(u8),
    InvalidFlags(PacketFlags),
    InvalidMyDiscriminator(u32),
    InvalidYourDiscriminator(u32),
    AuthError,
}

// BFD I/O errors.
#[derive(Debug)]
pub enum IoError {
    UdpSocketError(std::io::Error),
    UdpRecvError(std::io::Error),
    UdpSendError(std::io::Error),
    UdpRecvMissingSourceAddr,
    UdpRecvMissingAncillaryData,
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::SessionIdNotFound(sess_id) => {
                warn!(?sess_id, "{}", self);
            }
            Error::UdpInvalidSourceAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::UdpPacketDecodeError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            Error::VersionMismatch(version) => {
                warn!(%version, "{}", self);
            }
            Error::SessionNoMatch(packet_info, your_discr) => {
                warn!(?packet_info, %your_discr, "{}", self);
            }
            Error::InvalidDetectMult(detect_mult) => {
                warn!(%detect_mult, "{}", self);
            }
            Error::InvalidFlags(flags) => {
                warn!(?flags, "{}", self);
            }
            Error::InvalidMyDiscriminator(discr) => {
                warn!(%discr, "{}", self);
            }
            Error::InvalidYourDiscriminator(discr) => {
                warn!(%discr, "{}", self);
            }
            Error::AuthError => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::SessionIdNotFound(..) => {
                write!(f, "session ID not found")
            }
            Error::UdpInvalidSourceAddr(..) => {
                write!(f, "invalid source address")
            }
            Error::UdpPacketDecodeError(..) => {
                write!(f, "failed to decode packet")
            }
            Error::SessionNoMatch(..) => {
                write!(f, "failed to find session")
            }
            Error::VersionMismatch(..) => {
                write!(f, "packet version mismatch")
            }
            Error::InvalidDetectMult(..) => {
                write!(f, "received invalid detection multiplier")
            }
            Error::InvalidFlags(..) => {
                write!(f, "received invalid flags")
            }
            Error::InvalidMyDiscriminator(..) => {
                write!(f, "received invalid My Discriminator")
            }
            Error::InvalidYourDiscriminator(..) => {
                write!(f, "received invalid Your Discriminator")
            }
            Error::AuthError => {
                write!(f, "failed to authenticate packet")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::UdpPacketDecodeError(error) => Some(error),
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
            IoError::UdpSocketError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::UdpRecvMissingSourceAddr
            | IoError::UdpRecvMissingAncillaryData => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::UdpSocketError(..) => {
                write!(f, "failed to create UDP socket")
            }
            IoError::UdpRecvError(..) => {
                write!(f, "failed to receive UDP packet")
            }
            IoError::UdpSendError(..) => {
                write!(f, "failed to send UDP packet")
            }
            IoError::UdpRecvMissingSourceAddr => {
                write!(
                    f,
                    "failed to retrieve source address from received packet"
                )
            }
            IoError::UdpRecvMissingAncillaryData => {
                write!(
                    f,
                    "failed to retrieve ancillary data from received packet"
                )
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::UdpSocketError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error) => Some(error),
            _ => None,
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
