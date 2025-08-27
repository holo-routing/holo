//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use tracing::{error, warn, warn_span};

use crate::packet::error::DecodeError;

// BGP errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    // Network input
    NbrRxError(IpAddr, NbrRxError),
    // Message processing
    NbrBadAs(IpAddr, u32, u32),
    NbrBadIdentifier(IpAddr, Ipv4Addr),
    // Other
    InstanceStartError(Box<Error>),
}

// BGP I/O errors.
#[derive(Debug)]
pub enum IoError {
    TcpSocketError(std::io::Error),
    TcpAcceptError(std::io::Error),
    TcpConnectError(std::io::Error),
    TcpInfoError(std::io::Error),
    TcpAuthError(std::io::Error),
    TcpRecvError(std::io::Error),
    TcpSendError(std::io::Error),
}

// Neighbor Rx errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum NbrRxError {
    TcpConnClosed,
    MsgDecodeError(DecodeError),
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::NbrRxError(addr, error) => {
                warn_span!("neighbor", %addr).in_scope(|| {
                    error.log();
                });
            }
            Error::NbrBadAs(addr, received, expected) => {
                warn_span!("neighbor", %addr).in_scope(|| {
                    warn!(%received, %expected, "{}", self);
                });
            }
            Error::NbrBadIdentifier(addr, identifier) => {
                warn_span!("neighbor", %addr).in_scope(|| {
                    warn!(%identifier, "{}", self);
                });
            }
            Error::InstanceStartError(error) => {
                error!(error = %with_source(error), "{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::NbrRxError(_, error) => error.fmt(f),
            Error::NbrBadAs(..) => {
                write!(f, "bad peer AS")
            }
            Error::NbrBadIdentifier(..) => {
                write!(f, "BGP identifier conflict")
            }
            Error::InstanceStartError(..) => {
                write!(f, "failed to start instance")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::NbrRxError(_, error) => Some(error),
            Error::InstanceStartError(error) => Some(error),
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
            IoError::TcpSocketError(error)
            | IoError::TcpAcceptError(error)
            | IoError::TcpConnectError(error)
            | IoError::TcpAuthError(error)
            | IoError::TcpInfoError(error)
            | IoError::TcpRecvError(error)
            | IoError::TcpSendError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::TcpSocketError(..) => {
                write!(f, "failed to create TCP socket")
            }
            IoError::TcpAcceptError(..) => {
                write!(f, "failed to accept connection request")
            }
            IoError::TcpConnectError(..) => {
                write!(f, "failed to establish TCP connection")
            }
            IoError::TcpAuthError(..) => {
                write!(f, "failed to set TCP authentication option")
            }
            IoError::TcpInfoError(..) => {
                write!(
                    f,
                    "failed to fetch address and port information from the socket"
                )
            }
            IoError::TcpRecvError(..) => {
                write!(f, "failed to read TCP data")
            }
            IoError::TcpSendError(..) => {
                write!(f, "failed to send TCP data")
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::TcpSocketError(error)
            | IoError::TcpAcceptError(error)
            | IoError::TcpConnectError(error)
            | IoError::TcpAuthError(error)
            | IoError::TcpInfoError(error)
            | IoError::TcpRecvError(error)
            | IoError::TcpSendError(error) => Some(error),
        }
    }
}

// ===== impl NbrRxError =====

impl NbrRxError {
    pub(crate) fn log(&self) {
        match self {
            NbrRxError::TcpConnClosed => {
                warn!("{}", self);
            }
            NbrRxError::MsgDecodeError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
        }
    }
}

impl std::fmt::Display for NbrRxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NbrRxError::TcpConnClosed => {
                write!(f, "connection closed by remote end")
            }
            NbrRxError::MsgDecodeError(..) => {
                write!(f, "failed to decode BGP message")
            }
        }
    }
}

impl std::error::Error for NbrRxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NbrRxError::MsgDecodeError(error) => Some(error),
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
