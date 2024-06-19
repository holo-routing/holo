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
    VridError,
    AddressListError(Vec<IpAddr>, Vec<IpAddr>),
    IntervalError
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

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
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

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}