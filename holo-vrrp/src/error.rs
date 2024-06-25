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

use tracing::{warn, warn_span};

// VRRP errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    InterfaceError(String),

    // vrrp-ietf-yang-2018-03-13 specific errors
    GlobalError(GlobalError),
    VirtualRouterError(VirtualRouterError),
}

#[derive(Debug)]
pub enum GlobalError {
    ChecksumError,
    IpTtlError,
    VersionError,
    VridError,
}

#[derive(Debug)]
pub enum VirtualRouterError {
    AddressListError,
    IntervalError,
    PacketLengthError,
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
            }
            Error::InterfaceError(error) => {
                warn_span!("vrrp_interface_error").in_scope(|| warn!(error));
            }
            Error::GlobalError(error) => {
                match error {
                    GlobalError::ChecksumError => {
                        warn_span!("global_error").in_scope(|| { warn!("invalid checksum received") })
                    },
                    GlobalError::IpTtlError => {
                        warn_span!("global_error").in_scope(|| { warn!("TTL for IP packet is not 255.") })
                    },
                    GlobalError::VersionError => {
                        warn_span!("global_error").in_scope(|| { warn!("invalid version received. only version 2 accepted.") })
                    },
                    GlobalError::VridError => {
                        warn_span!("global_error").in_scope(|| { warn!("vrid is not locally configured. ") })
                    },
                }
            },
            Error::VirtualRouterError(error) => {
                match error {
                    VirtualRouterError::AddressListError => {
                        warn_span!("vr_error").in_scope(|| { warn!("addresses received not locally configured") })
                    },
                    VirtualRouterError::IntervalError => {
                        warn_span!("vr_error").in_scope(|| { warn!("interval does not match locally configured interval") })
                    },
                    VirtualRouterError::PacketLengthError => {
                        warn_span!("vr_error").in_scope(|| { warn!("packet length error") });
                    },
                }
            },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => std::fmt::Display::fmt(error, f),
            Error::InterfaceError(error) => write!(f, "{}", error),
            Error::GlobalError(error) => std::fmt::Display::fmt(error, f),
            Error::VirtualRouterError(error) => {
                std::fmt::Display::fmt(error, f)
            }
        }
    }
}

impl std::fmt::Display for GlobalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GlobalError::ChecksumError => {
                write!(f, "incorrect checksum received")
            }
            GlobalError::IpTtlError => {
                write!(f, "invalid ttl received. IP ttl for vrrp should always be 255")
            }
            GlobalError::VersionError => {
                write!(
                    f,
                    "invalid VRRP version received. only version 2 accepted"
                )
            }
            GlobalError::VridError => {
                write!(f, "vrid received is not in the configured VRIDs")
            }
        }
    }
}

impl std::fmt::Display for VirtualRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualRouterError::AddressListError => {
                write!(f, "VRRP address received not in configured addresses")
            }
            VirtualRouterError::IntervalError => {
                write!(f, "VRRP interval received not match locally configured interval")
            }
            VirtualRouterError::PacketLengthError => {
                write!(f, "the VRRP packet should be between 16 bytes and 80 bytes. received packet not in range.")
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
