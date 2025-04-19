//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ip::AddressFamily;
use holo_yang::ToYang;
use tracing::{error, warn, warn_span};

use crate::collections::{
    AdjacencyId, InterfaceId, InterfaceIndex, LspEntryId,
};
use crate::instance::InstanceArenas;
use crate::network::MulticastAddr;
use crate::packet::error::DecodeError;
use crate::packet::{LevelNumber, SystemId};
use crate::spf;

// IS-IS errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    // Inter-task communication
    InterfaceIdNotFound(InterfaceId),
    AdjacencyIdNotFound(AdjacencyId),
    LspEntryIdNotFound(LspEntryId),
    // Packet input
    PduDecodeError(InterfaceIndex, [u8; 6], DecodeError),
    AdjacencyReject(InterfaceIndex, [u8; 6], AdjacencyRejectError),
    // Segment Routing
    SrCapNotFound(LevelNumber, SystemId),
    SrCapUnsupportedAf(LevelNumber, SystemId, AddressFamily),
    InvalidSidIndex(u32),
    // Other
    CircuitIdAllocationFailed,
    SpfDelayUnexpectedEvent(LevelNumber, spf::fsm::State, spf::fsm::Event),
    InterfaceStartError(String, Box<Error>),
    InstanceStartError(Box<Error>),
}

// IS-IS I/O errors.
#[derive(Debug)]
pub enum IoError {
    SocketError(std::io::Error),
    MulticastJoinError(MulticastAddr, std::io::Error),
    MulticastLeaveError(MulticastAddr, std::io::Error),
    RecvError(std::io::Error),
    RecvMissingSourceAddr,
    SendError(std::io::Error),
}

#[derive(Debug)]
pub enum AdjacencyRejectError {
    InvalidHelloType,
    CircuitTypeMismatch,
    MaxAreaAddrsMismatch(u8),
    AreaMismatch,
    WrongSystem,
    DuplicateSystemId,
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self, arenas: &InstanceArenas) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::InterfaceIdNotFound(iface_id) => {
                warn!(?iface_id, "{}", self);
            }
            Error::AdjacencyIdNotFound(adj_id) => {
                warn!(?adj_id, "{}", self);
            }
            Error::LspEntryIdNotFound(lse_id) => {
                warn!(?lse_id, "{}", self);
            }
            Error::PduDecodeError(iface_idx, source, error) => {
                let iface = &arenas.interfaces[*iface_idx];
                warn_span!("interface", name = %iface.name, ?source).in_scope(
                    || {
                        warn!(%error, "{}", self);
                    },
                )
            }
            Error::AdjacencyReject(iface_idx, source, error) => {
                let iface = &arenas.interfaces[*iface_idx];
                warn_span!("interface", name = %iface.name, ?source).in_scope(
                    || {
                        error.log();
                    },
                )
            }
            Error::CircuitIdAllocationFailed => {
                warn!("{}", self);
            }
            Error::SrCapNotFound(level, system_id) => {
                warn!(%level, system_id = %system_id.to_yang(), "{}", self);
            }
            Error::SrCapUnsupportedAf(level, system_id, af) => {
                warn!(%level, system_id = %system_id.to_yang(), %af, "{}", self);
            }
            Error::InvalidSidIndex(sid_index) => {
                warn!(%sid_index, "{}", self);
            }
            Error::SpfDelayUnexpectedEvent(level, state, event) => {
                warn!(?level, ?state, ?event, "{}", self);
            }
            Error::InterfaceStartError(name, error) => {
                error!(%name, error = %with_source(error), "{}", self);
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
            Error::InterfaceIdNotFound(..) => {
                write!(f, "interface ID not found")
            }
            Error::AdjacencyIdNotFound(..) => {
                write!(f, "adjacency ID not found")
            }
            Error::LspEntryIdNotFound(..) => {
                write!(f, "LSP entry ID not found")
            }
            Error::PduDecodeError(..) => {
                write!(f, "failed to decode packet")
            }
            Error::AdjacencyReject(_, _, error) => error.fmt(f),
            Error::CircuitIdAllocationFailed => {
                write!(f, "failed to allocate Circuit ID")
            }
            Error::SrCapNotFound(..) => {
                write!(f, "failed to find next-hop's neighbor SR capabilities")
            }
            Error::SrCapUnsupportedAf(..) => {
                write!(
                    f,
                    "next-hop router doesn't support SR-MPLS for the address family"
                )
            }
            Error::InvalidSidIndex(..) => {
                write!(f, "failed to map SID index to MPLS label")
            }
            Error::SpfDelayUnexpectedEvent(..) => {
                write!(f, "unexpected SPF Delay FSM event")
            }
            Error::InterfaceStartError(..) => {
                write!(f, "failed to start interface")
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
            Error::InterfaceStartError(_, error) => Some(error),
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
                write!(f, "failed to create raw socket")
            }
            IoError::MulticastJoinError(..) => {
                write!(f, "failed to join multicast group")
            }
            IoError::MulticastLeaveError(..) => {
                write!(f, "failed to leave multicast group")
            }
            IoError::RecvError(..) => {
                write!(f, "failed to receive packet")
            }
            IoError::RecvMissingSourceAddr => {
                write!(
                    f,
                    "failed to retrieve source address from received packet"
                )
            }
            IoError::SendError(..) => {
                write!(f, "failed to send packet")
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

// ===== impl AdjacencyRejectError =====

impl AdjacencyRejectError {
    pub(crate) fn log(&self) {
        match self {
            AdjacencyRejectError::MaxAreaAddrsMismatch(max_area_addrs) => {
                warn!(%max_area_addrs, "{}", self);
            }
            _ => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for AdjacencyRejectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdjacencyRejectError::InvalidHelloType => {
                write!(f, "invalid hello type")
            }
            AdjacencyRejectError::CircuitTypeMismatch => {
                write!(f, "level mismatch")
            }
            AdjacencyRejectError::MaxAreaAddrsMismatch(..) => {
                write!(f, "maximumAreaAddresses mismatch")
            }
            AdjacencyRejectError::AreaMismatch => {
                write!(f, "area mismatch")
            }
            AdjacencyRejectError::WrongSystem => {
                write!(f, "wrong system")
            }
            AdjacencyRejectError::DuplicateSystemId => {
                write!(f, "duplicate System-ID")
            }
        }
    }
}

impl std::error::Error for AdjacencyRejectError {}

// ===== helper functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
