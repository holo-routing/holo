//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::DatabaseError;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use holo_yang::ToYang;
use tracing::{error, warn, warn_span};

use crate::collections::{AdjacencyId, InterfaceId, LspEntryId};
use crate::network::MulticastAddr;
use crate::packet::consts::PduType;
use crate::packet::error::DecodeError;
use crate::packet::tlv::ExtendedSeqNum;
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
    // PDU input
    PduInputError(String, MacAddr, PduInputError),
    // Segment Routing
    SrCapNotFound(LevelNumber, SystemId),
    SrCapUnsupportedAf(LevelNumber, SystemId, AddressFamily),
    InvalidSidIndex(u32),
    // Other
    CircuitIdAllocationFailed,
    SpfDelayUnexpectedEvent(LevelNumber, spf::fsm::State, spf::fsm::Event),
    InterfaceStartError(String, Box<Error>),
    InstanceStartError(Box<Error>),
    BootCountNvmUpdate(DatabaseError),
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
pub enum PduInputError {
    DecodeError(DecodeError),
    AdjacencyReject(AdjacencyRejectError),
    ExtendedSeqNumError(ExtendedSeqNumError),
}

#[derive(Debug)]
pub enum AdjacencyRejectError {
    InvalidHelloType,
    CircuitTypeMismatch,
    MaxAreaAddrsMismatch(u8),
    AreaMismatch,
    NeighborMismatch,
    WrongSystem,
    DuplicateSystemId,
    MissingProtocolsSupported,
    NoCommonMt,
}

#[derive(Debug)]
pub enum ExtendedSeqNumError {
    MissingSeqNum(PduType),
    InvalidSeqNum(PduType, ExtendedSeqNum),
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
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
            Error::PduInputError(ifname, source, error) => {
                warn_span!("interface", name = %ifname, %source).in_scope(
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
            Error::BootCountNvmUpdate(error) => {
                error!(%error, "{}", self);
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
            Error::PduInputError(..) => {
                write!(f, "failed to decode packet")
            }
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
            Error::BootCountNvmUpdate(..) => {
                write!(
                    f,
                    "failed to record updated boot count in non-volatile storage"
                )
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

// ===== impl PduInputError =====

impl PduInputError {
    fn log(&self) {
        match self {
            PduInputError::DecodeError(error) => {
                warn!("{}", error);
            }
            PduInputError::AdjacencyReject(error) => {
                error.log();
            }
            PduInputError::ExtendedSeqNumError(error) => {
                error.log();
            }
        }
    }
}

impl From<AdjacencyRejectError> for PduInputError {
    fn from(error: AdjacencyRejectError) -> PduInputError {
        PduInputError::AdjacencyReject(error)
    }
}

impl From<ExtendedSeqNumError> for PduInputError {
    fn from(error: ExtendedSeqNumError) -> PduInputError {
        PduInputError::ExtendedSeqNumError(error)
    }
}

// ===== impl AdjacencyRejectError =====

impl AdjacencyRejectError {
    fn log(&self) {
        match self {
            AdjacencyRejectError::MaxAreaAddrsMismatch(max_area_addrs) => {
                warn!(%max_area_addrs, "adjacency rejected: {}", self);
            }
            _ => {
                warn!("adjacency rejected: {}", self);
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
            AdjacencyRejectError::NeighborMismatch => {
                write!(f, "neighbor mismatch")
            }
            AdjacencyRejectError::WrongSystem => {
                write!(f, "wrong system")
            }
            AdjacencyRejectError::DuplicateSystemId => {
                write!(f, "duplicate System-ID")
            }
            AdjacencyRejectError::MissingProtocolsSupported => {
                write!(f, "missing Protocols Supported TLV")
            }
            AdjacencyRejectError::NoCommonMt => {
                write!(f, "no multi-topology ID in common")
            }
        }
    }
}

impl std::error::Error for AdjacencyRejectError {}

// ===== impl ExtendedSeqNumError =====

impl ExtendedSeqNumError {
    fn log(&self) {
        match self {
            ExtendedSeqNumError::MissingSeqNum(pdu_type) => {
                warn!(?pdu_type, "{}", self);
            }
            ExtendedSeqNumError::InvalidSeqNum(pdu_type, ext_seqnum) => {
                warn!(?pdu_type, ?ext_seqnum, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for ExtendedSeqNumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendedSeqNumError::MissingSeqNum(..) => {
                write!(f, "missing extended sequence number")
            }
            ExtendedSeqNumError::InvalidSeqNum(..) => {
                write!(f, "invalid extended sequence number")
            }
        }
    }
}

impl std::error::Error for ExtendedSeqNumError {}

// ===== helper functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
