//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use tracing::{error, warn, warn_span};

use crate::collections::{AdjacencyId, InterfaceId, NeighborId};
use crate::neighbor;
use crate::packet::error::DecodeError;
use crate::packet::messages::notification::StatusCode;

// LDP errors.
#[derive(Debug, Deserialize, Serialize)]
pub enum Error {
    // I/O errors
    #[serde(skip)]
    IoError(IoError),
    // Inter-task communication
    InterfaceIdNotFound(InterfaceId),
    AdjacencyIdNotFound(AdjacencyId),
    NeighborIdNotFound(NeighborId),
    // Other
    UdpInvalidSourceAddr(IpAddr),
    UdpPduDecodeError(DecodeError),
    TcpConnClosed(Ipv4Addr),
    TcpInvalidConnRequest(Ipv4Addr),
    TcpAdditionalTransportConn(Ipv4Addr),
    NbrPduDecodeError(Ipv4Addr, DecodeError),
    NbrRcvdError(Ipv4Addr, StatusCode),
    NbrSentError(Ipv4Addr, StatusCode),
    NbrFsmUnexpectedEvent(Ipv4Addr, neighbor::fsm::State, neighbor::fsm::Event),
    InstanceStartError(Box<Error>),
    InterfaceStartError(String, Box<Error>),
}

// LDP I/O errors.
#[derive(Debug)]
pub enum IoError {
    UdpSocketError(std::io::Error),
    UdpMulticastJoinError(std::io::Error),
    UdpMulticastLeaveError(std::io::Error),
    UdpRecvError(std::io::Error),
    UdpSendError(std::io::Error),
    TcpSocketError(std::io::Error),
    TcpAcceptError(std::io::Error),
    TcpConnectError(std::io::Error),
    TcpInfoError(std::io::Error),
    TcpAuthError(std::io::Error),
    TcpRecvError(std::io::Error),
    TcpSendError(std::io::Error),
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
            Error::NeighborIdNotFound(nbr_id) => {
                warn!(?nbr_id, "{}", self);
            }
            Error::UdpInvalidSourceAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::UdpPduDecodeError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            Error::TcpConnClosed(lsr_id)
            | Error::TcpInvalidConnRequest(lsr_id)
            | Error::TcpAdditionalTransportConn(lsr_id) => {
                warn_span!("neighbor", %lsr_id).in_scope(|| {
                    warn!("{}", self);
                });
            }
            Error::NbrPduDecodeError(lsr_id, error) => {
                warn_span!("neighbor", %lsr_id).in_scope(|| {
                    warn!(error = %with_source(error), "{}", self);
                });
            }
            Error::NbrRcvdError(lsr_id, status)
            | Error::NbrSentError(lsr_id, status) => {
                warn_span!("neighbor", %lsr_id).in_scope(|| {
                    warn!(?status, "{}", self);
                });
            }
            Error::NbrFsmUnexpectedEvent(lsr_id, state, event) => {
                warn_span!("neighbor", %lsr_id).in_scope(|| {
                    warn_span!("fsm").in_scope(|| {
                        warn!(?state, ?event, "{}", self);
                    });
                });
            }
            Error::InstanceStartError(error) => {
                error!(error = %with_source(error), "{}", self);
            }
            Error::InterfaceStartError(name, error) => {
                error!(%name, error = %with_source(error), "{}", self);
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
            Error::NeighborIdNotFound(..) => {
                write!(f, "neighbor ID not found")
            }
            Error::UdpInvalidSourceAddr(..) => {
                write!(f, "invalid source address")
            }
            Error::UdpPduDecodeError(..) => {
                write!(f, "failed to decode PDU")
            }
            Error::TcpConnClosed(..) => {
                write!(f, "connection closed by remote end")
            }
            Error::TcpInvalidConnRequest(..) => {
                write!(f, "invalid connection request (passive neighbor)")
            }
            Error::TcpAdditionalTransportConn(..) => {
                write!(f, "rejecting additional transport connection")
            }
            Error::NbrPduDecodeError(..) => {
                write!(f, "failed to decode PDU")
            }
            Error::NbrRcvdError(..) => {
                write!(f, "received fatal notification message")
            }
            Error::NbrSentError(..) => {
                write!(f, "sent fatal notification message")
            }
            Error::NbrFsmUnexpectedEvent(..) => {
                write!(f, "unexpected event")
            }
            Error::InstanceStartError(..) => {
                write!(f, "failed to start instance")
            }
            Error::InterfaceStartError(..) => {
                write!(f, "failed to start interface")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::UdpPduDecodeError(error) => Some(error),
            Error::NbrPduDecodeError(_, error) => Some(error),
            Error::InstanceStartError(error) => Some(error),
            Error::InterfaceStartError(_, error) => Some(error),
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
            | IoError::UdpMulticastJoinError(error)
            | IoError::UdpMulticastLeaveError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error)
            | IoError::TcpSocketError(error)
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
            IoError::UdpSocketError(..) => {
                write!(f, "failed to create UDP socket")
            }
            IoError::UdpMulticastJoinError(..) => {
                write!(f, "failed to join multicast group")
            }
            IoError::UdpMulticastLeaveError(..) => {
                write!(f, "failed to leave multicast group")
            }
            IoError::UdpRecvError(..) => {
                write!(f, "failed to receive UDP packet")
            }
            IoError::UdpSendError(..) => {
                write!(f, "failed to send UDP packet")
            }
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
            IoError::UdpSocketError(error)
            | IoError::UdpMulticastJoinError(error)
            | IoError::UdpMulticastLeaveError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error)
            | IoError::TcpSocketError(error)
            | IoError::TcpAcceptError(error)
            | IoError::TcpConnectError(error)
            | IoError::TcpAuthError(error)
            | IoError::TcpInfoError(error)
            | IoError::TcpRecvError(error)
            | IoError::TcpSendError(error) => Some(error),
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
