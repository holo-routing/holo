//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use tracing::{error, warn};

use crate::version::Version;

// RIP errors.
#[derive(Debug)]
pub enum Error<V: Version> {
    IoError(IoError),
    UdpInvalidSourceAddr(V::IpAddr),
    UdpPduDecodeError(V::PduDecodeError),
    UdpPduAuthInvalidSeqno(V::SocketAddr, u32),
    InterfaceStartError(String, IoError),
}

// RIP I/O errors.
#[derive(Debug)]
pub enum IoError {
    UdpSocketError(std::io::Error),
    UdpMulticastJoinError(std::io::Error),
    UdpMulticastLeaveError(std::io::Error),
    UdpRecvError(std::io::Error),
    UdpSendError(std::io::Error),
}

// RIP metric errors.
#[derive(Debug)]
pub enum MetricError {
    InvalidValue,
}

// ===== impl Error =====

impl<V> Error<V>
where
    V: Version,
{
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::UdpInvalidSourceAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::UdpPduDecodeError(error) => {
                warn!(%error, "{}", self);
            }
            Error::UdpPduAuthInvalidSeqno(source, seqno) => {
                warn!(%source, %seqno, "{}", self);
            }
            Error::InterfaceStartError(name, error) => {
                error!(%name, error = %with_source(error), "{}", self);
            }
        }
    }
}

impl<V> std::fmt::Display for Error<V>
where
    V: Version,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::UdpInvalidSourceAddr(..) => {
                write!(f, "invalid source address")
            }
            Error::UdpPduDecodeError(..) => {
                write!(f, "failed to decode PDU")
            }
            Error::UdpPduAuthInvalidSeqno(..) => {
                write!(f, "authentication failed: decreasing sequence number")
            }
            Error::InterfaceStartError(..) => {
                write!(f, "failed to start interface")
            }
        }
    }
}

impl<V> std::error::Error for Error<V>
where
    V: Version,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::UdpPduDecodeError(error) => Some(error),
            Error::InterfaceStartError(_, error) => Some(error),
            _ => None,
        }
    }
}

impl<V> From<IoError> for Error<V>
where
    V: Version,
{
    fn from(error: IoError) -> Error<V> {
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
            | IoError::UdpSendError(error) => {
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
            | IoError::UdpSendError(error) => Some(error),
        }
    }
}

// ===== impl MetricError =====

impl std::fmt::Display for MetricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricError::InvalidValue => {
                write!(f, "invalid RIP metric")
            }
        }
    }
}

impl std::error::Error for MetricError {}

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
