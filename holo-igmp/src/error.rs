//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{error, warn};

// IGMP errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    // Other
    InterfaceStartError(String, Box<Error>),
}

// IGMP I/O errors.
#[derive(Debug)]
pub enum IoError {
    SocketError(std::io::Error),
    RecvError(std::io::Error),
    SendError(std::io::Error),
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
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
            Error::InterfaceStartError(_, error) => Some(error),
            //_ => None,
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
            IoError::RecvError(error) | IoError::SendError(error) => {
                warn!(error = %with_source(error), "{}", self);
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
            IoError::RecvError(..) => {
                write!(f, "failed to receive IP packet")
            }
            IoError::SendError(..) => {
                write!(f, "failed to send IP packet")
            }
        }
    }
}

impl std::error::Error for IoError {}

// ===== global functions =====

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
