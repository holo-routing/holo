//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use indextree::NodeId;

#[derive(Debug)]
pub enum Error {
    Parser(ParserError),
    EditConfig(yang2::Error),
    ValidateConfig(yang2::Error),
    Callback(String),
    Backend(tonic::Status),
}

#[derive(Debug)]
pub enum ParserError {
    NoMatch,
    Incomplete(NodeId),
    Ambiguous(Vec<NodeId>),
}

// ===== impl Error =====

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parser(error) => write!(f, "{}", error),
            Error::EditConfig(error) => {
                write!(f, "failed to edit configuration: {}", error)
            }
            Error::ValidateConfig(error) => {
                write!(f, "failed to validate configuration: {}", error)
            }
            Error::Callback(error) => {
                write!(f, "failed to execute command: {}", error)
            }
            Error::Backend(error) => {
                write!(f, "{}", error)
            }
        }
    }
}

impl std::error::Error for Error {}

// ===== impl ParserError =====

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserError::NoMatch => write!(f, "unknown command"),
            ParserError::Incomplete(_) => write!(f, "incomplete command"),
            ParserError::Ambiguous(_) => write!(f, "ambiguous command"),
        }
    }
}

impl std::error::Error for ParserError {}
