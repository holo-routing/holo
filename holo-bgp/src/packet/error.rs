//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use serde::{Deserialize, Serialize};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// BGP message decoding errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    MessageHeader(MessageHeaderError),
    OpenMessage(OpenMessageError),
    UpdateMessage(UpdateMessageError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MessageHeaderError {
    ConnectionNotSynchronized,
    BadMessageLength(u16),
    BadMessageType(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum OpenMessageError {
    UnsupportedVersion(u8),
    BadPeerAs,
    BadBgpIdentifier,
    UnsupportedOptParam,
    UnacceptableHoldTime,
    UnsupportedCapability,
    MalformedOptParam,
}

// UPDATE message errors.
//
// NOTE: many of the errors originally specified by RFC 4271 were made obsolete
// by RFC 7606.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum UpdateMessageError {
    MalformedAttributeList,
    UnrecognizedWellKnownAttribute,
    OptionalAttributeError,
    InvalidNetworkField,
}

// Attribute errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum AttrError {
    Discard,
    Withdraw,
    Reset,
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::MessageHeader(error) => error.fmt(f),
            DecodeError::OpenMessage(error) => error.fmt(f),
            DecodeError::UpdateMessage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<MessageHeaderError> for DecodeError {
    fn from(error: MessageHeaderError) -> DecodeError {
        DecodeError::MessageHeader(error)
    }
}

impl From<OpenMessageError> for DecodeError {
    fn from(error: OpenMessageError) -> DecodeError {
        DecodeError::OpenMessage(error)
    }
}

impl From<UpdateMessageError> for DecodeError {
    fn from(error: UpdateMessageError) -> DecodeError {
        DecodeError::UpdateMessage(error)
    }
}

// ===== impl MessageHeaderError =====

impl std::fmt::Display for MessageHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageHeaderError::ConnectionNotSynchronized => {
                write!(f, "Connection not synchronized")
            }
            MessageHeaderError::BadMessageLength(len) => {
                write!(f, "Invalid message length: {}", len)
            }
            MessageHeaderError::BadMessageType(msg_type) => {
                write!(f, "Invalid message type: {}", msg_type)
            }
        }
    }
}

// ===== impl OpenMessageError =====

impl std::fmt::Display for OpenMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OPEN message error: ")?;

        match self {
            OpenMessageError::UnsupportedVersion(version) => {
                write!(f, "unsupported version number: {}", version)
            }
            OpenMessageError::BadPeerAs => {
                write!(f, "bad peer AS")
            }
            OpenMessageError::BadBgpIdentifier => {
                write!(f, "bad BGP identifier")
            }
            OpenMessageError::UnsupportedOptParam => {
                write!(f, "unsupported optional parameter")
            }
            OpenMessageError::UnacceptableHoldTime => {
                write!(f, "unacceptable hold time")
            }
            OpenMessageError::UnsupportedCapability => {
                write!(f, "unsupported capability")
            }
            OpenMessageError::MalformedOptParam => {
                write!(f, "malformed optional parameter")
            }
        }
    }
}

// ===== impl UpdateMessageError =====

impl std::fmt::Display for UpdateMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UPDATE message error: ")?;

        match self {
            UpdateMessageError::MalformedAttributeList => {
                write!(f, "malformed attribute list")
            }
            UpdateMessageError::UnrecognizedWellKnownAttribute => {
                write!(f, "unrecognized well-known attribute")
            }
            UpdateMessageError::OptionalAttributeError => {
                write!(f, "optional attribute error")
            }
            UpdateMessageError::InvalidNetworkField => {
                write!(f, "invalid network field")
            }
        }
    }
}
