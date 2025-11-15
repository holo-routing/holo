//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bytes::TryGetError;
use serde::{Deserialize, Serialize};

// BGP message decoding errors.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ReadOutOfBounds,
    MessageHeader(MessageHeaderError),
    OpenMessage(OpenMessageError),
    UpdateMessage(UpdateMessageError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum MessageHeaderError {
    ReadOutOfBounds,
    ConnectionNotSynchronized,
    BadMessageLength(u16),
    BadMessageType(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum OpenMessageError {
    ReadOutOfBounds,
    UnsupportedVersion(u8),
    BadPeerAs,
    BadBgpIdentifier,
    UnsupportedOptParam,
    UnacceptableHoldTime,
    UnsupportedCapability,
    MalformedOptParam,
    RoleMismatch,
}

// UPDATE message errors.
//
// NOTE: many of the errors originally specified by RFC 4271 were made obsolete
// by RFC 7606.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum UpdateMessageError {
    ReadOutOfBounds,
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
            DecodeError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            DecodeError::MessageHeader(error) => error.fmt(f),
            DecodeError::OpenMessage(error) => error.fmt(f),
            DecodeError::UpdateMessage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<TryGetError> for DecodeError {
    fn from(_error: TryGetError) -> DecodeError {
        DecodeError::ReadOutOfBounds
    }
}

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
            MessageHeaderError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            MessageHeaderError::ConnectionNotSynchronized => {
                write!(f, "connection not synchronized")
            }
            MessageHeaderError::BadMessageLength(len) => {
                write!(f, "invalid message length: {len}")
            }
            MessageHeaderError::BadMessageType(msg_type) => {
                write!(f, "invalid message type: {msg_type}")
            }
        }
    }
}

impl From<TryGetError> for MessageHeaderError {
    fn from(_error: TryGetError) -> MessageHeaderError {
        MessageHeaderError::ReadOutOfBounds
    }
}

// ===== impl OpenMessageError =====

impl std::fmt::Display for OpenMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OPEN message error: ")?;

        match self {
            OpenMessageError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
            OpenMessageError::UnsupportedVersion(version) => {
                write!(f, "unsupported version number: {version}")
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
            OpenMessageError::RoleMismatch => {
                write!(f, "BGP role mismatched")
            }
        }
    }
}

impl From<TryGetError> for OpenMessageError {
    fn from(_error: TryGetError) -> OpenMessageError {
        OpenMessageError::ReadOutOfBounds
    }
}

// ===== impl UpdateMessageError =====

impl std::fmt::Display for UpdateMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UPDATE message error: ")?;

        match self {
            UpdateMessageError::ReadOutOfBounds => {
                write!(f, "attempt to read out of bounds")
            }
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

impl From<TryGetError> for UpdateMessageError {
    fn from(_error: TryGetError) -> UpdateMessageError {
        UpdateMessageError::ReadOutOfBounds
    }
}

// ===== impl AttrError =====

impl From<TryGetError> for AttrError {
    fn from(_error: TryGetError) -> AttrError {
        AttrError::Withdraw
    }
}
