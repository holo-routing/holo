//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use tracing::warn;

// Northbound errors.
#[derive(Debug)]
pub enum Error {
    ValidationCallback(String),
    CfgCallback(String),
    RpcNotFound,
    RpcRelay(String),
    RpcCallback(String),
    YangInvalidPath(yang2::Error),
    YangInvalidData(yang2::Error),
}

// ===== impl Error =====

impl Error {
    pub fn log(&self) {
        match self {
            Error::ValidationCallback(error) => {
                warn!(%error, "{}", self);
            }
            Error::CfgCallback(error) => {
                warn!(%error, "{}", self);
            }
            Error::RpcNotFound => warn!("{}", self),
            Error::RpcRelay(error) => {
                warn!(%error, "{}", self);
            }
            Error::RpcCallback(error) => {
                warn!(%error, "{}", self);
            }
            Error::YangInvalidPath(error) => {
                warn!(%error, "{}", self);
            }
            Error::YangInvalidData(error) => {
                warn!(%error, "{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ValidationCallback(..) => {
                write!(f, "validation callback failed")
            }
            Error::CfgCallback(..) => {
                write!(f, "configuration callback failed")
            }
            Error::RpcNotFound => write!(f, "RPC/Action not found"),
            Error::RpcRelay(..) => {
                write!(f, "failed to relay RPC to the appropriate subscriber")
            }
            Error::RpcCallback(..) => {
                write!(f, "RPC callback failed")
            }
            Error::YangInvalidPath(..) => {
                write!(f, "Invalid YANG data path")
            }
            Error::YangInvalidData(..) => {
                write!(f, "Invalid YANG instance data")
            }
        }
    }
}

impl std::error::Error for Error {}
