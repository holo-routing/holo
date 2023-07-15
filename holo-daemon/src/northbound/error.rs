//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_northbound as northbound;

//
// Type aliases.
//
pub type Result<T> = std::result::Result<T, Error>;

//
// Northbound errors.
//
#[derive(Debug)]
pub enum Error {
    YangInvalidPath(yang2::Error),
    YangInvalidData(yang2::Error),
    YangInternal(yang2::Error),
    TransactionValidation(northbound::error::Error),
    TransactionPreparation(northbound::error::Error),
    TransactionIdNotFound(u32),
    Get(northbound::error::Error),
}

// ===== impl Error =====

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::YangInvalidPath(err) => {
                write!(f, "Invalid YANG data path: {}", err)
            }
            Error::YangInvalidData(err) => {
                write!(f, "Invalid YANG instance data: {}", err)
            }
            Error::YangInternal(err) => {
                write!(f, "YANG internal error: {}", err)
            }
            Error::TransactionValidation(err) => {
                write!(f, "Validation error: {}", err)
            }
            Error::TransactionPreparation(err) => {
                write!(f, "Resource allocation error: {}", err)
            }
            Error::TransactionIdNotFound(id) => {
                write!(f, "Transaction ID not found: {}", id)
            }
            Error::Get(err) => {
                write!(f, "Failed to get operational data: {}", err)
            }
        }
    }
}

impl std::error::Error for Error {}
