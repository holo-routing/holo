//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_utils::Responder;
use yang2::data::DataTree;

use crate::northbound::Result;

// Daemon -> External client requests.
#[allow(dead_code)]
pub mod daemon {}

// External client -> Daemon requests.
pub mod client {
    use super::*;

    #[derive(Debug)]
    pub enum Request {
        // Request to get data (configuration, state or both).
        Get(GetRequest),
        // Request to change the running configuration.
        Commit(CommitRequest),
        // Request to invoke a YANG RPC or Action.
        Execute(ExecuteRequest),
    }

    #[derive(Debug)]
    pub struct GetRequest {
        pub data_type: DataType,
        pub path: Option<String>,
        pub responder: Responder<Result<GetResponse>>,
    }

    #[derive(Debug)]
    pub struct GetResponse {
        pub dtree: DataTree,
    }

    #[derive(Debug)]
    pub struct CommitRequest {
        pub operation: CommitOperation,
        pub config: DataTree,
        pub confirmed_timeout: u32,
        pub responder: Responder<Result<CommitResponse>>,
    }

    #[derive(Debug)]
    pub struct CommitResponse {
        pub transaction_id: u32,
    }

    #[derive(Debug)]
    pub struct ExecuteRequest {
        pub data: DataTree,
        pub responder: Responder<Result<ExecuteResponse>>,
    }

    #[derive(Debug)]
    pub struct ExecuteResponse {
        pub data: DataTree,
    }

    // ===== impl Request =====

    impl std::fmt::Display for Request {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Request::Get(_) => write!(f, "Get"),
                Request::Commit(_) => write!(f, "Commit"),
                Request::Execute(_) => write!(f, "Execute"),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DataType {
    All,
    Configuration,
    State,
}

#[derive(Clone, Copy, Debug)]
pub enum CommitOperation {
    Merge,
    Replace,
    Change,
}
