//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashSet;
use std::sync::Arc;

use holo_utils::Responder;
use serde::{Deserialize, Serialize};
use yang3::data::DataTree;

use crate::configuration::{CommitPhase, ConfigChanges};
use crate::error::Error;
use crate::CallbackKey;

// Daemon -> Provider requests.
pub mod daemon {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub enum Request {
        // Request to get all loaded YANG callbacks.
        GetCallbacks(GetCallbacksRequest),
        // Request to validate a candidate configuration.
        Validate(ValidateRequest),
        // Request to change the running configuration.
        Commit(CommitRequest),
        // Request to get state data.
        Get(GetRequest),
        // Request to invoke a YANG RPC or Action.
        Rpc(RpcRequest),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct GetCallbacksRequest {
        #[serde(skip)]
        pub responder: Option<Responder<GetCallbacksResponse>>,
    }

    #[derive(Debug)]
    pub struct GetCallbacksResponse {
        pub callbacks: HashSet<CallbackKey>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ValidateRequest {
        #[serde(with = "holo_yang::serde::data_tree::arc")]
        pub config: Arc<DataTree>,
        #[serde(skip)]
        pub responder: Option<Responder<Result<ValidateResponse, Error>>>,
    }

    #[derive(Debug)]
    pub struct ValidateResponse {}

    #[derive(Debug, Deserialize, Serialize)]
    pub struct CommitRequest {
        pub phase: CommitPhase,
        #[serde(with = "holo_yang::serde::data_tree::arc")]
        pub old_config: Arc<DataTree>,
        #[serde(with = "holo_yang::serde::data_tree::arc")]
        pub new_config: Arc<DataTree>,
        pub changes: ConfigChanges,
        #[serde(skip)]
        pub responder: Option<Responder<Result<CommitResponse, Error>>>,
    }

    #[derive(Debug)]
    pub struct CommitResponse {}

    #[derive(Debug, Deserialize, Serialize)]
    pub struct GetRequest {
        pub path: Option<String>,
        #[serde(skip)]
        pub responder: Option<Responder<Result<GetResponse, Error>>>,
    }

    #[derive(Debug)]
    pub struct GetResponse {
        pub data: DataTree,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RpcRequest {
        #[serde(with = "holo_yang::serde::data_tree")]
        pub data: DataTree,
        #[serde(skip)]
        pub responder: Option<Responder<Result<RpcResponse, Error>>>,
    }

    #[derive(Debug)]
    pub struct RpcResponse {
        pub data: DataTree,
    }
}

// Provider -> Daemon messages.
pub mod provider {
    use super::*;

    #[derive(Debug)]
    pub struct Notification {
        pub data: DataTree,
    }
}
