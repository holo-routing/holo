//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::Path;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot::Sender as Responder;
use yang5::data::{DataDiff, DataTree};

use crate::northbound::Result;
use crate::northbound::core::Transaction;

// Daemon -> External client requests.
pub mod daemon {}

// External client -> Daemon requests.
pub mod client {
    use super::*;

    #[derive(Debug)]
    pub enum Request {
        // Request to get state data.
        GetState(GetStateRequest),
        // Request to get configuration data.
        GetConfig(GetConfigRequest),
        // Request to validate a candidate configuration.
        Validate(ValidateRequest),
        // Request to change the running configuration.
        Commit(CommitRequest),
        // Request to invoke a YANG RPC or Action.
        Execute(ExecuteRequest),
        // Request to get the list of transactions recorded in the rollback
        // log.
        ListTransactions(ListTransactionsRequest),
        // Request to retrieve configuration data from the rollback log.
        GetTransaction(GetTransactionRequest),
        // Request to subscribe to YANG notifications.
        Subscribe(SubscribeRequest),
    }

    #[derive(Debug)]
    pub struct GetStateRequest {
        pub path: Option<Path>,
        pub responder: Responder<Result<GetStateResponse>>,
    }

    #[derive(Debug)]
    pub struct GetStateResponse {
        pub dtree: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct GetConfigRequest {
        pub path: Option<Path>,
        pub responder: Responder<Result<GetConfigResponse>>,
    }

    #[derive(Debug)]
    pub struct GetConfigResponse {
        pub dtree: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct ValidateRequest {
        pub config: DataTree<'static>,
        pub responder: Responder<Result<ValidateResponse>>,
    }

    #[derive(Debug)]
    pub struct ValidateResponse {}

    #[derive(Debug)]
    pub struct CommitRequest {
        pub config: CommitConfiguration,
        pub comment: String,
        pub confirmed_timeout: u32,
        pub responder: Responder<Result<CommitResponse>>,
    }

    #[derive(Debug)]
    pub struct CommitResponse {
        pub transaction_id: u32,
    }

    #[derive(Debug)]
    pub struct ExecuteRequest {
        pub data: DataTree<'static>,
        pub responder: Responder<Result<ExecuteResponse>>,
    }

    #[derive(Debug)]
    pub struct ExecuteResponse {
        pub data: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct ListTransactionsRequest {
        pub responder: Responder<Result<ListTransactionsResponse>>,
    }

    #[derive(Debug)]
    pub struct ListTransactionsResponse {
        pub transactions: Vec<Transaction>,
    }

    #[derive(Debug)]
    pub struct GetTransactionRequest {
        pub transaction_id: u32,
        pub responder: Responder<Result<GetTransactionResponse>>,
    }

    #[derive(Debug)]
    pub struct GetTransactionResponse {
        pub dtree: DataTree<'static>,
    }

    #[derive(Debug)]
    pub struct SubscribeRequest {
        pub path: Option<String>,
        pub tx: UnboundedSender<SubscribeNotification>,
    }

    #[derive(Debug)]
    pub struct SubscribeNotification {
        pub path: String,
        pub data: DataTree<'static>,
    }
}

#[derive(Debug)]
pub enum CommitConfiguration {
    Merge(DataTree<'static>),
    Replace(DataTree<'static>),
    Change(DataDiff<'static>),
}
