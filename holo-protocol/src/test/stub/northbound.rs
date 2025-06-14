//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_northbound::configuration::{self, CommitPhase, ConfigChanges};
use holo_northbound::{NbDaemonSender, api};
use holo_yang::YANG_CTX;
use tokio::sync::oneshot;
use yang3::data::{
    Data, DataDiff, DataDiffFlags, DataFormat, DataOperation, DataParserFlags,
    DataPrinterFlags, DataTree, DataValidationFlags,
};

use crate::test::stub::UPDATE_OUTPUTS;

// Stub northbound layer.
#[derive(Debug)]
pub struct NorthboundStub {
    running_config: Arc<DataTree<'static>>,
    state_cache: Option<DataTree<'static>>,
    daemon_tx: NbDaemonSender,
}

// ===== impl NorthboundStub =====

impl NorthboundStub {
    pub fn new(daemon_tx: NbDaemonSender) -> NorthboundStub {
        let yang_ctx = YANG_CTX.get().unwrap();
        let running_config = Arc::new(DataTree::new(yang_ctx));

        NorthboundStub {
            running_config,
            state_cache: None,
            daemon_tx,
        }
    }

    pub(crate) async fn commit_changes(&mut self, data_diff_str: &str) {
        let yang_ctx = YANG_CTX.get().unwrap();

        // Parse data diff.
        let data_diff = DataDiff::parse_string(
            yang_ctx,
            data_diff_str,
            DataFormat::JSON,
            DataParserFlags::NO_VALIDATION,
            DataValidationFlags::empty(),
        )
        .expect("Failed to parse data diff");

        // Create candidate configuration.
        let mut candidate = self
            .running_config
            .duplicate()
            .expect("Failed to duplicate running configuration");
        candidate
            .diff_apply(&data_diff)
            .expect("Failed to apply data diff");
        candidate
            .validate(DataValidationFlags::NO_STATE)
            .expect("Failed to validate updated configuration");

        self.commit(candidate, data_diff).await;
    }

    pub async fn commit_replace(&mut self, data_str: &str) {
        let yang_ctx = YANG_CTX.get().unwrap();

        // Parse candidate configuration.
        let candidate = DataTree::parse_string(
            yang_ctx,
            data_str,
            DataFormat::JSON,
            DataParserFlags::empty(),
            DataValidationFlags::NO_STATE,
        )
        .expect("Failed to parse data tree");

        // Get data diff.
        let data_diff = self
            .running_config
            .diff(&candidate, DataDiffFlags::empty())
            .expect("Failed to compare data trees");

        self.commit(candidate, data_diff).await;
    }

    pub(crate) async fn rpc(&mut self, data: &str) {
        let yang_ctx = YANG_CTX.get().unwrap();

        // Parse RPC data.
        let data = DataTree::parse_op_string(
            yang_ctx,
            data,
            DataFormat::JSON,
            DataOperation::RpcYang,
        )
        .expect("Failed to parse RPC data");

        // Prepare request.
        let (responder_tx, responder_rx) = oneshot::channel();
        let request = api::daemon::Request::Rpc(api::daemon::RpcRequest {
            data,
            responder: Some(responder_tx),
        });

        // Send the request and receive the response.
        self.daemon_tx
            .send(request)
            .await
            .expect("Failed to send RPC request");
        let _ = responder_rx.await.expect("Failed to receive RPC response");
    }

    pub(crate) async fn init_state_cache(&mut self) {
        let state = self.get_state().await;
        self.state_cache = Some(state);
    }

    async fn get_state(&self) -> DataTree<'static> {
        // Prepare request.
        let (responder_tx, responder_rx) = oneshot::channel();
        let request = api::daemon::Request::Get(api::daemon::GetRequest {
            path: None,
            responder: Some(responder_tx),
        });

        // Send the request and receive the response.
        self.daemon_tx
            .send(request)
            .await
            .expect("Failed to send Get request");
        let response = responder_rx
            .await
            .expect("Failed to receive Get response")
            .expect("Received invalid state data");
        response.data
    }

    pub(crate) async fn assert_state(
        &mut self,
        expected: Option<&str>,
        path: &impl AsRef<std::path::Path>,
    ) {
        let yang_ctx = YANG_CTX.get().unwrap();

        // Get actual output.
        let actual = self.get_state().await;

        // Update or verify output.
        if *UPDATE_OUTPUTS {
            match self.state_cache.as_ref() {
                Some(old_state) => {
                    // In case this isn't the first time we're retrieving the
                    // state data, create/update the expected output file only
                    // if anything has changed.
                    let data_diff = actual
                        .diff(old_state, DataDiffFlags::empty())
                        .expect("Failed to compare data trees");
                    if data_diff.iter().next().is_none() {
                        let _ = std::fs::remove_file(path);
                    } else {
                        std::fs::write(path, dtree_print(&actual)).unwrap();
                    }
                }
                None => {
                    std::fs::write(path, dtree_print(&actual)).unwrap();
                }
            }
        } else {
            let expected = match expected {
                // Convert expected data string to data tree.
                Some(data) => DataTree::parse_string(
                    yang_ctx,
                    data,
                    DataFormat::JSON,
                    DataParserFlags::NO_VALIDATION,
                    DataValidationFlags::empty(),
                )
                .expect("Failed to parse data tree"),
                None => self.state_cache.as_ref().unwrap().duplicate().unwrap(),
            };

            let data_diff = actual
                .diff(&expected, DataDiffFlags::empty())
                .expect("Failed to compare data trees");
            assert!(
                data_diff.iter().next().is_none(),
                "unexpected state data: {}",
                data_diff
                    .print_string(
                        DataFormat::JSON,
                        DataPrinterFlags::WITH_SIBLINGS
                            | DataPrinterFlags::WD_TRIM,
                    )
                    .unwrap()
            );
        }

        // Update state cache.
        self.state_cache = Some(actual.duplicate().unwrap());
    }

    async fn commit(
        &mut self,
        candidate: DataTree<'static>,
        data_diff: DataDiff<'static>,
    ) {
        // Get configuration changes from data diff.
        let changes = configuration::changes_from_diff(&data_diff);

        // Send configuration changes.
        let candidate = Arc::new(candidate);
        self.commit_phase_notify(CommitPhase::Prepare, &candidate, &changes)
            .await;
        self.commit_phase_notify(CommitPhase::Apply, &candidate, &changes)
            .await;

        // Update running configuration.
        self.running_config = candidate;
    }

    async fn commit_phase_notify(
        &self,
        phase: CommitPhase,
        candidate: &Arc<DataTree<'static>>,
        changes: &ConfigChanges,
    ) {
        // Prepare request.
        let (responder_tx, responder_rx) = oneshot::channel();
        let request =
            api::daemon::Request::Commit(api::daemon::CommitRequest {
                phase,
                old_config: self.running_config.clone(),
                new_config: candidate.clone(),
                changes: changes.clone(),
                responder: Some(responder_tx),
            });

        // Send the request and receive the response.
        self.daemon_tx
            .send(request)
            .await
            .expect("Failed to send commit request");
        let _ = responder_rx
            .await
            .expect("Failed to receive commit response");
    }
}

// ===== helper functions =====

fn dtree_print(dtree: &DataTree<'static>) -> String {
    dtree
        .print_string(DataFormat::JSON, DataPrinterFlags::WITH_SIBLINGS)
        .unwrap()
}
