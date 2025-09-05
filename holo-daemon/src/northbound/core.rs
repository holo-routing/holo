//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use derive_new::new;
use holo_northbound as northbound;
use holo_northbound::configuration::{CommitPhase, ConfigChange};
use holo_northbound::{
    CallbackKey, CallbackOp, NbDaemonSender, NbProviderReceiver, api as papi,
};
use holo_protocol::InstanceShared;
use holo_utils::task::{Task, TimeoutTask};
use holo_utils::yang::SchemaNodeExt;
use holo_utils::{Database, ibus};
use holo_yang::YANG_CTX;
use pickledb::PickleDb;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, WeakSender};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, instrument, trace, warn};
use yang3::data::{
    Data, DataDiffFlags, DataFormat, DataPrinterFlags, DataTree,
    DataValidationFlags,
};

use crate::config::Config;
use crate::northbound::client::{api as capi, gnmi, grpc};
use crate::northbound::{Error, Result, db, yang};

pub struct Northbound {
    // YANG-modeled running configuration.
    running_config: Arc<DataTree<'static>>,
    // Non-volatile storage.
    db: Database,
    // Callback keys from the data providers.
    callbacks: BTreeMap<CallbackKey, WeakSender<papi::daemon::Request>>,
    // List of management interfaces.
    clients: Vec<Task<()>>,
    // List of data providers.
    providers: Vec<NbDaemonSender>,
    // Channel used to receive messages from the external clients.
    rx_clients: Receiver<capi::client::Request>,
    // Channel used to receive messages from the data providers.
    rx_providers: UnboundedReceiver<papi::provider::Notification>,
    // Confirmed commit information.
    confirmed_commit: ConfirmedCommit,
}

#[derive(Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct Transaction {
    // Unique identifier for the transaction.
    #[new(default)]
    pub id: u32,

    // Date and time for when the transaction occurred.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub date: DateTime<Utc>,

    // Optional comment for the transaction.
    pub comment: String,

    // Configuration that was committed.
    #[serde(with = "holo_yang::serde::data_tree")]
    pub configuration: DataTree<'static>,
}

#[derive(Debug)]
pub struct ConfirmedCommit {
    // Channels used to send and receive timeout notifications.
    tx: Sender<()>,
    rx: Receiver<()>,

    // Confirmed commit in progress.
    rollback: Option<Rollback>,
}

#[derive(Debug)]
pub struct Rollback {
    configuration: DataTree<'static>,
    #[expect(unused)]
    timeout: TimeoutTask,
}

// ===== impl Northbound =====

impl Northbound {
    pub(crate) async fn init(config: &Config, db: PickleDb) -> Northbound {
        let db = Arc::new(Mutex::new(db));

        // Create global YANG context.
        yang::create_context();
        let yang_ctx = YANG_CTX.get().unwrap();

        // Create empty running configuration.
        let running_config = Arc::new(DataTree::new(yang_ctx));

        // Start client tasks (e.g. gRPC, gNMI).
        let (rx_clients, clients) = start_clients(config);

        // Start provider tasks (e.g. interfaces, routing, etc).
        let (rx_providers, providers) = start_providers(config, db.clone());

        // Load callbacks keys from data providers and check for missing
        // callbacks.
        let callbacks = load_callbacks(&providers).await;
        validate_callbacks(&callbacks);

        Northbound {
            running_config,
            db,
            callbacks,
            clients,
            providers,
            rx_clients,
            rx_providers,
            confirmed_commit: Default::default(),
        }
    }

    // Main event loop.
    #[instrument(skip_all, "northbound")]
    pub(crate) async fn run(mut self: Northbound, mut signal_rx: Receiver<()>) {
        loop {
            tokio::select! {
                Some(request) = self.rx_clients.recv() => {
                    self.process_client_msg(request).await;
                }
                request = self.rx_providers.recv() => match request {
                    Some(request) => {
                        self.process_provider_msg(request);
                    }
                    // All providers have exited. Teardown is complete.
                    None => return,
                },
                Some(_) = self.confirmed_commit.rx.recv() => {
                    self.process_confirmed_commit_timeout().await;
                }
                _ = signal_rx.recv() => {
                    self.rx_clients.close();
                    self.clients.clear();
                    self.providers.clear();
                },
                else => break,
            }
        }
    }

    // Processes a message received from an external client.
    async fn process_client_msg(&mut self, request: capi::client::Request) {
        trace!(?request, "received client request");

        match request {
            capi::client::Request::Get(request) => {
                let response = self
                    .process_client_get(request.data_type, request.path)
                    .await;
                let _ = request.responder.send(response);
            }
            capi::client::Request::Validate(request) => {
                let response =
                    self.process_client_validate(request.config).await;
                if let Err(error) = &response {
                    warn!(%error, "configuration validation failed");
                }
                let _ = request.responder.send(response);
            }
            capi::client::Request::Commit(request) => {
                let response = self
                    .process_client_commit(
                        request.config,
                        request.comment,
                        request.confirmed_timeout,
                    )
                    .await;
                if let Err(error) = &response {
                    warn!(%error, "commit failed");
                }
                let _ = request.responder.send(response);
            }
            capi::client::Request::Execute(request) => {
                let response = self.process_client_execute(request.data).await;
                if let Err(error) = &response {
                    warn!(%error, "execute failed");
                }
                let _ = request.responder.send(response);
            }
            capi::client::Request::ListTransactions(request) => {
                let response = self.process_client_list_transactions().await;
                let _ = request.responder.send(response);
            }
            capi::client::Request::GetTransaction(request) => {
                let response = self
                    .process_client_get_transaction(request.transaction_id)
                    .await;
                let _ = request.responder.send(response);
            }
        }
    }

    // Processes a `Get` message received from an external client.
    async fn process_client_get(
        &self,
        data_type: capi::DataType,
        path: Option<String>,
    ) -> Result<capi::client::GetResponse> {
        let path = path.as_deref();
        let dtree = match data_type {
            capi::DataType::State => self.get_state(path).await?,
            capi::DataType::Configuration => self.get_configuration(path)?,
            capi::DataType::All => {
                let mut dtree_state = self.get_state(path).await?;
                let dtree_config = self.get_configuration(path)?;
                dtree_state
                    .merge(&dtree_config)
                    .map_err(Error::YangInternal)?;
                dtree_state
            }
        };

        Ok(capi::client::GetResponse { dtree })
    }

    // Processes a `Validate` message received from an external client.
    async fn process_client_validate(
        &mut self,
        candidate: DataTree<'static>,
    ) -> Result<capi::client::ValidateResponse> {
        let candidate = Arc::new(candidate);

        // Validate the candidate configuration.
        self.validate_notify(&candidate)
            .await
            .map_err(Error::TransactionValidation)?;

        Ok(capi::client::ValidateResponse {})
    }

    // Processes a `Commit` message received from an external client.
    async fn process_client_commit(
        &mut self,
        config: capi::CommitConfiguration,
        comment: String,
        confirmed_timeout: u32,
    ) -> Result<capi::client::CommitResponse> {
        // Handle different commit operations.
        let candidate = match config {
            capi::CommitConfiguration::Merge(config) => {
                let mut candidate = self
                    .running_config
                    .duplicate()
                    .map_err(Error::YangInternal)?;
                candidate.merge(&config).map_err(Error::YangInternal)?;
                candidate
            }
            capi::CommitConfiguration::Replace(config) => config,
            capi::CommitConfiguration::Change(diff) => {
                let mut candidate = self
                    .running_config
                    .duplicate()
                    .map_err(Error::YangInternal)?;
                candidate.diff_apply(&diff).map_err(Error::YangInternal)?;
                candidate
            }
        };

        // Create configuration transaction.
        let transaction_id = self
            .create_transaction(candidate, comment, confirmed_timeout)
            .await?;
        Ok(capi::client::CommitResponse { transaction_id })
    }

    // Processes an `Execute` message received from an external client.
    async fn process_client_execute(
        &mut self,
        data: DataTree<'static>,
    ) -> Result<capi::client::ExecuteResponse> {
        let data = self.execute(data).await?;
        Ok(capi::client::ExecuteResponse { data })
    }

    // Processes a `ListTransactions` message received from an external client.
    async fn process_client_list_transactions(
        &mut self,
    ) -> Result<capi::client::ListTransactionsResponse> {
        let db = self.db.lock().unwrap();
        let transactions = db::transaction_get_all(&db);
        Ok(capi::client::ListTransactionsResponse { transactions })
    }

    // Processes a `GetTransaction` message received from an external client.
    async fn process_client_get_transaction(
        &mut self,
        transaction_id: u32,
    ) -> Result<capi::client::GetTransactionResponse> {
        let db = self.db.lock().unwrap();
        let transaction = db::transaction_get(&db, transaction_id)
            .ok_or(Error::TransactionIdNotFound(transaction_id))?;
        Ok(capi::client::GetTransactionResponse {
            dtree: transaction.configuration,
        })
    }

    // Processes a message received from a data provider.
    fn process_provider_msg(&mut self, _request: papi::provider::Notification) {
        // TODO: relay request to the external clients (e.g. YANG notification).
    }

    // Processes a confirmed commit timeout.
    async fn process_confirmed_commit_timeout(&mut self) {
        info!(
            "confirmed commit has timed out, rolling back to previous configuration"
        );

        let comment = "Confirmed commit rollback".to_owned();
        let rollback = self.confirmed_commit.rollback.take().unwrap();
        if let Err(error) = self
            .create_transaction(rollback.configuration, comment, 0)
            .await
        {
            error!(%error, "failed to rollback to previous configuration");
        }
    }

    // Creates a configuration transaction using a two-phase commit protocol. In
    // case of success, the transaction ID is returned.
    //
    // A configuration transaction might fail if the candidate configuration
    // fails to be validated, or if one or more resources fail to be allocated.
    async fn create_transaction(
        &mut self,
        candidate: DataTree<'static>,
        comment: String,
        confirmed_timeout: u32,
    ) -> Result<u32> {
        let candidate = Arc::new(candidate);

        // Validate the candidate configuration.
        self.validate_notify(&candidate)
            .await
            .map_err(Error::TransactionValidation)?;

        // Compute diff between the running config and the candidate config.
        let diff = self
            .running_config
            .diff(&candidate, DataDiffFlags::DEFAULTS)
            .map_err(Error::YangInternal)?;

        // Check if the configuration has changed.
        if diff.iter().next().is_none() {
            // Check if this a confirmation commit.
            if self.confirmed_commit.rollback.take().is_some() {
                debug!("commit confirmation accepted");
            }

            return Ok(0);
        }

        // Get list of configuration changes.
        let changes = northbound::configuration::changes_from_diff(&diff);

        // Log configuration transaction.
        let changes_json = diff
            .print_string(DataFormat::JSON, DataPrinterFlags::WITH_SIBLINGS)
            .unwrap();
        debug!(%confirmed_timeout, changes = %changes_json, "configuration transaction");

        // Phase 1: validate configuration and attempt to prepare resources for
        // the transaction.
        match self
            .commit_phase_notify(CommitPhase::Prepare, &candidate, &changes)
            .await
        {
            Ok(_) => {
                // Phase 2: apply the configuration changes.
                let _ = self
                    .commit_phase_notify(
                        CommitPhase::Apply,
                        &candidate,
                        &changes,
                    )
                    .await;

                // Start confirmed commit timeout if necessary.
                if confirmed_timeout > 0 {
                    let rollback_config =
                        (*self.running_config).duplicate().unwrap();
                    self.confirmed_commit
                        .start(rollback_config, confirmed_timeout);
                }

                // Update the running configuration.
                let running_config =
                    Arc::get_mut(&mut self.running_config).unwrap();
                running_config
                    .diff_apply(&diff)
                    .map_err(Error::YangInternal)?;
                running_config
                    .validate(DataValidationFlags::NO_STATE)
                    .map_err(Error::YangInternal)?;

                // Create transaction structure.
                let candidate = Arc::try_unwrap(candidate).unwrap();
                let mut transaction =
                    Transaction::new(Utc::now(), comment, candidate);

                // Record transaction.
                let mut db = self.db.lock().unwrap();
                db::transaction_record(&mut db, &mut transaction);

                Ok(transaction.id)
            }
            Err(error) => {
                // Phase 2: abort the configuration changes.
                let _ = self
                    .commit_phase_notify(
                        CommitPhase::Abort,
                        &candidate,
                        &changes,
                    )
                    .await;

                Err(Error::TransactionPreparation(error))
            }
        }
    }

    // Request all data providers to validate the candidate configuration.
    async fn validate_notify(
        &mut self,
        candidate: &Arc<DataTree<'static>>,
    ) -> std::result::Result<(), northbound::error::Error> {
        let mut handles = Vec::new();

        // Spawn one task per data provider.
        for daemon_tx in self.providers.iter() {
            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request = papi::daemon::Request::Validate(
                papi::daemon::ValidateRequest {
                    config: candidate.clone(),
                    responder: Some(responder_tx),
                },
            );

            // Spawn task to send the request and receive the response.
            let daemon_tx = daemon_tx.clone();
            let handle = tokio::spawn(async move {
                daemon_tx.send(request).await.unwrap();
                responder_rx.await.unwrap()
            });
            handles.push(handle);
        }
        // Wait for all tasks to complete.
        for handle in handles {
            handle.await.unwrap()?;
        }

        Ok(())
    }

    // Notifies all data providers of the configuration changes associated to an
    // on-going transaction.
    async fn commit_phase_notify(
        &mut self,
        phase: CommitPhase,
        candidate: &Arc<DataTree<'static>>,
        changes: &[ConfigChange],
    ) -> std::result::Result<(), northbound::error::Error> {
        // Spawn one task per data provider.
        for daemon_tx in self.providers.iter() {
            // Batch all changes that should be sent to this provider.
            let changes = changes
                .iter()
                .filter(|(cb_key, _)| {
                    if let Some(tx) = self.callbacks.get(cb_key) {
                        tx.upgrade().unwrap().same_channel(daemon_tx)
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();

            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Commit(papi::daemon::CommitRequest {
                    phase,
                    old_config: self.running_config.clone(),
                    new_config: candidate.clone(),
                    changes,
                    responder: Some(responder_tx),
                });

            // Spawn task to send the request and receive the response.
            let daemon_tx = daemon_tx.clone();
            let handle = tokio::spawn(async move {
                daemon_tx.send(request).await.unwrap();
                responder_rx.await.unwrap()
            });

            // Wait for task to complete.
            handle.await.unwrap()?;
        }

        Ok(())
    }

    // Gets a full or partial copy of the running configuration.
    fn get_configuration(
        &self,
        path: Option<&str>,
    ) -> Result<DataTree<'static>> {
        match path {
            Some(path) => {
                let yang_ctx = YANG_CTX.get().unwrap();
                let mut dtree = DataTree::new(yang_ctx);
                for dnode in self
                    .running_config
                    .find_xpath(path)
                    .map_err(Error::YangInvalidPath)?
                {
                    let subtree =
                        dnode.duplicate(true).map_err(Error::YangInternal)?;
                    dtree.merge(&subtree).map_err(Error::YangInternal)?;
                }
                Ok(dtree)
            }
            None => {
                self.running_config.duplicate().map_err(Error::YangInternal)
            }
        }
    }

    // Gets dynamically generated operational data for the provided path. The
    // request might span multiple data providers.
    async fn get_state(&self, path: Option<&str>) -> Result<DataTree<'static>> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let mut dtree = DataTree::new(yang_ctx);

        for daemon_tx in self.providers.iter() {
            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Get(papi::daemon::GetRequest {
                    path: path.map(String::from),
                    responder: Some(responder_tx),
                });
            daemon_tx.send(request).await.unwrap();

            // Receive response.
            let response = responder_rx.await.unwrap().map_err(Error::Get)?;

            // Combine all responses into a single data tree.
            dtree.merge(&response.data).map_err(Error::YangInternal)?;
        }

        Ok(dtree)
    }

    // Invoke a YANG RPC or Action.
    async fn execute(
        &self,
        data: DataTree<'static>,
    ) -> Result<DataTree<'static>> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let mut dtree = DataTree::new(yang_ctx);

        // Log RPC invocation with full JSON-encoded request data.
        let data_json = data
            .print_string(DataFormat::JSON, DataPrinterFlags::WITH_SIBLINGS)
            .unwrap();
        debug!(data = %data_json, "RPC invocation received");

        for daemon_tx in self.providers.iter() {
            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Rpc(papi::daemon::RpcRequest {
                    data: data.duplicate().map_err(Error::YangInternal)?,
                    responder: Some(responder_tx),
                });
            daemon_tx.send(request).await.unwrap();

            // Receive response.
            let response = responder_rx.await.unwrap().unwrap();

            // Combine all responses into a single data tree.
            dtree.merge(&response.data).map_err(Error::YangInternal)?;
        }

        Ok(dtree)
    }
}

// ===== impl ConfirmedCommit =====

impl ConfirmedCommit {
    fn start(&mut self, configuration: DataTree<'static>, timeout: u32) {
        debug!(%timeout, "starting confirmed commit timeout");

        let timeout = self.timeout_task(timeout);

        self.rollback = Some(Rollback {
            configuration,
            timeout,
        });
    }

    fn timeout_task(&self, timeout: u32) -> TimeoutTask {
        let tx = self.tx.clone();
        let timeout = Duration::from_secs(timeout as u64 * 60);
        TimeoutTask::new(timeout, move || async move {
            let _ = tx.send(()).await;
        })
    }
}

impl Default for ConfirmedCommit {
    fn default() -> ConfirmedCommit {
        let (tx, rx) = mpsc::channel(4);

        ConfirmedCommit {
            tx,
            rx,
            rollback: None,
        }
    }
}

// ===== helper functions =====

// Starts base data providers.
#[allow(unused_mut, unused_variables)]
fn start_providers(
    config: &Config,
    db: Database,
) -> (NbProviderReceiver, Vec<NbDaemonSender>) {
    let mut providers = Vec::new();
    let (provider_tx, provider_rx) = mpsc::unbounded_channel();
    let (
        (
            ibus_tx_routing,
            ibus_tx_interface,
            ibus_tx_system,
            ibus_tx_keychain,
            ibus_tx_policy,
        ),
        ibus_rx,
    ) = ibus::ibus_channels();
    let shared = InstanceShared {
        db: Some(db),
        event_recorder_config: Some(config.event_recorder.clone()),
        ..Default::default()
    };

    // Start holo-interface.
    #[cfg(feature = "interface")]
    {
        let daemon_tx = holo_interface::start(
            provider_tx.clone(),
            ibus_tx_interface,
            ibus_rx.interface,
            shared.clone(),
        );
        providers.push(daemon_tx);
    }

    // Start holo-keychain.
    #[cfg(feature = "keychain")]
    {
        let daemon_tx = holo_keychain::start(
            provider_tx.clone(),
            ibus_tx_keychain,
            ibus_rx.keychain,
        );
        providers.push(daemon_tx);
    }

    // Start holo-policy.
    #[cfg(feature = "policy")]
    {
        let daemon_tx = holo_policy::start(
            provider_tx.clone(),
            ibus_tx_policy,
            ibus_rx.policy,
        );
        providers.push(daemon_tx);
    }

    // Start holo-system.
    #[cfg(feature = "system")]
    {
        let daemon_tx = holo_system::start(
            provider_tx.clone(),
            ibus_tx_system,
            ibus_rx.system,
        );
        providers.push(daemon_tx);
    }

    // Start holo-routing.
    #[cfg(feature = "routing")]
    {
        let daemon_tx = holo_routing::start(
            provider_tx,
            ibus_tx_routing,
            ibus_rx.routing,
            shared,
        );
        providers.push(daemon_tx);
    }

    (provider_rx, providers)
}

// Starts external clients.
fn start_clients(
    config: &Config,
) -> (Receiver<capi::client::Request>, Vec<Task<()>>) {
    let mut clients = Vec::new();
    let (client_tx, daemon_rx) = mpsc::channel(4);

    // Spawn gRPC task.
    let grpc_config = &config.plugins.grpc;
    if grpc_config.enabled {
        let client = grpc::start(grpc_config, client_tx.clone());
        clients.push(client);
    }

    // Spawn gNMI task.
    let gnmi_config = &config.plugins.gnmi;
    if gnmi_config.enabled {
        let client = gnmi::start(gnmi_config, client_tx);
        clients.push(client);
    }

    (daemon_rx, clients)
}

// Loads all YANG callback keys from the data providers.
async fn load_callbacks(
    providers: &[NbDaemonSender],
) -> BTreeMap<CallbackKey, WeakSender<papi::daemon::Request>> {
    let mut callbacks = BTreeMap::new();

    for provider_tx in providers.iter() {
        // Prepare request.
        let (responder_tx, responder_rx) = oneshot::channel();
        let request = papi::daemon::Request::GetCallbacks(
            papi::daemon::GetCallbacksRequest {
                responder: Some(responder_tx),
            },
        );
        provider_tx.send(request).await.unwrap();

        // Receive response.
        let provider_response = responder_rx.await.unwrap();

        // Validate and store callback key.
        for cb_key in provider_response.callbacks {
            validate_callback(&cb_key);
            callbacks.insert(cb_key, provider_tx.downgrade());
        }
    }

    callbacks
}

// Checks for missing YANG callbacks.
fn validate_callbacks(
    callbacks: &BTreeMap<CallbackKey, WeakSender<papi::daemon::Request>>,
) {
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut errors: usize = 0;

    for snode in yang_ctx
        .traverse()
        .filter(|snode| snode.module().is_implemented())
        .filter(|snode| snode.module().name() != "ietf-yang-schema-mount")
        .filter(|snode| snode.is_status_current())
    {
        for operation in [
            CallbackOp::Create,
            CallbackOp::Modify,
            CallbackOp::Delete,
            CallbackOp::Lookup,
            CallbackOp::Rpc,
            CallbackOp::GetIterate,
            CallbackOp::GetObject,
        ] {
            let path = snode.data_path();
            if operation.is_valid(&snode) {
                let cb_key = CallbackKey::new(path.clone(), operation);
                if callbacks.get(&cb_key).is_none() {
                    error!(?operation, path = %cb_key.path, "missing callback");
                    errors += 1;
                }
            }
        }
    }

    if errors > 0 {
        error!(%errors, "failed to validate northbound callbacks");
        std::process::exit(1);
    }
}

// Checks whether the callback key is valid.
fn validate_callback(callback: &CallbackKey) {
    let yang_ctx = YANG_CTX.get().unwrap();

    if let Ok(snode) = yang_ctx.find_path(&callback.path)
        && !callback.operation.is_valid(&snode)
    {
        error!(xpath = %callback.path, operation = ?callback.operation,
            "invalid callback",
        );
        std::process::exit(1);
    }
}
