//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use holo_yang::YangPath;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use yang2::data::{Data, DataDiff, DataDiffOp, DataNodeRef, DataTree};
use yang2::schema::{SchemaNodeKind, SchemaPathFormat};

use crate::debug::Debug;
use crate::error::Error;
use crate::{api, CallbackKey, CallbackOp, NbDaemonSender, ProviderBase};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum CommitPhase {
    Prepare,
    Abort,
    Apply,
}

//
// Commit callbacks.
//

pub struct Callbacks<P: Provider>(pub HashMap<CallbackKey, CallbacksNode<P>>);

pub struct CallbacksNode<P: Provider> {
    pub lookup: Option<CallbackLookup<P>>,
    pub prepare: Option<CallbackPhaseOne<P>>,
    pub abort: Option<CallbackPhaseTwo<P>>,
    pub apply: Option<CallbackPhaseTwo<P>>,
}

pub struct CallbacksBuilder<P: Provider> {
    path: Option<YangPath>,
    callbacks: Callbacks<P>,
}

#[derive(Debug)]
pub struct CallbackArgs<'a, P: Provider> {
    pub event_queue: &'a mut BTreeSet<P::Event>,
    pub list_entry: P::ListEntry,
    pub resource: &'a mut Option<P::Resource>,
    pub old_config: &'a Arc<DataTree>,
    pub new_config: &'a Arc<DataTree>,
    pub dnode: DataNodeRef<'a>,
}

//
// Validation callbacks.
//

#[derive(Default)]
pub struct ValidationCallbacks(pub HashMap<String, ValidationCallback>);

#[derive(Default)]
pub struct ValidationCallbacksBuilder {
    path: Option<YangPath>,
    callbacks: ValidationCallbacks,
}

#[derive(Debug)]
pub struct ValidationCallbackArgs<'a> {
    pub dnode: DataNodeRef<'a>,
}

//
// Useful type definition(s).
//

pub type ConfigChange = (CallbackKey, String);
pub type ConfigChanges = Vec<ConfigChange>;

pub type CallbackLookup<P: Provider> = for<'a> fn(
    &'a mut P,
    list_entry: P::ListEntry,
    dnode: DataNodeRef<'a>,
) -> P::ListEntry;

pub type CallbackPhaseOne<P> =
    for<'a> fn(&'a mut P, CallbackArgs<'a, P>) -> Result<(), String>;

pub type CallbackPhaseTwo<P> = for<'a> fn(&'a mut P, CallbackArgs<'a, P>);

pub type ValidationCallback =
    fn(ValidationCallbackArgs<'_>) -> Result<(), String>;

//
// Provider northbound.
//

#[async_trait]
pub trait Provider: ProviderBase {
    type ListEntry: Send + Default;
    type Event: std::fmt::Debug + Eq + Ord + PartialEq + PartialOrd + Send;
    type Resource: Send;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        None
    }

    fn callbacks() -> Option<&'static Callbacks<Self>> {
        None
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        None
    }

    fn relay_changes(
        &self,
        _changes: ConfigChanges,
    ) -> Vec<(ConfigChanges, NbDaemonSender)> {
        vec![]
    }

    async fn process_event(&mut self, _event: Self::Event) {}
}

// ===== impl Callbacks =====

impl<P> Callbacks<P>
where
    P: Provider,
{
    fn get_lookup(&self, path: String) -> Option<&CallbackLookup<P>> {
        let key = CallbackKey::new(path, CallbackOp::Lookup);
        self.0.get(&key).and_then(|cb_node| cb_node.lookup.as_ref())
    }

    fn get_prepare(&self, key: &CallbackKey) -> Option<&CallbackPhaseOne<P>> {
        self.0.get(key).unwrap().prepare.as_ref()
    }

    fn get_abort(&self, key: &CallbackKey) -> Option<&CallbackPhaseTwo<P>> {
        self.0.get(key).unwrap().abort.as_ref()
    }

    fn get_apply(&self, key: &CallbackKey) -> Option<&CallbackPhaseTwo<P>> {
        self.0.get(key).unwrap().apply.as_ref()
    }

    pub fn keys(&self) -> Vec<CallbackKey> {
        self.0.keys().cloned().collect()
    }
}

impl<P> std::fmt::Debug for Callbacks<P>
where
    P: Provider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Callbacks({:?})", self.0.keys())
    }
}

impl<P> Default for Callbacks<P>
where
    P: Provider,
{
    fn default() -> Self {
        Callbacks(HashMap::new())
    }
}

// ===== impl CallbacksNode =====

impl<P> Default for CallbacksNode<P>
where
    P: Provider,
{
    fn default() -> Self {
        CallbacksNode {
            lookup: None,
            prepare: None,
            abort: None,
            apply: None,
        }
    }
}

// ===== impl CallbacksBuilder =====

impl<P> CallbacksBuilder<P>
where
    P: Provider,
{
    pub fn new(callbacks: Callbacks<P>) -> Self {
        CallbacksBuilder {
            path: None,
            callbacks,
        }
    }

    #[must_use]
    pub fn path(mut self, path: YangPath) -> Self {
        self.path = Some(path);
        self
    }

    #[must_use]
    fn load_prepare(
        mut self,
        operation: CallbackOp,
        cb: CallbackPhaseOne<P>,
    ) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, operation);
        self.callbacks.0.entry(key).or_default().prepare = Some(cb);
        self
    }

    #[must_use]
    fn load_abort(
        mut self,
        operation: CallbackOp,
        cb: CallbackPhaseTwo<P>,
    ) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, operation);
        self.callbacks.0.entry(key).or_default().abort = Some(cb);
        self
    }

    #[must_use]
    fn load_apply(
        mut self,
        operation: CallbackOp,
        cb: CallbackPhaseTwo<P>,
    ) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, operation);
        self.callbacks.0.entry(key).or_default().apply = Some(cb);
        self
    }

    #[must_use]
    pub fn lookup(mut self, cb: CallbackLookup<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::Lookup);
        self.callbacks.0.entry(key).or_default().lookup = Some(cb);
        self
    }

    #[must_use]
    pub fn create_prepare(self, cb: CallbackPhaseOne<P>) -> Self {
        self.load_prepare(CallbackOp::Create, cb)
    }

    #[must_use]
    pub fn create_abort(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_abort(CallbackOp::Create, cb)
    }

    #[must_use]
    pub fn create_apply(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_apply(CallbackOp::Create, cb)
    }

    #[must_use]
    pub fn delete_prepare(self, cb: CallbackPhaseOne<P>) -> Self {
        self.load_prepare(CallbackOp::Delete, cb)
    }

    #[must_use]
    pub fn delete_abort(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_abort(CallbackOp::Delete, cb)
    }

    #[must_use]
    pub fn delete_apply(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_apply(CallbackOp::Delete, cb)
    }

    #[must_use]
    pub fn modify_prepare(self, cb: CallbackPhaseOne<P>) -> Self {
        self.load_prepare(CallbackOp::Modify, cb)
    }

    #[must_use]
    pub fn modify_abort(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_abort(CallbackOp::Modify, cb)
    }

    #[must_use]
    pub fn modify_apply(self, cb: CallbackPhaseTwo<P>) -> Self {
        self.load_apply(CallbackOp::Modify, cb)
    }

    #[must_use]
    pub fn build(self) -> Callbacks<P> {
        self.callbacks
    }
}

impl<P> Default for CallbacksBuilder<P>
where
    P: Provider,
{
    fn default() -> Self {
        CallbacksBuilder {
            path: None,
            callbacks: Callbacks::default(),
        }
    }
}

// ===== impl ValidationCallbacks =====

impl ValidationCallbacks {
    pub fn load(&mut self, path: YangPath, cb: ValidationCallback) {
        let path = path.to_string();
        self.0.insert(path, cb);
    }

    fn get(&self, key: &str) -> Option<&ValidationCallback> {
        self.0.get(key)
    }

    pub fn keys(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }
}

impl std::fmt::Debug for ValidationCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidationCallbacks({:?})", self.0.keys())
    }
}

// ===== impl ValidationCallbacksBuilder =====

impl ValidationCallbacksBuilder {
    pub fn new(callbacks: ValidationCallbacks) -> Self {
        ValidationCallbacksBuilder {
            path: None,
            callbacks,
        }
    }

    #[must_use]
    pub fn path(mut self, path: YangPath) -> Self {
        self.path = Some(path);
        self
    }

    #[must_use]
    pub fn validate(mut self, cb: ValidationCallback) -> Self {
        let path = self.path.unwrap().to_string();
        self.callbacks.0.insert(path, cb);
        self
    }

    #[must_use]
    pub fn build(self) -> ValidationCallbacks {
        self.callbacks
    }
}

// ===== helper functions =====

async fn process_commit_local<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: &Arc<DataTree>,
    new_config: &Arc<DataTree>,
    changes: &mut ConfigChanges,
    resources: &mut Vec<Option<P::Resource>>,
) -> Result<(), Error>
where
    P: Provider,
{
    let mut event_queue = BTreeSet::new();

    // Resize the resources vector to match the number of configuration changes.
    if phase == CommitPhase::Prepare {
        resources.resize_with(changes.len(), Default::default);
    }

    let callbacks = P::callbacks().unwrap();
    for ((cb_key, data_path), resource) in changes.iter().zip(resources) {
        Debug::ConfigurationCallback(phase, cb_key.operation, &cb_key.path)
            .log();

        // Get data node that is being created, modified or deleted.
        let dnode_config = match cb_key.operation {
            CallbackOp::Create | CallbackOp::Modify => new_config,
            CallbackOp::Delete => old_config,
            _ => unreachable!(),
        };
        let dnode = dnode_config.find_path(data_path).unwrap();

        // Fill-in callback arguments.
        let mut args = CallbackArgs {
            event_queue: &mut event_queue,
            list_entry: P::ListEntry::default(),
            resource,
            old_config,
            new_config,
            dnode,
        };

        // Lookup reference(s) associated to the list entry.
        if phase != CommitPhase::Prepare {
            args.list_entry = lookup_list_entry(
                provider,
                phase,
                cb_key.operation,
                &callbacks,
                &args.dnode,
            );
        }

        match phase {
            CommitPhase::Prepare => {
                // Invoke 1st-phase commit callback.
                if let Some(cb) = callbacks.get_prepare(cb_key) {
                    (*cb)(provider, args).map_err(Error::CfgCallback)?;
                }
            }
            CommitPhase::Abort => {
                // Invoke 2nd-phase commit callback.
                if let Some(cb) = callbacks.get_abort(cb_key) {
                    (*cb)(provider, args);
                }
            }
            CommitPhase::Apply => {
                // Invoke 2nd-phase commit callback.
                if let Some(cb) = callbacks.get_apply(cb_key) {
                    (*cb)(provider, args);
                }
            }
        }
    }

    // Process event queue once the running configuration is fully updated.
    for event in event_queue {
        provider.process_event(event).await;
    }

    Ok(())
}

async fn process_commit_relayed<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: &Arc<DataTree>,
    new_config: &Arc<DataTree>,
    relayed_changes: ConfigChanges,
) -> Result<(), Error>
where
    P: Provider,
{
    for (changes, nb_tx) in provider.relay_changes(relayed_changes) {
        // Send request to child task.
        let (responder_tx, responder_rx) = oneshot::channel();
        let relayed_commit = api::daemon::CommitRequest {
            phase,
            changes,
            old_config: old_config.clone(),
            new_config: new_config.clone(),
            responder: Some(responder_tx),
        };
        nb_tx
            .send(api::daemon::Request::Commit(relayed_commit))
            .await
            .unwrap();

        // Receive response.
        let _ = responder_rx.await.unwrap()?;
    }

    Ok(())
}

fn lookup_list_entry<P>(
    provider: &mut P,
    phase: CommitPhase,
    operation: CallbackOp,
    callbacks: &Callbacks<P>,
    dnode: &DataNodeRef<'_>,
) -> P::ListEntry
where
    P: Provider,
{
    let ancestors =
        if phase == CommitPhase::Apply && operation == CallbackOp::Create {
            dnode.ancestors()
        } else {
            dnode.inclusive_ancestors()
        };

    let mut list_entry = P::ListEntry::default();
    for dnode in ancestors
        .filter(|dnode| dnode.schema().kind() == SchemaNodeKind::List)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let path = dnode.schema().path(SchemaPathFormat::DATA);
        if let Some(cb) = callbacks.get_lookup(path) {
            list_entry = (*cb)(provider, list_entry, dnode);
        }
    }

    list_entry
}

async fn validate_configuration<P>(
    provider: &P,
    config: &Arc<DataTree>,
) -> Result<(), Error>
where
    P: Provider,
{
    if let Some(callbacks) = P::validation_callbacks() {
        for dnode in config
            .find_path(&provider.top_level_node())
            .unwrap()
            .traverse()
        {
            if let Some(cb) =
                callbacks.get(&dnode.schema().path(SchemaPathFormat::DATA))
            {
                let path = dnode.path();
                Debug::ValidationCallback(&path).log();

                // Invoke validation callback.
                let args = ValidationCallbackArgs { dnode };
                (*cb)(args).map_err(Error::ValidationCallback)?;
            }
        }
    }

    Ok(())
}

// ===== global functions =====

pub fn changes_from_diff(diff: &DataDiff) -> ConfigChanges {
    let mut changes = vec![];

    for (op, dnode) in diff.iter() {
        match op {
            DataDiffOp::Create => {
                for dnode in dnode.traverse() {
                    if dnode.is_default() {
                        continue;
                    }

                    let snode = dnode.schema();
                    let operation = if CallbackOp::Create.is_valid(&snode) {
                        CallbackOp::Create
                    } else if CallbackOp::Modify.is_valid(&snode) {
                        CallbackOp::Modify
                    } else {
                        continue;
                    };

                    let cb_key = CallbackKey::new(
                        dnode.schema().path(SchemaPathFormat::DATA),
                        operation,
                    );
                    changes.push((cb_key, dnode.path().to_owned()));
                }
            }
            DataDiffOp::Delete => {
                let snode = dnode.schema();
                if CallbackOp::Delete.is_valid(&snode) {
                    let cb_key = CallbackKey::new(
                        dnode.schema().path(SchemaPathFormat::DATA),
                        CallbackOp::Delete,
                    );
                    changes.push((cb_key, dnode.path().to_owned()));
                    continue;
                }

                // NP-containers.
                for dnode in dnode.traverse() {
                    let snode = dnode.schema();
                    if !CallbackOp::Delete.is_valid(&snode) {
                        continue;
                    }

                    let cb_key = CallbackKey::new(
                        dnode.schema().path(SchemaPathFormat::DATA),
                        CallbackOp::Delete,
                    );
                    changes.push((cb_key, dnode.path().to_owned()));
                }
            }
            DataDiffOp::Replace => {
                let snode = dnode.schema();
                if !CallbackOp::Modify.is_valid(&snode) {
                    continue;
                }

                let cb_key = CallbackKey::new(
                    dnode.schema().path(SchemaPathFormat::DATA),
                    CallbackOp::Modify,
                );
                changes.push((cb_key, dnode.path().to_owned()));
            }
        }
    }

    changes
}

pub(crate) async fn process_commit<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: Arc<DataTree>,
    new_config: Arc<DataTree>,
    mut changes: ConfigChanges,
    resources: &mut Vec<Option<P::Resource>>,
) -> Result<api::daemon::CommitResponse, Error>
where
    P: Provider,
{
    // Perform code-level validation before the preparation phase.
    if phase == CommitPhase::Prepare {
        validate_configuration::<P>(provider, &new_config).await?;
    }

    // Move to a separate vector the changes that need to be relayed.
    let callbacks = P::callbacks().unwrap();
    let relayed_changes = changes
        .drain_filter(|(cb_key, _)| callbacks.0.get(cb_key).is_none())
        .collect();

    // Process local changes.
    process_commit_local(
        provider,
        phase,
        &old_config,
        &new_config,
        &mut changes,
        resources,
    )
    .await?;

    // Process relayed changes.
    process_commit_relayed(
        provider,
        phase,
        &old_config,
        &new_config,
        relayed_changes,
    )
    .await?;

    Ok(api::daemon::CommitResponse {})
}
