//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use holo_utils::yang::SchemaNodeExt;
use holo_yang::YangPath;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use yang3::data::{Data, DataDiff, DataDiffOp, DataNodeRef, DataTree};
use yang3::schema::SchemaNodeKind;

use crate::debug::Debug;
use crate::error::Error;
use crate::{CallbackKey, CallbackOp, NbDaemonSender, ProviderBase, api};

// A generic struct representing an inheritable configuration value.
//
// It contains two fields: `explicit`, which is an optional explicit value, and
// `resolved`, the resolved configuration value (inherited or explicit).
#[derive(Clone, Debug)]
pub struct InheritableConfig<T> {
    pub explicit: Option<T>,
    pub resolved: T,
}

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
    pub old_config: &'a Arc<DataTree<'static>>,
    pub new_config: &'a Arc<DataTree<'static>>,
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

pub trait Provider: ProviderBase {
    type ListEntry: Default;
    type Event;
    type Resource: Send;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        None
    }

    fn callbacks() -> &'static Callbacks<Self>;

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        None
    }

    fn relay_validation(&self) -> Vec<NbDaemonSender> {
        vec![]
    }

    fn relay_changes(
        &self,
        _changes: ConfigChanges,
    ) -> Vec<(ConfigChanges, NbDaemonSender)> {
        vec![]
    }

    fn process_event(&mut self, _event: Self::Event) {}
}

// ===== impl InheritableConfig =====

impl<T> InheritableConfig<T> {
    pub fn new(resolved: T) -> Self {
        InheritableConfig {
            explicit: None,
            resolved,
        }
    }
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

fn process_commit_local<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: &Arc<DataTree<'static>>,
    new_config: &Arc<DataTree<'static>>,
    changes: &ConfigChanges,
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

    let callbacks = P::callbacks();
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
        provider.process_event(event);
    }

    Ok(())
}

fn process_commit_relayed<P>(
    provider: &P,
    phase: CommitPhase,
    old_config: &Arc<DataTree<'static>>,
    new_config: &Arc<DataTree<'static>>,
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
            .blocking_send(api::daemon::Request::Commit(relayed_commit))
            .unwrap();

        // Receive response.
        let _ = responder_rx.blocking_recv().unwrap()?;
    }

    Ok(())
}

fn lookup_list_entry<P>(
    provider: &mut P,
    phase: CommitPhase,
    operation: CallbackOp,
    dnode: &DataNodeRef<'_>,
) -> P::ListEntry
where
    P: Provider,
{
    let callbacks = P::callbacks();
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
        let path = dnode.schema().data_path();
        if let Some(cb) = callbacks.get_lookup(path) {
            list_entry = (*cb)(provider, list_entry, dnode);
        }
    }

    list_entry
}

fn validate_configuration<P>(
    provider: &P,
    config: &Arc<DataTree<'static>>,
) -> Result<(), Error>
where
    P: Provider,
{
    if let Some(callbacks) = P::validation_callbacks() {
        for dnode in config
            .find_path(&provider.top_level_node())
            .iter()
            .flat_map(|dnode| dnode.traverse())
        {
            if let Some(cb) = callbacks.get(&dnode.schema().data_path()) {
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

pub fn changes_from_diff(diff: &DataDiff<'static>) -> ConfigChanges {
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

                    let cb_key =
                        CallbackKey::new(dnode.schema().data_path(), operation);
                    changes.push((cb_key, dnode.path().to_owned()));
                }
            }
            DataDiffOp::Delete => {
                let snode = dnode.schema();
                if CallbackOp::Delete.is_valid(&snode) {
                    let cb_key = CallbackKey::new(
                        dnode.schema().data_path(),
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
                        dnode.schema().data_path(),
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
                    dnode.schema().data_path(),
                    CallbackOp::Modify,
                );
                changes.push((cb_key, dnode.path().to_owned()));
            }
        }
    }

    changes
}

pub(crate) fn process_validate<P>(
    provider: &P,
    config: Arc<DataTree<'static>>,
) -> Result<api::daemon::ValidateResponse, Error>
where
    P: Provider,
{
    // Validate local subtree.
    validate_configuration::<P>(provider, &config)?;

    // Validate nested subtrees.
    for nb_tx in provider.relay_validation() {
        // Send request to child task.
        let (responder_tx, responder_rx) = oneshot::channel();
        let relayed_req = api::daemon::ValidateRequest {
            config: config.clone(),
            responder: Some(responder_tx),
        };
        nb_tx
            .blocking_send(api::daemon::Request::Validate(relayed_req))
            .unwrap();

        // Receive response.
        let _ = responder_rx.blocking_recv().unwrap()?;
    }

    Ok(api::daemon::ValidateResponse {})
}

pub(crate) fn process_commit<P>(
    provider: &mut P,
    phase: CommitPhase,
    old_config: Arc<DataTree<'static>>,
    new_config: Arc<DataTree<'static>>,
    mut changes: ConfigChanges,
    resources: &mut Vec<Option<P::Resource>>,
) -> Result<api::daemon::CommitResponse, Error>
where
    P: Provider,
{
    // Move to a separate vector the changes that need to be relayed.
    let callbacks = P::callbacks();
    let relayed_changes = changes
        .extract_if(.., |(cb_key, _)| !callbacks.0.contains_key(cb_key))
        .collect();

    // Process local changes.
    process_commit_local(
        provider,
        phase,
        &old_config,
        &new_config,
        &changes,
        resources,
    )?;

    // Process relayed changes.
    process_commit_relayed(
        provider,
        phase,
        &old_config,
        &new_config,
        relayed_changes,
    )?;

    Ok(api::daemon::CommitResponse {})
}
