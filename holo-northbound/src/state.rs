//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::fmt::Write;

use holo_utils::yang::SchemaNodeExt;
use holo_yang::{YANG_CTX, YangObject, YangPath};
use tokio::sync::oneshot;
use yang3::data::{DataNodeRef, DataTree};
use yang3::schema::{SchemaNode, SchemaNodeKind};

use crate::error::Error;
use crate::{CallbackKey, CallbackOp, NbDaemonSender, ProviderBase, api};

//
// State callbacks.
//

pub struct Callbacks<P: Provider>(HashMap<CallbackKey, CallbacksNode<P>>);

pub struct CallbacksNode<P: Provider> {
    get_iterate: Option<GetIterateCb<P>>,
    get_object: Option<GetObjectCb<P>>,
}

pub struct CallbacksBuilder<P: Provider> {
    path: Option<YangPath>,
    callbacks: Callbacks<P>,
}

//
// GetIterate callback.
//

pub type GetIterateCb<P: Provider> = for<'a, 'b> fn(
    &'a P,
    GetIterateArgs<'a, 'b, P>,
) -> Option<
    Box<dyn Iterator<Item = P::ListEntry<'a>> + 'b>,
>;

#[derive(Debug)]
pub struct GetIterateArgs<'a, 'b, P: Provider> {
    pub parent_list_entry: &'b P::ListEntry<'a>,
    // TODO: starting point
}

//
// GetObject callback.
//

pub type GetObjectCb<P: Provider> =
    for<'a, 'b> fn(&'a P, GetObjectArgs<'a, 'b, P>) -> Box<dyn YangObject + 'a>;

#[derive(Debug)]
pub struct GetObjectArgs<'a, 'b, P: Provider> {
    pub list_entry: &'b P::ListEntry<'a>,
}

//
// List entry trait.
//

pub trait ListEntryKind: std::fmt::Debug + Default {
    // Return the task associated with the child node of this list entry,
    // identified by its corresponding module name.
    fn child_task(&self, _module_name: &str) -> Option<NbDaemonSender> {
        None
    }
}

// Type aliases.
type GetReceiver = oneshot::Receiver<Result<api::daemon::GetResponse, Error>>;

//
// Provider northbound.
//

pub trait Provider: ProviderBase {
    type ListEntry<'a>: ListEntryKind;

    fn callbacks() -> &'static Callbacks<Self>;

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        None
    }
}

// ===== impl Callbacks =====

impl<P> Callbacks<P>
where
    P: Provider,
{
    fn get_iterate(&self, key: &CallbackKey) -> Option<&GetIterateCb<P>> {
        let node = self.0.get(key)?;

        node.get_iterate.as_ref()
    }

    fn get_object(&self, key: &CallbackKey) -> Option<&GetObjectCb<P>> {
        let node = self.0.get(key)?;

        node.get_object.as_ref()
    }

    pub fn keys(&self) -> Vec<CallbackKey> {
        self.0.keys().cloned().collect()
    }

    pub fn extend(&mut self, callbacks: Callbacks<P>) {
        self.0.extend(callbacks.0);
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
            get_iterate: None,
            get_object: None,
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
    pub fn get_iterate(mut self, cb: GetIterateCb<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::GetIterate);
        let node = self.callbacks.0.entry(key).or_default();
        node.get_iterate = Some(cb);
        self
    }

    #[must_use]
    pub fn get_object(mut self, cb: GetObjectCb<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::GetObject);
        let node = self.callbacks.0.entry(key).or_default();
        node.get_object = Some(cb);
        self
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

// ===== helper functions =====

fn iterate_node<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
    first: bool,
) -> Result<(), Error>
where
    P: Provider,
{
    match snode.kind() {
        SchemaNodeKind::List => {
            iterate_list(provider, dnode, snode, list_entry, relay_list)?;
        }
        SchemaNodeKind::Container => {
            iterate_container(
                provider, dnode, snode, list_entry, relay_list, first,
            )?;
        }
        SchemaNodeKind::Choice | SchemaNodeKind::Case => {
            iterate_children(provider, dnode, snode, list_entry, relay_list)?;
        }
        _ => (),
    }

    Ok(())
}

fn iterate_list<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    parent_list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    let cbs = P::callbacks();
    let snode_path = snode.data_path();
    let cb_key = CallbackKey::new(snode_path, CallbackOp::GetIterate);

    if let Some(cb) = cbs.get_iterate(&cb_key)
        && let Some(list_iter) =
            (*cb)(provider, GetIterateArgs { parent_list_entry })
    {
        for list_entry in list_iter {
            iterate_list_entry(provider, dnode, snode, list_entry, relay_list)?;
        }
    }

    Ok(())
}

fn iterate_list_entry<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    let cbs = P::callbacks();
    let module = snode.module();
    let snode_path = snode.data_path();
    let cb_key = CallbackKey::new(snode_path, CallbackOp::GetObject);

    let mut dnode = match cbs.get_object(&cb_key) {
        // Keyed list.
        Some(cb) => {
            // Get YANG object from callback.
            let obj = (*cb)(
                provider,
                GetObjectArgs {
                    list_entry: &list_entry,
                },
            );

            // Get list keys.
            let keys = obj.list_keys();

            // Add list entry node.
            let mut dnode =
                dnode.new_list(Some(&module), snode.name(), &keys).unwrap();

            // Initialize list entry.
            obj.into_data_node(&mut dnode);
            dnode
        }
        // Keyless list.
        None => {
            // Add list entry node.
            let keys = String::new();
            dnode.new_list(Some(&module), snode.name(), &keys).unwrap()
        }
    };

    // Iterate over child nodes.
    iterate_children(provider, &mut dnode, snode, &list_entry, relay_list)?;

    Ok(())
}

fn iterate_container<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
    first: bool,
) -> Result<(), Error>
where
    P: Provider,
{
    let cbs = P::callbacks();
    let mut dnode = dnode.clone();
    let mut dnode_container;

    // Add container node.
    let dnode = if first {
        &mut dnode
    } else {
        let module = snode.module();
        dnode_container = dnode.new_inner(Some(&module), snode.name()).unwrap();
        &mut dnode_container
    };

    // Find GetObject callback.
    let snode_path = snode.data_path();
    let cb_key = CallbackKey::new(snode_path, CallbackOp::GetObject);
    if let Some(cb) = cbs.get_object(&cb_key) {
        // Invoke the callback and return an optional string.
        let obj = (*cb)(provider, GetObjectArgs { list_entry });

        // Initialize container node.
        obj.into_data_node(dnode);
    }

    iterate_children(provider, dnode, snode, list_entry, relay_list)?;

    // Remove the container node if it was added and remains empty.
    if !first && dnode.children().next().is_none() {
        dnode.remove();
    }

    Ok(())
}

fn iterate_children<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    for snode in snode.children().filter(|snode| {
        matches!(
            snode.kind(),
            SchemaNodeKind::List
                | SchemaNodeKind::Container
                | SchemaNodeKind::Choice
                | SchemaNodeKind::Case
        )
    }) {
        // Check if the provider implements the child node.
        let module = snode.module();
        if let Some(child_nb_tx) = list_entry.child_task(module.name()) {
            // Prepare request to child task.
            let path =
                format!("{}/{}:{}", dnode.path(), module.name(), snode.name());
            let relay_rx = relay_request(child_nb_tx, path);
            relay_list.push(relay_rx);
            continue;
        }

        iterate_node(provider, dnode, &snode, list_entry, relay_list, false)?;
    }

    Ok(())
}

fn lookup_list_entry<'a, P>(
    provider: &'a P,
    dnode: &DataNodeRef<'_>,
) -> P::ListEntry<'a>
where
    P: Provider,
{
    let cbs = P::callbacks();
    let mut list_entry = Default::default();

    // Iterate over parent list entries starting from the root.
    for dnode in dnode
        .inclusive_ancestors()
        .filter(|dnode| dnode.schema().kind() == SchemaNodeKind::List)
        .collect::<Vec<_>>()
        .iter()
        .rev()
    {
        // Get list callbacks.
        let snode_path = dnode.schema().data_path();
        let cb_key =
            CallbackKey::new(snode_path.clone(), CallbackOp::GetIterate);
        let Some(cb_iterate) = cbs.get_iterate(&cb_key) else {
            continue;
        };
        let cb_key = CallbackKey::new(snode_path, CallbackOp::GetObject);
        let Some(cb_get) = cbs.get_object(&cb_key) else {
            continue;
        };

        // Obtain the list entry keys.
        let list_keys =
            dnode.list_keys().fold(String::new(), |mut list_keys, key| {
                let _ = write!(
                    list_keys,
                    "[{}='{}']",
                    key.schema().name(),
                    key.value_canonical().unwrap()
                );
                list_keys
            });

        // Find the list entry associated to the provided path.
        if let Some(entry) = {
            (*cb_iterate)(
                provider,
                GetIterateArgs {
                    parent_list_entry: &list_entry,
                },
            )
            .and_then(|mut list_iter| {
                list_iter.find(|entry| {
                    let obj = (*cb_get)(
                        provider,
                        GetObjectArgs { list_entry: entry },
                    );
                    list_keys == obj.list_keys()
                })
            })
        } {
            list_entry = entry;
        }
    }

    list_entry
}

fn relay_request(nb_tx: NbDaemonSender, path: String) -> GetReceiver {
    let (responder_tx, responder_rx) = oneshot::channel();
    let request = api::daemon::GetRequest {
        path: Some(path),
        responder: Some(responder_tx),
    };
    tokio::task::spawn(async move {
        nb_tx
            .send(api::daemon::Request::Get(request))
            .await
            .unwrap();
    });
    responder_rx
}

// ===== global functions =====

pub(crate) fn process_get<P>(
    provider: &P,
    path: Option<String>,
) -> Result<api::daemon::GetResponse, Error>
where
    P: Provider,
{
    let yang_ctx = YANG_CTX.get().unwrap();

    let mut dtree = DataTree::new(yang_ctx);

    // Populate data tree with path requested by the user.
    let mut relay_list = vec![];
    let path = path.unwrap_or(provider.top_level_node());
    let mut dnode = dtree
        .new_path(&path, None, false)
        .map_err(Error::YangInvalidPath)?
        .unwrap();
    let list_entry = lookup_list_entry(provider, &dnode);
    let snode = yang_ctx.find_path(&dnode.schema().data_path()).unwrap();

    // Check if the provider implements the child node.
    let module = snode.module();
    if let Some(child_nb_tx) = list_entry.child_task(module.name()) {
        // Prepare request to child task.
        let relay_rx = relay_request(child_nb_tx, path);
        relay_list.push(relay_rx);
    } else {
        // If a list entry was given, iterate over that list entry.
        if snode.kind() == SchemaNodeKind::List {
            iterate_children(
                provider,
                &mut dnode,
                &snode,
                &list_entry,
                &mut relay_list,
            )?;
        } else {
            iterate_node(
                provider,
                &mut dnode,
                &snode,
                &list_entry,
                &mut relay_list,
                true,
            )?;
        }
    }

    // Collect responses from all relayed requests.
    for relay_rx in relay_list {
        let response = relay_rx.blocking_recv().unwrap()?;
        dtree
            .merge(&response.data)
            .map_err(Error::YangInvalidData)?;
    }

    Ok(api::daemon::GetResponse { data: dtree })
}
