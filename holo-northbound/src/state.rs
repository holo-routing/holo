//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::fmt::Write;

use holo_utils::yang::SchemaNodeExt;
use holo_yang::YANG_CTX;
use tokio::sync::oneshot;
use yang5::data::{DataNodeRef, DataTree};
use yang5::schema::{SchemaNode, SchemaNodeKind};

use crate::error::Error;
use crate::{NbDaemonSender, Path, PathElem, YangObject, api};

// A path element paired with its pre-resolved YANG schema node.
struct ResolvedPathElem<'a> {
    elem: &'a PathElem,
    snode: SchemaNode<'static>,
}

// Northbound data provider.
pub trait Provider
where
    Self: 'static + Sized,
{
    type ListEntry<'a>: ListEntryKind;
    const YANG_OPS: YangOps<Self>;

    fn top_level_node(&self) -> String;
}

// Common behavior for all list entries.
pub trait ListEntryKind: std::fmt::Debug + Default {
    // Return the task associated with the child node of this list entry,
    // identified by its corresponding module name.
    fn child_task(&self, _module_name: &str) -> Option<NbDaemonSender> {
        None
    }
}

// Implemented by all auto-generated YANG container structs that hold state
// data.
pub trait YangContainer<'a, P: Provider> {
    fn new(provider: &'a P, list_entry: &P::ListEntry<'a>) -> Option<Self>
    where
        Self: Sized + 'a;
}

// Implemented by all auto-generated YANG list structs that hold state data.
pub trait YangList<'a, P: Provider> {
    fn iter(
        provider: &'a P,
        list_entry: &P::ListEntry<'a>,
    ) -> Option<ListIterator<'a, P>>;

    fn new(provider: &'a P, list_entry: &P::ListEntry<'a>) -> Self
    where
        Self: Sized + 'a;
}

// Static dispatch tables generated from YANG models.
pub struct YangOps<P: Provider> {
    pub list: phf::Map<&'static str, YangListOps<P>>,
    pub container: phf::Map<&'static str, YangContainerOps<P>>,
}

pub struct YangListOps<P: Provider> {
    pub iter: YangListIterFn<P>,
    pub new: YangListNewFn<P>,
}

pub struct YangContainerOps<P: Provider> {
    pub new: YangContainerNewFn<P>,
}

// Type aliases.
type YangListIterFn<P: Provider> =
    for<'a> fn(&'a P, &P::ListEntry<'a>) -> Option<ListIterator<'a, P>>;
type YangListNewFn<P: Provider> =
    for<'a> fn(&'a P, &P::ListEntry<'a>) -> Box<dyn YangObject + 'a>;
type YangContainerNewFn<P: Provider> =
    for<'a> fn(&'a P, &P::ListEntry<'a>) -> Option<Box<dyn YangObject + 'a>>;
type ListIterator<'a, P: Provider> =
    Box<dyn Iterator<Item = P::ListEntry<'a>> + 'a>;
type GetReceiver = oneshot::Receiver<Result<api::daemon::GetResponse, Error>>;

// ===== helper functions =====

fn iterate_node<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    match snode.kind() {
        SchemaNodeKind::List => {
            iterate_list(provider, dnode, snode, list_entry, relay_list)?;
        }
        SchemaNodeKind::Container => {
            iterate_container(provider, dnode, snode, list_entry, relay_list)?;
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
    let module = snode.module();
    let snode_path = snode.data_path();
    if let Some(list_ops) = P::YANG_OPS.list.get(&snode_path)
        && let Some(list_iter) = (list_ops.iter)(provider, parent_list_entry)
    {
        for list_entry in list_iter {
            let obj = (list_ops.new)(provider, &list_entry);

            // Get list keys.
            let keys = obj.list_keys();

            // Add list entry node.
            let mut dnode =
                dnode.new_list(Some(&module), snode.name(), &keys).unwrap();

            // Initialize list entry.
            obj.into_data_node(&mut dnode);

            // Iterate over child nodes.
            iterate_children(
                provider,
                &mut dnode,
                snode,
                &list_entry,
                relay_list,
            )?;
        }
    }

    Ok(())
}

fn iterate_container<'a, P>(
    provider: &'a P,
    dnode: &mut DataNodeRef<'_>,
    snode: &SchemaNode<'_>,
    list_entry: &P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    // Add container node.
    let module = snode.module();
    let mut child = dnode.new_inner(Some(&module), snode.name()).unwrap();

    let snode_path = snode.data_path();
    if let Some(container_ops) = P::YANG_OPS.container.get(&snode_path)
        && let Some(obj) = (container_ops.new)(provider, list_entry)
    {
        // Initialize container node.
        obj.into_data_node(&mut child);
    }

    iterate_children(provider, &mut child, snode, list_entry, relay_list)?;

    // Remove empty containers that produced no children.
    if child.children().next().is_none() {
        child.remove();
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
            let mut path = Path::from_dnode(dnode);
            path.elems.push(PathElem {
                name: format!("{}:{}", module.name(), snode.name()),
                keys: HashMap::new(),
            });
            let relay_rx = relay_request(child_nb_tx, path);
            relay_list.push(relay_rx);
            continue;
        }

        iterate_node(provider, dnode, &snode, list_entry, relay_list)?;
    }

    Ok(())
}

fn relay_request(nb_tx: NbDaemonSender, path: Path) -> GetReceiver {
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

// Resolves each path element to its schema node, validating key names.
fn resolve_path<'a>(
    path: &'a Path,
) -> Result<Vec<ResolvedPathElem<'a>>, Error> {
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut schema_path = String::new();
    let mut resolved = Vec::with_capacity(path.elems.len());

    for elem in &path.elems {
        let _ = write!(schema_path, "/{}", elem.name);
        let snode = yang_ctx
            .find_path(&schema_path)
            .map_err(Error::YangInvalidPath)?;

        if !elem.keys.is_empty() {
            let schema_keys: Vec<_> =
                snode.list_keys().map(|k| k.name().to_owned()).collect();
            for key_name in elem.keys.keys() {
                if !schema_keys.iter().any(|sk| sk == key_name) {
                    return Err(Error::YangInvalidListKeys);
                }
            }
        }

        resolved.push(ResolvedPathElem { elem, snode });
    }

    Ok(resolved)
}

// Recursively expands pre-resolved path elements into a data tree,
// creating intermediate list/container nodes and populating leaf data.
// Cross-module nodes are relayed to the child task that owns them.
fn expand_path<'a, P>(
    provider: &'a P,
    parent_dnode: &mut DataNodeRef<'_>,
    remaining: &[ResolvedPathElem<'_>],
    list_entry: P::ListEntry<'a>,
    relay_list: &mut Vec<GetReceiver>,
) -> Result<(), Error>
where
    P: Provider,
{
    // Target reached - populate the full subtree.
    let Some((resolved, rest)) = remaining.split_first() else {
        let yang_ctx = YANG_CTX.get().unwrap();
        let snode = yang_ctx
            .find_path(&parent_dnode.schema().data_path())
            .unwrap();
        let module = snode.module();
        if let Some(child_nb_tx) = list_entry.child_task(module.name()) {
            let path = Path::from_dnode(parent_dnode);
            let relay_rx = relay_request(child_nb_tx, path);
            relay_list.push(relay_rx);
        } else {
            if snode.kind() == SchemaNodeKind::Container {
                let snode_path = snode.data_path();
                if let Some(container_ops) =
                    P::YANG_OPS.container.get(&snode_path)
                    && let Some(obj) =
                        (container_ops.new)(provider, &list_entry)
                {
                    obj.into_data_node(parent_dnode);
                }
            }
            iterate_children(
                provider,
                parent_dnode,
                &snode,
                &list_entry,
                relay_list,
            )?;
        }
        return Ok(());
    };

    let elem = resolved.elem;
    let snode = &resolved.snode;

    // Relay to child task if this node is owned by a different provider.
    let module = snode.module();
    if let Some(child_nb_tx) = list_entry.child_task(module.name()) {
        let mut path = Path::from_dnode(parent_dnode);
        path.elems.extend(remaining.iter().map(|r| r.elem.clone()));
        let relay_rx = relay_request(child_nb_tx, path);
        relay_list.push(relay_rx);
        return Ok(());
    }

    // Leaf values are emitted by into_data_node() on the parent, so we
    // must populate the current node when the next element is a leaf.
    let next_is_leaf = rest.first().is_some_and(|next| {
        matches!(
            next.snode.kind(),
            SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
        )
    });

    match snode.kind() {
        SchemaNodeKind::List => {
            let snode_path = snode.data_path();
            if let Some(list_ops) = P::YANG_OPS.list.get(&snode_path)
                && let Some(list_iter) = (list_ops.iter)(provider, &list_entry)
            {
                let is_target = rest.is_empty();
                for entry in list_iter {
                    let obj = (list_ops.new)(provider, &entry);
                    let keys = obj.list_keys();

                    // Filter by provided keys (no keys = match all).
                    if !elem.keys.iter().all(|(k, v)| {
                        keys.contains(&format!("[{}='{}']", k, v))
                    }) {
                        continue;
                    }

                    let mut child = parent_dnode
                        .new_list(Some(&module), snode.name(), &keys)
                        .map_err(Error::YangInvalidPath)?;

                    if is_target || next_is_leaf {
                        obj.into_data_node(&mut child);
                    }

                    let relay_count = relay_list.len();
                    expand_path(provider, &mut child, rest, entry, relay_list)?;

                    // Prune entries with only keys and no actual data.
                    if relay_list.len() == relay_count
                        && child.children().count() <= snode.list_keys().count()
                    {
                        child.remove();
                    }
                }
            } else if elem.keys.len() == snode.list_keys().count() {
                let key_values = snode
                    .list_keys()
                    .map(|key| &elem.keys[key.name()])
                    .collect::<Vec<_>>();
                let mut child = parent_dnode
                    .new_list2(Some(&module), snode.name(), &key_values)
                    .map_err(Error::YangInvalidPath)?;

                let relay_count = relay_list.len();
                expand_path(
                    provider,
                    &mut child,
                    rest,
                    Default::default(),
                    relay_list,
                )?;

                if relay_list.len() == relay_count
                    && child.children().count() <= snode.list_keys().count()
                {
                    child.remove();
                }
            }
        }
        SchemaNodeKind::Container => {
            let mut child = parent_dnode
                .new_inner(Some(&module), snode.name())
                .map_err(Error::YangInvalidPath)?;

            if next_is_leaf {
                let snode_path = snode.data_path();
                if let Some(container_ops) =
                    P::YANG_OPS.container.get(&snode_path)
                    && let Some(obj) =
                        (container_ops.new)(provider, &list_entry)
                {
                    obj.into_data_node(&mut child);
                }
            }

            expand_path(provider, &mut child, rest, list_entry, relay_list)?;

            if child.children().next().is_none() {
                child.remove();
            }
        }
        _ => {}
    }

    Ok(())
}

// ===== global functions =====

pub(crate) fn process_get<P>(
    provider: &P,
    path: Option<Path>,
) -> Result<api::daemon::GetResponse, Error>
where
    P: Provider,
{
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut dtree = DataTree::new(yang_ctx);
    let mut relay_list = vec![];

    let path = path
        .filter(|path| !path.elems.is_empty())
        .unwrap_or_else(|| Path::from_yang_path(&provider.top_level_node()));
    let resolved = resolve_path(&path)?;

    // Create the root data node and expand the remaining path.
    let first_path = format!("/{}", path.elems[0].name);
    let mut dnode = dtree
        .new_path(&first_path, None, false)
        .map_err(Error::YangInvalidPath)?
        .unwrap();
    expand_path(
        provider,
        &mut dnode,
        &resolved[1..],
        Default::default(),
        &mut relay_list,
    )?;

    // Merge responses from child tasks.
    for relay_rx in relay_list {
        let response = relay_rx.blocking_recv().unwrap()?;
        dtree
            .merge(&response.data)
            .map_err(Error::YangInvalidData)?;
    }

    Ok(api::daemon::GetResponse { data: dtree })
}
