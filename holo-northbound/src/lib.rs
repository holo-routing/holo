//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(type_alias_bounds)]

mod debug;

pub mod api;
pub mod configuration;
pub mod error;
pub mod notification;
pub mod rpc;
pub mod state;

#[allow(unused_variables)]
#[allow(clippy::module_inception, clippy::needless_borrow)]
pub mod yang;

use derive_new::new;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tracing::Span;
use yang3::schema::{DataValueType, SchemaNode, SchemaNodeKind};

use crate::debug::Debug;

/// YANG callback operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum CallbackOp {
    Create,
    Modify,
    Delete,
    Lookup,
    Rpc,
    GetIterate,
    GetObject,
}

/// YANG callback key.
#[derive(Clone, Debug, Eq, Hash, new, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct CallbackKey {
    pub path: String,
    pub operation: CallbackOp,
}

//
// Useful type definitions.
//
pub type NbDaemonSender = Sender<api::daemon::Request>;
pub type NbDaemonReceiver = Receiver<api::daemon::Request>;
pub type NbProviderSender = UnboundedSender<api::provider::Notification>;
pub type NbProviderReceiver = UnboundedReceiver<api::provider::Notification>;

/// Base northbound provider trait.
pub trait ProviderBase
where
    Self: 'static + Sized,
{
    fn yang_modules() -> &'static [&'static str];

    fn top_level_node(&self) -> String;

    fn debug_span(name: &str) -> Span;
}

// ===== impl CallbackOp =====

impl CallbackOp {
    pub fn is_valid(&self, snode: &SchemaNode<'_>) -> bool {
        match self {
            CallbackOp::Create => CallbackOp::create_is_valid(snode),
            CallbackOp::Modify => CallbackOp::modify_is_valid(snode),
            CallbackOp::Delete => CallbackOp::delete_is_valid(snode),
            CallbackOp::Lookup => CallbackOp::lookup_is_valid(snode),
            CallbackOp::Rpc => CallbackOp::rpc_is_valid(snode),
            CallbackOp::GetIterate => CallbackOp::get_iterate_is_valid(snode),
            CallbackOp::GetObject => CallbackOp::get_object_is_valid(snode),
        }
    }

    fn create_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                snode.leaf_type().unwrap().base_type() == DataValueType::Empty
            }
            SchemaNodeKind::Container => !snode.is_np_container(),
            SchemaNodeKind::LeafList | SchemaNodeKind::List => true,
            _ => false,
        }
    }

    fn modify_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                // List keys can't be modified.
                !(snode.leaf_type().unwrap().base_type()
                    == DataValueType::Empty
                    || snode.is_list_key())
            }
            _ => false,
        }
    }

    fn delete_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        match snode.kind() {
            SchemaNodeKind::Leaf => {
                // List keys can't be deleted.
                if snode.is_list_key() {
                    return false;
                }

                // Only optional leaves can be deleted, or leaves whose
                // parent is a case statement.
                if let Some(parent) = snode.ancestors().next()
                    && parent.kind() == SchemaNodeKind::Case
                {
                    return true;
                }
                if snode.whens().next().is_some() {
                    return true;
                }
                if snode.is_mandatory() || snode.has_default() {
                    return false;
                }

                true
            }
            SchemaNodeKind::Container => !snode.is_np_container(),
            SchemaNodeKind::LeafList | SchemaNodeKind::List => true,
            _ => false,
        }
    }

    fn lookup_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() {
            return false;
        }

        snode.kind() == SchemaNodeKind::List
    }

    fn rpc_is_valid(snode: &SchemaNode<'_>) -> bool {
        matches!(snode.kind(), SchemaNodeKind::Rpc | SchemaNodeKind::Action)
    }

    fn get_iterate_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !snode.is_config() && !snode.is_state() {
            return false;
        }

        if snode.kind() != SchemaNodeKind::List {
            return false;
        }

        snode.traverse().any(|snode| snode.is_state())
    }

    fn get_object_is_valid(snode: &SchemaNode<'_>) -> bool {
        if !matches!(
            snode.kind(),
            SchemaNodeKind::List | SchemaNodeKind::Container
        ) {
            return false;
        }

        if !snode.traverse().any(|snode| snode.is_state()) {
            return false;
        }

        snode.children().any(|snode| {
            if snode.is_list_key() {
                return true;
            }

            if !snode.is_state() {
                return false;
            }

            contains_leaf_or_leaflist(&snode)
        })
    }
}

// ===== helper functions =====

fn contains_leaf_or_leaflist(snode: &SchemaNode<'_>) -> bool {
    match snode.kind() {
        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => true,
        SchemaNodeKind::Choice => snode
            .children()
            .flat_map(|snode| snode.children())
            .any(|snode| contains_leaf_or_leaflist(&snode)),
        _ => false,
    }
}

fn process_get_callbacks<Provider>() -> api::daemon::GetCallbacksResponse
where
    Provider: configuration::Provider + state::Provider + rpc::Provider,
{
    let callbacks = [
        Some(<Provider as configuration::Provider>::callbacks().keys()),
        Some(<Provider as rpc::Provider>::callbacks().keys()),
        Some(<Provider as state::Provider>::callbacks().keys()),
        <Provider as configuration::Provider>::nested_callbacks(),
        <Provider as rpc::Provider>::nested_callbacks(),
        <Provider as state::Provider>::nested_callbacks(),
    ]
    .into_iter()
    .flatten()
    .flat_map(|v| v.into_iter())
    .collect();

    api::daemon::GetCallbacksResponse { callbacks }
}

// ===== global functions =====

// Processes a northbound message coming from the Holo daemon.
pub fn process_northbound_msg<Provider>(
    provider: &mut Provider,
    resources: &mut Vec<Option<Provider::Resource>>,
    request: api::daemon::Request,
) where
    Provider: configuration::Provider + state::Provider + rpc::Provider,
{
    Debug::RequestRx(&request).log();

    match request {
        api::daemon::Request::GetCallbacks(request) => {
            let response = process_get_callbacks::<Provider>();
            if let Some(responder) = request.responder {
                responder.send(response).unwrap();
            }
        }
        api::daemon::Request::Validate(request) => {
            let response =
                configuration::process_validate(provider, request.config);
            if let Some(responder) = request.responder {
                responder.send(response).unwrap();
            }
        }
        api::daemon::Request::Commit(request) => {
            let response = configuration::process_commit(
                provider,
                request.phase,
                request.old_config,
                request.new_config,
                request.changes,
                resources,
            );
            if let Some(responder) = request.responder {
                responder.send(response).unwrap();
            }
        }
        api::daemon::Request::Get(request) => {
            let response = state::process_get(provider, request.path);
            if let Some(responder) = request.responder {
                responder.send(response).unwrap();
            }
        }
        api::daemon::Request::Rpc(request) => {
            let response = rpc::process_rpc(provider, request.data);
            if let Some(responder) = request.responder {
                responder.send(response).unwrap();
            }
        }
    }
}
