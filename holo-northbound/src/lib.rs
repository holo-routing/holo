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
pub mod yang_codegen;

use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use yang5::data::DataNodeRef;

use crate::debug::Debug;

// A trait representing YANG objects (containers or lists).
//
// This trait is automatically implemented for all structs generated from
// YANG definitions at build-time.
pub trait YangObject: YangObjectDyn {
    // Initialize a given YANG data node with attributes from the current
    // object.
    fn into_data_node(self, dnode: &mut DataNodeRef<'_>)
    where
        Self: Sized;

    // Return the keys of the list, or an empty string for containers or keyless
    // lists.
    fn list_keys(&self) -> String {
        String::new()
    }
}

// A bridge trait that enables dynamic dispatch for [YangObject].
pub trait YangObjectDyn {
    // Initialize a given YANG data node with attributes from the current
    // object.
    fn into_data_node(self: Box<Self>, dnode: &mut DataNodeRef<'_>);
}

// Blanket implementation that provides dynamic dispatch support to any type
// implementing [YangObject].
impl<T: YangObject> YangObjectDyn for T {
    fn into_data_node(self: Box<Self>, dnode: &mut DataNodeRef<'_>) {
        // T is Sized here, so we unbox and call the concrete implementation.
        (*self).into_data_node(dnode);
    }
}

//
// YANG path type.
//
// Instances of this structure are created automatically at build-time, and
// their use should be preferred over regular strings for extra type safety.
//
#[derive(Clone, Copy, Debug)]
pub struct YangPath(&'static str);

//
// Useful type definitions.
//
pub type NbDaemonSender = Sender<api::daemon::Request>;
pub type NbDaemonReceiver = Receiver<api::daemon::Request>;
pub type NbProviderSender = UnboundedSender<api::provider::Notification>;
pub type NbProviderReceiver = UnboundedReceiver<api::provider::Notification>;

// ===== impl YangPath =====

impl YangPath {
    pub const fn new(path: &'static str) -> YangPath {
        YangPath(path)
    }
}

impl std::fmt::Display for YangPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for YangPath {
    fn as_ref(&self) -> &str {
        self.0
    }
}

// ===== helper functions =====

fn process_get_callbacks<Provider>() -> api::daemon::GetCallbacksResponse
where
    Provider: configuration::Provider + state::Provider + rpc::Provider,
{
    let callbacks = [
        Some(<Provider as configuration::Provider>::callbacks().keys()),
        <Provider as configuration::Provider>::nested_callbacks(),
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
