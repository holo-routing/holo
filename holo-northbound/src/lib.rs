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

use crate::debug::Debug;

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
    fn top_level_node(&self) -> String;
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
