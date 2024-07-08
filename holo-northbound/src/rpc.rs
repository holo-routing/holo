//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use holo_utils::yang::SchemaNodeExt;
use holo_yang::YangPath;
use tokio::sync::oneshot;
use yang3::data::{DataNodeRef, DataTree};
use yang3::schema::SchemaNodeKind;

use crate::debug::Debug;
use crate::error::Error;
use crate::{api, CallbackKey, CallbackOp, NbDaemonSender, ProviderBase};

//
// RPC callbacks.
//

pub struct Callbacks<P: Provider>(pub HashMap<CallbackKey, Callback<P>>);

pub struct CallbacksBuilder<P: Provider> {
    path: Option<YangPath>,
    callbacks: Callbacks<P>,
}

#[derive(Debug)]
pub struct CallbackArgs<'a> {
    pub data: &'a mut DataTree,
    pub rpc_path: &'a str,
}

//
// Useful type definition(s).
//

pub type Callback<P> = for<'a> fn(
    &'a mut P,
    CallbackArgs<'a>,
) -> Pin<
    Box<dyn Future<Output = Result<(), String>> + Send + 'a>,
>;

// RPC protocol trait.
pub trait Provider: ProviderBase {
    fn callbacks() -> Option<&'static Callbacks<Self>> {
        None
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        None
    }

    fn relay_rpc(
        &self,
        _rpc: DataNodeRef<'_>,
    ) -> Result<Option<Vec<NbDaemonSender>>, String> {
        Ok(None)
    }
}

// ===== impl Callbacks =====

impl<P> Callbacks<P>
where
    P: Provider,
{
    pub fn load(&mut self, path: &'static str, cb: Callback<P>) {
        let path = path.to_string();
        let key = CallbackKey::new(path, CallbackOp::Rpc);
        self.0.insert(key, cb);
    }

    fn get(&self, key: &CallbackKey) -> Option<&Callback<P>> {
        self.0.get(key)
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

// ===== impl CallbacksBuilder =====

impl<P> CallbacksBuilder<P>
where
    P: Provider,
{
    #[must_use]
    pub fn path(mut self, path: YangPath) -> Self {
        self.path = Some(path);
        self
    }

    #[must_use]
    pub fn rpc(mut self, cb: Callback<P>) -> Self {
        let path = self.path.unwrap().to_string();
        let key = CallbackKey::new(path, CallbackOp::Rpc);
        self.callbacks.0.insert(key, cb);
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

async fn process_rpc_local<P>(
    provider: &mut P,
    mut data: DataTree,
    rpc_data_path: String,
    rpc_schema_path: String,
) -> Result<api::daemon::RpcResponse, Error>
where
    P: Provider,
{
    if let Some(callbacks) = P::callbacks() {
        Debug::RpcCallback(&rpc_data_path).log();

        let key = CallbackKey::new(rpc_schema_path, CallbackOp::Rpc);
        if let Some(cb) = callbacks.get(&key) {
            let args = CallbackArgs {
                data: &mut data,
                rpc_path: &rpc_data_path,
            };
            (*cb)(provider, args).await.map_err(Error::RpcCallback)?;
        }
    }

    let response = api::daemon::RpcResponse { data };
    Ok(response)
}

async fn process_rpc_relayed(
    mut data: DataTree,
    children_nb_tx: Vec<NbDaemonSender>,
) -> Result<api::daemon::RpcResponse, Error> {
    for nb_tx in children_nb_tx {
        // Send request to child task.
        let (responder_tx, responder_rx) = oneshot::channel();
        let relayed_req = api::daemon::RpcRequest {
            data,
            responder: Some(responder_tx),
        };
        nb_tx
            .send(api::daemon::Request::Rpc(relayed_req))
            .await
            .unwrap();

        // Receive response.
        let response = responder_rx.await.unwrap()?;
        data = response.data;
    }

    let response = api::daemon::RpcResponse { data };
    Ok(response)
}

fn find_rpc(data: &DataTree) -> Result<DataNodeRef<'_>, Error> {
    data.traverse()
        .find(|dnode| {
            matches!(
                dnode.schema().kind(),
                SchemaNodeKind::Rpc | SchemaNodeKind::Action
            )
        })
        .ok_or(Error::RpcNotFound)
}

// ===== global functions =====

pub(crate) async fn process_rpc<P>(
    provider: &mut P,
    data: DataTree,
) -> Result<api::daemon::RpcResponse, Error>
where
    P: Provider,
{
    let rpc = find_rpc(&data)?;
    let rpc_data_path = rpc.path().to_owned();
    let rpc_schema_path = rpc.schema().data_path();

    if let Some(children_nb_tx) =
        provider.relay_rpc(rpc).map_err(Error::RpcRelay)?
    {
        process_rpc_relayed(data, children_nb_tx).await
    } else {
        process_rpc_local(provider, data, rpc_data_path, rpc_schema_path).await
    }
}
