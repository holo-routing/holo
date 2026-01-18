//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::yang::SchemaNodeExt;
use tokio::sync::oneshot;
use yang4::data::{DataNodeRef, DataTree};
use yang4::schema::SchemaNodeKind;

use crate::error::Error;
use crate::{NbDaemonSender, ProviderBase, api};

// Northbound RPC provider.
pub trait Provider: ProviderBase {
    const YANG_OPS: YangOps<Self>;

    fn relay_rpc(
        &self,
        _rpc: &DataNodeRef<'_>,
    ) -> Result<Option<Vec<NbDaemonSender>>, String> {
        Ok(None)
    }
}

// Implemented by all auto-generated YANG RPC/Action structs.
pub trait YangRpc<P: Provider> {
    fn invoke(
        provider: &mut P,
        data: &mut DataTree<'static>,
        rpc_path: &str,
    ) -> Result<(), String>;
}

// Static dispatch tables generated from YANG models.
pub struct YangOps<P: Provider> {
    pub rpc: phf::Map<&'static str, YangRpcOps<P>>,
}

pub struct YangRpcOps<P: Provider> {
    pub invoke: YangInvokeFn<P>,
}

// Type aliases.
type YangInvokeFn<P> =
    fn(&mut P, &mut DataTree<'static>, &str) -> Result<(), String>;

// ===== helper functions =====

fn process_rpc_local<P>(
    provider: &mut P,
    mut data: DataTree<'static>,
    rpc_data_path: String,
    rpc_schema_path: String,
) -> Result<api::daemon::RpcResponse, Error>
where
    P: Provider,
{
    if let Some(rpc_ops) = P::YANG_OPS.rpc.get(&rpc_schema_path) {
        (rpc_ops.invoke)(provider, &mut data, &rpc_data_path)
            .map_err(Error::RpcCallback)?;
    }

    let response = api::daemon::RpcResponse { data };
    Ok(response)
}

fn process_rpc_relayed(
    mut data: DataTree<'static>,
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
            .blocking_send(api::daemon::Request::Rpc(relayed_req))
            .unwrap();

        // Receive response.
        let response = responder_rx.blocking_recv().unwrap()?;
        data = response.data;
    }

    let response = api::daemon::RpcResponse { data };
    Ok(response)
}

fn find_rpc<'a>(data: &'a DataTree<'static>) -> Result<DataNodeRef<'a>, Error> {
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

pub(crate) fn process_rpc<P>(
    provider: &mut P,
    data: DataTree<'static>,
) -> Result<api::daemon::RpcResponse, Error>
where
    P: Provider,
{
    let rpc = find_rpc(&data)?;
    if let Some(children_nb_tx) =
        provider.relay_rpc(&rpc).map_err(Error::RpcRelay)?
    {
        process_rpc_relayed(data, children_nb_tx)
    } else {
        let rpc_data_path = rpc.path().to_owned();
        let rpc_schema_path = rpc.schema().data_path();
        process_rpc_local(provider, data, rpc_data_path, rpc_schema_path)
    }
}
