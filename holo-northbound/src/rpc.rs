//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::yang::SchemaNodeExt;
use tokio::sync::oneshot;
use yang5::data::{Data, DataNodeRef, DataTree};
use yang5::schema::SchemaNodeKind;

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

// Manually implemented in each provider to handle RPC/Action invocations.
pub trait YangRpc<P: Provider> {
    fn invoke(&mut self, provider: &mut P) -> Result<(), String>;
}

// Static dispatch tables generated from YANG models.
pub struct YangOps<P: Provider> {
    pub rpc: phf::Map<&'static str, YangRpcOps<P>>,
}

pub struct YangRpcOps<P: Provider> {
    pub process: fn(&mut DataNodeRef<'_>, &mut P) -> Result<(), String>,
}

// Automatically implemented for all auto-generated YANG RPC/Action structs.
pub trait YangRpcObject: Sized {
    // Parses input parameters from the YANG data node into the generated struct.
    fn parse_input(dnode: &DataNodeRef<'_>) -> Self;

    // Writes output parameters back into the YANG data node after invoke().
    fn write_output(self, dnode: &mut DataNodeRef<'_>);
}

// ===== helper functions =====

fn process_rpc_local<P>(
    provider: &mut P,
    data: DataTree<'static>,
    rpc_data_path: String,
    rpc_schema_path: String,
) -> Result<api::daemon::RpcResponse, Error>
where
    P: Provider,
{
    if let Some(rpc_ops) = P::YANG_OPS.rpc.get(&rpc_schema_path) {
        let mut rpc = data
            .find_path(&rpc_data_path)
            .map_err(|_| Error::RpcNotFound)?;
        (rpc_ops.process)(&mut rpc, provider).map_err(Error::RpcCallback)?;
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
