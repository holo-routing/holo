//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod dataplane;
mod ibus;
mod interface;
pub mod northbound;

use futures::stream::{SelectAll, StreamExt};
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, process_northbound_msg,
};
use holo_protocol::InstanceShared;
use holo_utils::ibus::{
    IbusChannelsTx, IbusClient, IbusClientId, IbusConnEvent, IbusConnReceiver,
    IbusConnStream, IbusMsg, connection_stream,
};
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tracing::debug_span;

use crate::dataplane::{Dataplane, DataplaneMonitor};
use crate::interface::Interfaces;

#[derive(Debug)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // Dataplane handle.
    pub dataplane: dataplane::Backend,
    // Shared data among all protocol instances.
    pub shared: InstanceShared,
    // List of interfaces.
    pub interfaces: Interfaces,
}

#[derive(Debug)]
pub(crate) enum EventMsg {
    Northbound(Option<holo_northbound::api::daemon::Request>),
    Ibus { client: IbusClient, msg: IbusMsg },
    IbusDisconnect { id: IbusClientId },
    Dataplane(<dataplane::Backend as Dataplane>::Event),
}

// ===== impl Master =====

impl Master {
    fn run(
        &mut self,
        nb_rx: NbDaemonReceiver,
        ibus_conn_rx: IbusConnReceiver,
        dataplane_rx: DataplaneMonitor,
    ) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator =
            event_aggregator(nb_rx, ibus_conn_rx, dataplane_rx, agg_tx);

        let mut pending_changes = vec![];
        loop {
            // Receive event message, exiting when the aggregator task
            // goes away.
            let Some(msg) = agg_rx.blocking_recv() else {
                return;
            };

            // Process event message.
            match msg {
                EventMsg::Northbound(Some(msg)) => {
                    process_northbound_msg(self, &mut pending_changes, msg);
                }
                EventMsg::Northbound(None) => {
                    // Exit when northbound channel closes.
                    return;
                }
                EventMsg::Ibus { client, msg } => {
                    ibus::process_msg(self, client, msg);
                }
                EventMsg::IbusDisconnect { id } => {
                    ibus::disconnect(self, id);
                }
                EventMsg::Dataplane(msg) => {
                    dataplane::Backend::process_msg(self, msg);
                }
            }
        }
    }
}

// ===== helper functions =====

fn event_aggregator(
    mut nb_rx: NbDaemonReceiver,
    mut ibus_conn_rx: IbusConnReceiver,
    mut dataplane_rx: DataplaneMonitor,
    agg_tx: Sender<EventMsg>,
) -> Task<()> {
    Task::spawn(async move {
        let mut connections: SelectAll<IbusConnStream> = SelectAll::new();

        loop {
            let msg = tokio::select! {
                msg = nb_rx.recv() => {
                    EventMsg::Northbound(msg)
                }
                Some(conn) = ibus_conn_rx.recv() => {
                    connections.push(connection_stream(conn));
                    continue;
                }
                Some((id, event)) = connections.next(),
                    if !connections.is_empty() =>
                {
                    match event {
                        IbusConnEvent::Msg { tx, msg } => EventMsg::Ibus {
                            client: IbusClient { id, tx },
                            msg,
                        },
                        IbusConnEvent::Disconnect => {
                            EventMsg::IbusDisconnect { id }
                        }
                    }
                }
                Some(msg) = dataplane_rx.next() => {
                    EventMsg::Dataplane(msg)
                }
            };
            let _ = agg_tx.send(msg).await;
        }
    })
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    ibus_tx: &IbusChannelsTx,
    ibus_conn_rx: IbusConnReceiver,
    shared: InstanceShared,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);
    let (ibus_notif_tx, _) = mpsc::unbounded_channel();
    let ibus_tx = IbusChannelsTx::with_client(ibus_tx, ibus_notif_tx);

    tokio::task::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            dataplane: dataplane::Backend::init(),
            shared,
            interfaces: Default::default(),
        };

        // Start monitoring dataplane interface events.
        let dataplane_rx = dataplane::Backend::monitor();

        // Fetch interface information from the dataplane.
        dataplane::Backend::interfaces_fetch(&mut master).await;

        tokio::task::spawn_blocking(move || {
            // Run task main loop.
            let span = debug_span!("interface");
            let _span_guard = span.enter();
            master.run(nb_daemon_rx, ibus_conn_rx, dataplane_rx);

            // Flush pending dataplane requests before exiting.
            master.dataplane.flush();
        });
    });

    nb_daemon_tx
}
