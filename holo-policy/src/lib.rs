//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod northbound;

use std::collections::BTreeMap;

use derive_new::new;
use futures::stream::{SelectAll, StreamExt};
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, process_northbound_msg,
};
use holo_utils::ibus::{
    IbusChannelsTx, IbusClient, IbusClientId, IbusConnEvent, IbusConnReceiver,
    IbusConnStream, IbusMsg, connection_stream,
};
use holo_utils::policy::{MatchSets, Policy};
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tracing::debug_span;

#[derive(Debug, new)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // Sets of attributes used in policy match statements.
    #[new(default)]
    pub match_sets: MatchSets,
    // List of configured policies.
    #[new(default)]
    pub policies: BTreeMap<String, Policy>,
}

#[derive(Debug)]
pub enum EventMsg {
    Northbound(Option<holo_northbound::api::daemon::Request>),
    Ibus { client: IbusClient, msg: IbusMsg },
    IbusDisconnect { id: IbusClientId },
}

// ===== impl Master =====

impl Master {
    fn run(&mut self, nb_rx: NbDaemonReceiver, ibus_conn_rx: IbusConnReceiver) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator = event_aggregator(nb_rx, ibus_conn_rx, agg_tx);

        let mut resources = vec![];
        loop {
            // Receive event message.
            let msg = agg_rx.blocking_recv().unwrap();

            // Process event message.
            match msg {
                EventMsg::Northbound(Some(msg)) => {
                    process_northbound_msg(self, &mut resources, msg);
                }
                EventMsg::Northbound(None) => {
                    // Exit when northbound channel closes.
                    return;
                }
                EventMsg::Ibus { .. } => {}
                EventMsg::IbusDisconnect { .. } => {}
            }
        }
    }
}

// ===== helper functions =====

fn event_aggregator(
    mut nb_rx: NbDaemonReceiver,
    mut ibus_conn_rx: IbusConnReceiver,
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
            };
            let _ = agg_tx.send(msg).await;
        }
    })
}

// ===== global functions =====

pub fn start(
    nb_provider_tx: NbProviderSender,
    ibus_tx: &IbusChannelsTx,
    ibus_conn_rx: IbusConnReceiver,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);
    let (ibus_notif_tx, _) = mpsc::unbounded_channel();
    let ibus_tx = IbusChannelsTx::with_client(ibus_tx, ibus_notif_tx);

    tokio::task::spawn_blocking(|| {
        let mut master = Master::new(nb_provider_tx, ibus_tx);

        // Run task main loop.
        let span = debug_span!("policy");
        let _span_guard = span.enter();
        master.run(nb_daemon_rx, ibus_conn_rx);
    });

    nb_daemon_tx
}
