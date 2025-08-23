//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod ibus;
pub mod northbound;

use std::collections::HashMap;

use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, ProviderBase,
    process_northbound_msg,
};
use holo_utils::ibus::{IbusChannelsTx, IbusMsg, IbusReceiver, IbusSender};
use holo_utils::task::Task;
use northbound::configuration::SystemCfg;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

#[derive(Debug)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // System configuration.
    pub config: SystemCfg,
    // Hostname subscriptions.
    pub hostname_subscriptions: HashMap<usize, IbusSender>,
}

#[derive(Debug)]
pub enum EventMsg {
    Northbound(Option<holo_northbound::api::daemon::Request>),
    Ibus(IbusMsg),
}

// ===== impl Master =====

impl Master {
    fn run(&mut self, nb_rx: NbDaemonReceiver, ibus_rx: IbusReceiver) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator = event_aggregator(nb_rx, ibus_rx, agg_tx);

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
                EventMsg::Ibus(msg) => {
                    ibus::process_msg(self, msg);
                }
            }
        }
    }
}

// ===== helper functions =====

fn event_aggregator(
    mut nb_rx: NbDaemonReceiver,
    mut ibus_rx: IbusReceiver,
    agg_tx: Sender<EventMsg>,
) -> Task<()> {
    Task::spawn(async move {
        loop {
            let msg = tokio::select! {
                msg = nb_rx.recv() => {
                    EventMsg::Northbound(msg)
                }
                Some(msg) = ibus_rx.recv() => {
                    EventMsg::Ibus(msg)
                }
            };
            let _ = agg_tx.send(msg).await;
        }
    })
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    ibus_tx: IbusChannelsTx,
    ibus_rx: IbusReceiver,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::task::spawn_blocking(|| {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            config: Default::default(),
            hostname_subscriptions: Default::default(),
        };

        // Run task main loop.
        let span = Master::debug_span("");
        let _span_guard = span.enter();
        master.run(nb_daemon_rx, ibus_rx);
    });

    nb_daemon_tx
}
