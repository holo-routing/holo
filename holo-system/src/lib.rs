//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![feature(let_chains)]

mod ibus;
pub mod northbound;

use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, ProviderBase,
    process_northbound_msg,
};
use holo_utils::ibus::{IbusChannelsTx, IbusReceiver, IbusSubscriber};
use northbound::configuration::SystemCfg;
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(Debug)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // System configuration.
    pub config: SystemCfg,
}

// ===== impl Master =====

impl Master {
    async fn run(
        &mut self,
        mut nb_rx: NbDaemonReceiver,
        mut ibus_rx: IbusReceiver,
    ) {
        let mut resources = vec![];

        loop {
            tokio::select! {
                Some(request) = nb_rx.recv() => {
                    process_northbound_msg(
                        self,
                        &mut resources,
                        request,
                    )
                    .await;
                }
                Some(msg) = ibus_rx.recv() => {
                    ibus::process_msg(self, msg);
                }
            }
        }
    }
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    mut ibus_tx: IbusChannelsTx,
    ibus_rx: IbusReceiver,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);
    ibus_tx.subscriber = Some(IbusSubscriber::new(ibus_tx.system.clone()));

    tokio::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            config: Default::default(),
        };

        // Run task main loop.
        let span = Master::debug_span("");
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
