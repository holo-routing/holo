//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![feature(lazy_cell)]

pub mod northbound;

use std::collections::BTreeMap;

use derive_new::new;
use holo_northbound::{
    process_northbound_msg, NbDaemonReceiver, NbDaemonSender, NbProviderSender,
    ProviderBase,
};
use holo_utils::ibus::{IbusReceiver, IbusSender};
use holo_utils::policy::{MatchSets, Policy};
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(Debug, new)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channel.
    pub ibus_tx: IbusSender,
    // Sets of attributes used in policy match statements.
    #[new(default)]
    pub match_sets: MatchSets,
    // List of configured policies.
    #[new(default)]
    pub policies: BTreeMap<String, Policy>,
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
                Ok(_) = ibus_rx.recv() => {
                    // Ignore for now.
                }
            }
        }
    }
}

// ===== global functions =====

pub fn start(
    nb_provider_tx: NbProviderSender,
    ibus_tx: IbusSender,
    ibus_rx: IbusReceiver,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        let span = Master::debug_span("");
        let mut master = Master::new(nb_provider_tx, ibus_tx);

        // Run task main loop.
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
