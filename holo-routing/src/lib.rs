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
use holo_protocol::{event_recorder, spawn_protocol_task};
use holo_utils::ibus::{IbusReceiver, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::sr::SrCfg;
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(Debug, new)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channel.
    pub ibus_tx: IbusSender,
    // Event recorder configuration.
    pub event_recorder_config: event_recorder::Config,
    // Configuration data.
    #[new(default)]
    pub sr_config: SrCfg,
    // Protocol instances.
    #[new(default)]
    pub instances: BTreeMap<InstanceId, NbDaemonSender>,
}

#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, new, Ord)]
pub struct InstanceId {
    // Instance protocol.
    pub protocol: Protocol,
    // Instance name.
    pub name: String,
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
    event_recorder_config: event_recorder::Config,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        let span = Master::debug_span("");
        let mut master =
            Master::new(nb_provider_tx, ibus_tx, event_recorder_config);

        // Start BFD task.
        let name = "main".to_owned();
        let instance_id = InstanceId::new(Protocol::BFD, name.clone());
        let nb_daemon_tx = spawn_protocol_task::<holo_bfd::master::Master>(
            name,
            &master.nb_tx,
            &master.ibus_tx,
            Default::default(),
            Some(master.event_recorder_config.clone()),
        );
        master.instances.insert(instance_id, nb_daemon_tx);

        // Run task main loop.
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
