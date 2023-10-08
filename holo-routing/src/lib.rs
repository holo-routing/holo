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
use holo_protocol::{event_recorder, spawn_protocol_task, InstanceShared};
use holo_utils::ibus::{IbusMsg, IbusReceiver, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::sr::SrCfg;
use holo_utils::Database;
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(new)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channel.
    pub ibus_tx: IbusSender,
    // Shared data among all protocol instances.
    pub shared: InstanceShared,
    // Event recorder configuration.
    pub event_recorder_config: event_recorder::Config,
    // SR configuration data.
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
                Ok(msg) = ibus_rx.recv() => {
                    process_ibus_msg(self, msg);
                }
            }
        }
    }
}

fn process_ibus_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        IbusMsg::KeychainUpd(keychain) => {
            // Update the local copy of the keychain.
            master
                .shared
                .keychains
                .insert(keychain.name.clone(), keychain.clone());
        }
        IbusMsg::KeychainDel(keychain_name) => {
            // Remove the local copy of the keychain.
            master.shared.keychains.remove(&keychain_name);
        }
        IbusMsg::PolicyMatchSetsUpd(match_sets) => {
            // Update the local copy of the policy match sets.
            master.shared.policy_match_sets = match_sets;
        }
        IbusMsg::PolicyUpd(policy) => {
            // Update the local copy of the policy definition.
            master
                .shared
                .policies
                .insert(policy.name.clone(), policy.clone());
        }
        IbusMsg::PolicyDel(policy_name) => {
            // Remove the local copy of the policy definition.
            master.shared.policies.remove(&policy_name);
        }
        // Ignore other events.
        _ => {}
    }
}

// ===== global functions =====

pub fn start(
    nb_provider_tx: NbProviderSender,
    ibus_tx: IbusSender,
    ibus_rx: IbusReceiver,
    db: Database,
    event_recorder_config: event_recorder::Config,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        let shared = InstanceShared {
            db: Some(db.clone()),
            ..Default::default()
        };
        let mut master = Master::new(
            nb_provider_tx,
            ibus_tx,
            shared.clone(),
            event_recorder_config,
        );

        // Start BFD task.
        let name = "main".to_owned();
        let instance_id = InstanceId::new(Protocol::BFD, name.clone());
        let nb_daemon_tx = spawn_protocol_task::<holo_bfd::master::Master>(
            name,
            &master.nb_tx,
            &master.ibus_tx,
            Default::default(),
            shared,
            Some(master.event_recorder_config.clone()),
        );
        master.instances.insert(instance_id, nb_daemon_tx);

        // Run task main loop.
        let span = Master::debug_span("");
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
