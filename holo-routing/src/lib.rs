//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod birt;
mod dataplane;
mod ibus;
mod interface;
pub mod northbound;
mod rib;

use std::collections::BTreeMap;

use derive_new::new;
use futures::stream::{SelectAll, StreamExt};
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, process_northbound_msg,
};
use holo_protocol::InstanceShared;
use holo_utils::bier::BierCfg;
use holo_utils::ibus::{
    IbusChannelsTx, IbusClient, IbusClientId, IbusConnEvent, IbusConnReceiver,
    IbusConnStream, IbusMsg, IbusReceiver, IbusSender, connection_stream,
};
use holo_utils::protocol::Protocol;
use holo_utils::sr::SrCfg;
use holo_utils::task::Task;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tracing::debug_span;

use crate::birt::Birt;
use crate::dataplane::Dataplane;
use crate::interface::Interfaces;
use crate::northbound::configuration::StaticRoute;
use crate::rib::Rib;

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
    // RIB.
    pub rib: Rib,
    // Static routes.
    pub static_routes: BTreeMap<IpNetwork, StaticRoute>,
    // SR configuration data.
    pub sr_config: SrCfg,
    // BIER configuration data.
    pub bier_config: BierCfg,
    // Protocol instances.
    pub instances: BTreeMap<InstanceId, InstanceHandle>,
    // BIER Routing Table (BIRT)
    pub birt: Birt,
}

#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, new, Ord)]
pub struct InstanceId {
    // Instance protocol.
    pub protocol: Protocol,
    // Instance name.
    pub name: String,
}

#[derive(Debug, new)]
pub struct InstanceHandle {
    pub nb_tx: NbDaemonSender,
    pub ibus_tx: IbusSender,
}

#[derive(Debug)]
pub enum EventMsg {
    Northbound(Option<holo_northbound::api::daemon::Request>),
    Ibus { client: IbusClient, msg: IbusMsg },
    IbusDisconnect { id: IbusClientId },
    IbusNotification(IbusMsg),
    RibUpdate,
    BirtUpdate,
}

// ===== impl Master =====

impl Master {
    fn run(
        &mut self,
        nb_rx: NbDaemonReceiver,
        ibus_conn_rx: IbusConnReceiver,
        ibus_notif_rx: IbusReceiver,
        rib_update_queue_rx: UnboundedReceiver<()>,
        birt_update_queue_rx: UnboundedReceiver<()>,
    ) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator = event_aggregator(
            nb_rx,
            ibus_conn_rx,
            ibus_notif_rx,
            rib_update_queue_rx,
            birt_update_queue_rx,
            agg_tx,
        );

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
                EventMsg::IbusNotification(msg) => {
                    ibus::process_notification_msg(self, msg);
                }
                EventMsg::RibUpdate => {
                    self.rib.process_rib_update_queue(
                        &self.interfaces,
                        &self.dataplane,
                    );
                }
                EventMsg::BirtUpdate => {
                    self.birt.process_birt_update_queue(&self.interfaces);
                }
            }
        }
    }
}

// ===== helper functions =====

fn event_aggregator(
    mut nb_rx: NbDaemonReceiver,
    mut ibus_conn_rx: IbusConnReceiver,
    mut ibus_notif_rx: IbusReceiver,
    mut rib_update_queue_rx: UnboundedReceiver<()>,
    mut birt_update_queue_rx: UnboundedReceiver<()>,
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
                Some(msg) = ibus_notif_rx.recv() => {
                    EventMsg::IbusNotification(msg)
                }
                Some(_) = rib_update_queue_rx.recv() => {
                    EventMsg::RibUpdate
                }
                Some(_) = birt_update_queue_rx.recv() => {
                    EventMsg::BirtUpdate
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
    let (ibus_notif_tx, ibus_notif_rx) = mpsc::unbounded_channel();
    let ibus_tx = IbusChannelsTx::with_client(ibus_tx, ibus_notif_tx);
    let (rib_update_queue_tx, rib_update_queue_rx) = mpsc::unbounded_channel();
    let (birt_update_queue_tx, birt_update_queue_rx) =
        mpsc::unbounded_channel();

    tokio::task::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            dataplane: dataplane::Backend::init(),
            shared: shared.clone(),
            interfaces: Default::default(),
            rib: Rib::new(rib_update_queue_tx),
            static_routes: Default::default(),
            sr_config: Default::default(),
            bier_config: Default::default(),
            instances: Default::default(),
            birt: Birt::new(birt_update_queue_tx),
        };

        // Request information about all interfaces addresses.
        ibus::request_addresses(&master.ibus_tx);

        // Purge stale routes potentially left behind by a previous Holo
        // instance.
        master.dataplane.purge_stale_routes().await;

        // Start BFD task.
        #[cfg(feature = "bfd")]
        {
            use holo_protocol::spawn_protocol_task;

            let name = "main".to_owned();
            let instance_id = InstanceId::new(Protocol::BFD, name.clone());
            let (ibus_instance_tx, ibus_instance_rx) =
                mpsc::unbounded_channel();
            let nb_daemon_tx = spawn_protocol_task::<holo_bfd::master::Master>(
                name,
                &master.nb_tx,
                &master.ibus_tx,
                ibus_instance_tx.clone(),
                ibus_instance_rx,
                Default::default(),
                shared,
            );
            let instance = InstanceHandle::new(nb_daemon_tx, ibus_instance_tx);
            master.instances.insert(instance_id, instance);
        }

        // Run task main loop.
        tokio::task::spawn_blocking(move || {
            let span = debug_span!("routing");
            let _span_guard = span.enter();
            master.run(
                nb_daemon_rx,
                ibus_conn_rx,
                ibus_notif_rx,
                rib_update_queue_rx,
                birt_update_queue_rx,
            );

            // Uninstall all routes before exiting.
            master.rib.route_uninstall_all(&master.dataplane);
            master.dataplane.flush();
        });
    });

    nb_daemon_tx
}
