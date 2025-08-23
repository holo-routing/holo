//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod birt;
mod ibus;
mod interface;
mod netlink;
mod northbound;
mod rib;
mod sysctl;

use std::collections::BTreeMap;

use derive_new::new;
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, ProviderBase,
    process_northbound_msg,
};
use holo_protocol::InstanceShared;
use holo_utils::bier::BierCfg;
use holo_utils::ibus::{IbusChannelsTx, IbusMsg, IbusReceiver, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::sr::SrCfg;
use holo_utils::task::Task;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tracing::warn;

use crate::birt::Birt;
use crate::interface::Interfaces;
use crate::netlink::NetlinkRequest;
use crate::northbound::configuration::StaticRoute;
use crate::rib::Rib;

pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // Netlink Tx channel.
    pub netlink_tx: UnboundedSender<NetlinkRequest>,
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
    Ibus(IbusMsg),
    RibUpdate,
    BirtUpdate,
}

// ===== impl Master =====

impl Master {
    fn run(
        &mut self,
        nb_rx: NbDaemonReceiver,
        ibus_rx: IbusReceiver,
        rib_update_queue_rx: UnboundedReceiver<()>,
        birt_update_queue_rx: UnboundedReceiver<()>,
    ) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator = event_aggregator(
            nb_rx,
            ibus_rx,
            rib_update_queue_rx,
            birt_update_queue_rx,
            agg_tx,
        );

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
                EventMsg::RibUpdate => {
                    self.rib.process_rib_update_queue(
                        &self.interfaces,
                        &self.netlink_tx,
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
    mut ibus_rx: IbusReceiver,
    mut rib_update_queue_rx: UnboundedReceiver<()>,
    mut birt_update_queue_rx: UnboundedReceiver<()>,
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
    ibus_tx: IbusChannelsTx,
    ibus_rx: IbusReceiver,
    shared: InstanceShared,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);
    let (netlink_txp, mut netlink_txc) = mpsc::unbounded_channel();
    let (rib_update_queue_tx, rib_update_queue_rx) = mpsc::unbounded_channel();
    let (birt_update_queue_tx, birt_update_queue_rx) =
        mpsc::unbounded_channel();

    tokio::task::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            netlink_tx: netlink_txp,
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

        // Enable IPv4 and IPv6 forwarding in the kernel.
        if let Err(error) = sysctl::ipv4_forwarding("1") {
            warn!(%error, "failed to enable IPv4 forwarding");
        }
        if let Err(error) = sysctl::ipv6_forwarding("1") {
            warn!(%error, "failed to enable IPv6 forwarding");
        }

        // Set the maximum number of MPLS labels available for forwarding.
        if let Err(error) = sysctl::mpls_platform_labels("1048575") {
            warn!(%error, "failed to set MPLS platform labels");
        }

        // Initialize netlink socket.
        let netlink_handle = netlink::init();

        // Purge stale routes potentially left behind by a previous Holo
        // instance.
        netlink::purge_stale_routes(&netlink_handle).await;

        // Start netlink Tx task.
        let netlink_tx_task = tokio::task::spawn(async move {
            while let Some(request) = netlink_txc.recv().await {
                request.execute(&netlink_handle).await;
            }
        });

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
            let span = Master::debug_span("");
            let _span_guard = span.enter();
            master.run(
                nb_daemon_rx,
                ibus_rx,
                rib_update_queue_rx,
                birt_update_queue_rx,
            );

            // Uninstall all routes before exiting.
            master.rib.route_uninstall_all(&master.netlink_tx);
            drop(master.netlink_tx);
            let _ = tokio::runtime::Handle::current().block_on(netlink_tx_task);
        });
    });

    nb_daemon_tx
}
