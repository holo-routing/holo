//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod ibus;
mod interface;
mod netlink;
mod northbound;

use futures::stream::StreamExt;
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, ProviderBase,
    process_northbound_msg,
};
use holo_protocol::InstanceShared;
use holo_utils::ibus::{IbusChannelsTx, IbusMsg, IbusReceiver};
use holo_utils::task::Task;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::RouteNetlinkMessage;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

use crate::interface::Interfaces;
use crate::mpsc::UnboundedSender;
use crate::netlink::{NetlinkMonitor, NetlinkRequest};

#[derive(Debug)]
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
}

#[derive(Debug)]
pub enum EventMsg {
    Northbound(Option<holo_northbound::api::daemon::Request>),
    Ibus(IbusMsg),
    Netlink(NetlinkMessage<RouteNetlinkMessage>),
}

// ===== impl Master =====

impl Master {
    fn run(
        &mut self,
        nb_rx: NbDaemonReceiver,
        ibus_rx: IbusReceiver,
        netlink_rx: NetlinkMonitor,
    ) {
        // Spawn event aggregator task.
        let (agg_tx, mut agg_rx) = mpsc::channel(4);
        let _event_aggregator =
            event_aggregator(nb_rx, ibus_rx, netlink_rx, agg_tx);

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
                EventMsg::Netlink(msg) => {
                    netlink::process_msg(self, msg);
                }
            }
        }
    }
}

// ===== helper functions =====

fn event_aggregator(
    mut nb_rx: NbDaemonReceiver,
    mut ibus_rx: IbusReceiver,
    mut netlink_rx: NetlinkMonitor,
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
                Some((msg, _)) = netlink_rx.next() => {
                    EventMsg::Netlink(msg)
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

    tokio::task::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            netlink_tx: netlink_txp,
            shared,
            interfaces: Default::default(),
        };

        // Initialize netlink socket.
        let (netlink_handle, netlink_rx) = netlink::init();

        // Fetch interface information from the kernel.
        netlink::start(&mut master, &netlink_handle).await;

        // Start netlink Tx task.
        tokio::task::spawn(async move {
            while let Some(request) = netlink_txc.recv().await {
                request.execute(&netlink_handle).await;
            }
        });

        tokio::task::spawn_blocking(move || {
            // Run task main loop.
            let span = Master::debug_span("");
            let _span_guard = span.enter();
            master.run(nb_daemon_rx, ibus_rx, netlink_rx);
        });
    });

    nb_daemon_tx
}
