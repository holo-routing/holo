//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![feature(let_chains)]

mod ibus;
mod interface;
mod netlink;
pub mod northbound;

use futures::stream::StreamExt;
use holo_northbound::{
    process_northbound_msg, NbDaemonReceiver, NbDaemonSender, NbProviderSender,
    ProviderBase,
};
use holo_protocol::InstanceShared;
use holo_utils::ibus::{IbusReceiver, IbusSender};
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::interface::Interfaces;
use crate::netlink::NetlinkMonitor;

#[derive(Debug)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channel.
    pub ibus_tx: IbusSender,
    // Shared data among all protocol instances.
    pub shared: InstanceShared,
    // Netlink socket.
    pub netlink_handle: rtnetlink::Handle,
    // List of interfaces.
    pub interfaces: Interfaces,
}

// ===== impl Master =====

impl Master {
    async fn run(
        &mut self,
        mut nb_rx: NbDaemonReceiver,
        mut ibus_rx: IbusReceiver,
        mut netlink_rx: NetlinkMonitor,
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
                    ibus::process_msg(self, msg).await;
                }
                Some((msg, _)) = netlink_rx.next() => {
                    netlink::process_msg(self, msg).await;
                }
            }
        }
    }
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    ibus_tx: IbusSender,
    ibus_rx: IbusReceiver,
    shared: InstanceShared,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        // Initialize netlink socket.
        let (netlink_handle, netlink_rx) = netlink::init().await;

        let mut master = Master {
            nb_tx,
            ibus_tx,
            shared,
            netlink_handle,
            interfaces: Default::default(),
        };

        // Fetch interface information from the kernel.
        netlink::start(&mut master).await;

        // Run task main loop.
        let span = Master::debug_span("");
        master
            .run(nb_daemon_rx, ibus_rx, netlink_rx)
            .instrument(span)
            .await;
    });

    nb_daemon_tx
}
