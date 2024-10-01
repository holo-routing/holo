//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![feature(let_chains)]

mod ibus;
mod netlink;
pub mod northbound;
mod rib;

use std::collections::BTreeMap;

use derive_new::new;
use holo_northbound::{
    NbDaemonReceiver, NbDaemonSender, NbProviderSender, ProviderBase,
    process_northbound_msg,
};
use holo_protocol::InstanceShared;
use holo_utils::bier::BierCfg;
use holo_utils::ibus::{IbusChannelsTx, IbusReceiver, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::InterfaceFlags;
use holo_utils::sr::SrCfg;
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::northbound::configuration::StaticRoute;
use crate::rib::{Birt, Rib};

pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channels.
    pub ibus_tx: IbusChannelsTx,
    // Shared data among all protocol instances.
    pub shared: InstanceShared,
    // Netlink socket.
    pub netlink_handle: rtnetlink::Handle,
    // List of interfaces.
    pub interfaces: BTreeMap<String, Interface>,
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

#[derive(Debug, new)]
pub struct Interface {
    pub ifname: String,
    pub ifindex: u32,
    pub flags: InterfaceFlags,
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
               Some(_) = self.rib.update_queue_rx.recv() => {
                   self.rib
                       .process_rib_update_queue(
                           &self.netlink_handle,
                       )
                       .await;
               }
               Some(_) = self.birt.update_queue_rx.recv() => {
                   self.birt
                       .process_birt_update_queue().await;
               }
            }
        }
    }
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    ibus_tx: IbusChannelsTx,
    ibus_rx: IbusReceiver,
    shared: InstanceShared,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        let mut master = Master {
            nb_tx,
            ibus_tx,
            shared: shared.clone(),
            netlink_handle: netlink::init(),
            interfaces: Default::default(),
            rib: Default::default(),
            static_routes: Default::default(),
            sr_config: Default::default(),
            bier_config: Default::default(),
            instances: Default::default(),
            birt: Default::default(),
        };

        // Request information about all interfaces addresses.
        ibus::request_addresses(&master.ibus_tx);

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
        let span = Master::debug_span("");
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
