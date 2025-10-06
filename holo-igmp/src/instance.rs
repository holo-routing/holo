//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;

use crate::debug::Debug;
use crate::error::Error;
use crate::interface::Interface;
use crate::network::IGMP_IP_PROTO;
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus};
use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::capabilities;
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{AsyncFd, RawSocketExt, Socket};
use std::io;
use std::mem::MaybeUninit;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: InstanceState,
    // Instance interfaces.
    pub interfaces: BTreeMap<String, Interface>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
    // kernel mcast socket
    pub mcast_sock: Arc<AsyncFd<Socket>>,
}

#[derive(Debug, Default)]
pub struct InstanceSys {}

#[derive(Debug, Default)]
pub struct InstanceState {
    pub statistics: Statistics,
}

#[derive(Debug, Default)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub errors: ErrorStatistics,
    pub msgs_rcvd: MessageStatistics,
    pub msgs_sent: MessageStatistics,
}

#[derive(Debug, Default)]
pub struct ErrorStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
    pub checksum: u64,
    pub too_short: u64,
}

#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // Packet Rx event.
    pub net_packet_rx: Sender<NetRxPacketMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // Packet Rx event.
    pub net_packet_rx: Receiver<NetRxPacketMsg>,
}

pub struct InstanceView<'a> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState,
    pub tx: &'a InstanceChannelsTx<Instance>,
    pub shared: &'a InstanceShared,
    pub mcast_sock: &'a Arc<AsyncFd<Socket>>,
}

// ===== kernel multicast helpers =====
pub async fn recv_task_plain(
    async_sock: Arc<AsyncFd<Socket>>,
) -> io::Result<()> {
    loop {
        let mut guard = async_sock.readable().await?;

        let result = guard.try_io(|inner| {
            let mut buf: [MaybeUninit<u8>; 1024] =
                [MaybeUninit::uninit(); 1024];
            match inner.get_ref().recv(&mut buf) {
                Ok(n) => Ok("lets decode it"),
                Err(e) => Err(e),
            }
        });
    }
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn get_interface(
        &mut self,
        ifname: &str,
    ) -> Option<(InstanceView<'_>, &mut Interface)> {
        let iface = self.interfaces.get_mut(ifname)?;
        let instance = InstanceView {
            name: &self.name,
            system: &self.system,
            config: &self.config,
            state: &mut self.state,
            tx: &self.tx,
            shared: &self.shared,
            mcast_sock: &self.mcast_sock,
        };
        Some((instance, iface))
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::IGMP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        use socket2::{Domain, Protocol, Type};
        // Create raw socket.
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(IGMP_IP_PROTO)),
            )
        })
        .expect("failed to create IGMP raw socket");
        socket
            .set_nonblocking(true)
            .expect("failed to set IGMP socket non-blocking");
        socket
            .set_ipv4_pktinfo(true)
            .expect("failed to set IGMP socket IPv4 packet info");
        socket
            .set_mrt_init(true)
            .expect("failed to set IGMP socket MRT_INIT");

        let mcast_sock = Arc::new(AsyncFd::new(socket).unwrap());

        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: Default::default(),
            interfaces: Default::default(),
            tx,
            shared,
            mcast_sock,
        }
    }

    fn init(&mut self) {
        // TODO: anything to do here?

        // fire up a task to listen on the mcast socket
        let recv_handle = {
            let sock_clone = Arc::clone(&self.mcast_sock);
            tokio::spawn(async move {
                if let Err(e) = recv_task_plain(sock_clone).await {}
            })
        };
    }

    fn shutdown(self) {
        // TODO: stop IGMP on all interfaces.

        // TODO: cleanup the running mcast handle task.
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = process_protocol_msg(self, msg) {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (net_packet_rxp, net_packet_rxc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            net_packet_rx: net_packet_rxp,
        };
        let rx = ProtocolInputChannelsRx {
            net_packet_rx: net_packet_rxc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPacket)
            }
        }
    }
}

// ===== helper functions =====

fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    Debug::IbusRx(&msg).log();

    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg)?;
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut Instance,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received network packet.
        ProtocolInputMsg::NetRxPacket(msg) => {
            events::process_packet(instance, msg.ifname, msg.src, msg.packet)?;
        }
    }

    Ok(())
}
