//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::Task;
use holo_utils::UnboundedSender;
use tokio::sync::mpsc;

use crate::error::IoError;
use crate::interface::{InterfaceSys, InterfaceView};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::{network, tasks};

#[derive(Debug)]
pub struct MacvlanInterface {
    // Interface name.
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
    // Interface raw sockets and Tx/Rx tasks.
    pub net: Option<MacvlanNet>,
}

#[derive(Debug)]
pub struct MacvlanNet {
    // Raw sockets.
    pub socket_vrrp_tx: Arc<AsyncFd<Socket>>,
    pub socket_vrrp_rx: Arc<AsyncFd<Socket>>,
    pub socket_arp: Arc<AsyncFd<Socket>>,
    // Network Tx/Rx tasks.
    _net_tx_task: Task<()>,
    _vrrp_net_rx_task: Task<()>,
    // Network Tx output channel.
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg>,
}

// ==== impl MacvlanInterface ====

impl MacvlanInterface {
    pub(crate) fn new(vrid: u8) -> Self {
        let name = format!("mvlan-vrrp-{}", vrid);
        Self {
            name,
            system: InterfaceSys::default(),
            net: None,
        }
    }
}

// ==== impl MacvlanNet ====

impl MacvlanNet {
    pub(crate) fn new(
        parent_iface: &InterfaceView,
        mvlan: &MacvlanInterface,
    ) -> Result<Self, IoError> {
        let instance_channels_tx = &parent_iface.tx;

        // Create raw sockets.
        let socket_vrrp_rx = network::socket_vrrp_rx(parent_iface)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;
        let socket_vrrp_tx = network::socket_vrrp_tx(mvlan)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;
        let socket_arp = network::socket_arp(&mvlan.name)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        // Start network Tx/Rx tasks.
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let net_tx_task = tasks::net_tx(
            socket_vrrp_tx.clone(),
            socket_arp.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let vrrp_net_rx_task = tasks::vrrp_net_rx(
            socket_vrrp_rx.clone(),
            &instance_channels_tx.protocol_input.vrrp_net_packet_tx,
        );

        Ok(Self {
            socket_vrrp_tx,
            socket_vrrp_rx,
            socket_arp,
            _net_tx_task: net_tx_task,
            _vrrp_net_rx_task: vrrp_net_rx_task,
            net_tx_packetp,
        })
    }
}
