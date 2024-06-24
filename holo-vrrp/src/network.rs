//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{Sender, UnboundedReceiver};
use tokio::sync::mpsc::error::SendError;

use crate::error::IoError;
use crate::packet::VRRPPacket as Packet;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

pub(crate) fn socket_vrrp(_ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        todo!()
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_arp(_ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        todo!()
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
async fn send_packet_vrrp(
    _socket: &AsyncFd<Socket>,
    _src: IpAddr,
    _dst: IpAddr,
    _packet: Packet,
) -> Result<(), IoError> {
    todo!()
}

#[cfg(not(feature = "testing"))]
async fn send_packet_arp(
    _socket: &AsyncFd<Socket>,
    // TODO: add other params
) -> Result<(), IoError> {
    todo!()
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(msg) = net_tx_packetc.recv().await {
        match msg {
            NetTxPacketMsg::Vrrp { packet, src, dst } => {
                if let Err(error) =
                    send_packet_vrrp(&socket_vrrp, src, dst, packet).await
                {
                    error.log();
                }
            }
            NetTxPacketMsg::Arp {} => {
                if let Err(error) = send_packet_arp(&socket_arp).await {
                    error.log();
                }
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    _socket_vrrp: Arc<AsyncFd<Socket>>,
    _net_packet_rxp: Sender<NetRxPacketMsg>,
) -> Result<(), SendError<NetRxPacketMsg>> {
    // TODO: receive VRRP packets
    todo!()
}
