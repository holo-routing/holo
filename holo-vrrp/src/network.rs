//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use libc::ETH_P_ALL;
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;

use crate::error::IoError;
use crate::packet::VrrpPacket;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

pub fn socket_vrrp(_ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112)))
        })?;
        socket.set_broadcast(true)?;
        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_arp(_ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // TODO
        let socket = capabilities::raise(|| {
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112)))
        })?;
        socket.set_broadcast(true)?;
        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub async fn send_packet_vrrp(
    socket: &AsyncFd<Socket>,
    _src: IpAddr,
    _dst: IpAddr,
    packet: VrrpPacket,
) -> Result<usize, IoError> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    let buf: &[u8] = &packet.encode();
    let saddr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 8), 0);

    socket
        .async_io(tokio::io::Interest::WRITABLE, |sock| {
            sock.send_to(
                &buf, 
                &saddr.into()
            )
            .map_err(|errno| errno.into())
        })
        .await
        .map_err(IoError::SendError)
    
}

#[cfg(not(feature = "testing"))]
async fn send_packet_arp(
    _socket: &AsyncFd<Socket>,
    // TODO: add other params
) -> Result<(), IoError> {
    // TODO
    Ok(())
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
    Ok(())
}
