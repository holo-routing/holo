//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use holo_utils::ip::{IpAddrKind, SocketAddrKind};
use holo_utils::socket::UdpSocket;
use holo_utils::{Sender, UnboundedReceiver};
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;

use crate::error::{Error, IoError};
use crate::packet::PduVersion;
use crate::tasks::messages::input::UdpRxPduMsg;
use crate::tasks::messages::output::UdpTxPduMsg;
use crate::version::Version;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SendDestination<S: Into<SocketAddr>> {
    Multicast(u32),
    Unicast(S),
}

// RIP version-specific code.
#[async_trait]
pub trait NetworkVersion {
    const UDP_PORT: u16;

    // Create a RIP socket.
    fn socket(ifname: &str) -> Result<UdpSocket, std::io::Error>;

    // Join the RIP multicast group.
    fn join_multicast(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Leave the RIP multicast group.
    fn leave_multicast(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Set the interface for sending outbound multicast packets.
    fn set_multicast_if(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> std::io::Result<()>;

    // Return RIP multicast address.
    fn multicast_sockaddr() -> &'static SocketAddr;
}

// ===== global functions =====

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet<V>(
    socket: &UdpSocket,
    pdu: V::Pdu,
    dst: SendDestination<V::SocketAddr>,
) -> Result<(), std::io::Error>
where
    V: Version,
{
    // Encode PDU.
    let buf = pdu.encode();

    // Send packet.
    match dst {
        SendDestination::Multicast(ifindex) => {
            // Set outgoing interface.
            V::set_multicast_if(socket, ifindex).unwrap();

            socket.send_to(&buf, V::multicast_sockaddr()).await?;
        }
        SendDestination::Unicast(sockaddr) => {
            socket.send_to(&buf, sockaddr).await?;
        }
    }

    Ok(())
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop<V>(
    socket: Arc<UdpSocket>,
    mut udp_tx_pduc: UnboundedReceiver<UdpTxPduMsg<V>>,
) where
    V: Version,
{
    while let Some(UdpTxPduMsg { dst, pdu }) = udp_tx_pduc.recv().await {
        if let Err(error) = send_packet::<V>(&socket, pdu, dst).await {
            IoError::UdpSendError(error).log();
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop<V>(
    socket: Arc<UdpSocket>,
    udp_pdu_rxp: Sender<UdpRxPduMsg<V>>,
) -> Result<(), SendError<UdpRxPduMsg<V>>>
where
    V: Version,
{
    let mut buf = [0; 16384];

    loop {
        // Receive data from the network.
        let (num_bytes, src) = match socket.recv_from(&mut buf).await {
            Ok((num_bytes, src)) => (num_bytes, src),
            Err(error) => {
                IoError::UdpRecvError(error).log();
                continue;
            }
        };

        // Validate packet's source address.
        let src = V::SocketAddr::get(src).unwrap();
        let src_ip = *src.ip();
        if !src_ip.is_usable() {
            Error::<V>::UdpInvalidSourceAddr(src_ip).log();
            continue;
        }

        // Decode packet.
        let pdu = V::Pdu::decode(&buf[0..num_bytes]);
        let msg = UdpRxPduMsg { src, pdu };
        udp_pdu_rxp.send(msg).await?;
    }
}
