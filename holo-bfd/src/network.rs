//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{self, AtomicU64};
use std::sync::Arc;

use holo_utils::bfd::PathType;
use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::socket::{UdpSocket, UdpSocketExt};
use holo_utils::{capabilities, Sender};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::error::SendError;

use crate::error::{Error, IoError};
use crate::packet::Packet;
use crate::tasks::messages::input::UdpRxPacketMsg;

pub const PORT_DST_SINGLE_HOP: u16 = 3784;
pub const PORT_DST_ECHO: u16 = 3785;
pub const PORT_DST_MULTIHOP: u16 = 4784;
pub const PORT_SRC_RANGE: std::ops::RangeInclusive<u16> = 49152..=65535;

// Ancillary data about a received packet.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum PacketInfo {
    IpSingleHop { src: SocketAddr },
    IpMultihop { src: IpAddr, dst: IpAddr, ttl: u8 },
}

pub(crate) fn socket_rx(
    path_type: PathType,
    af: AddressFamily,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create socket.
        let port = match path_type {
            PathType::IpSingleHop => PORT_DST_SINGLE_HOP,
            PathType::IpMultihop => PORT_DST_MULTIHOP,
        };
        let addr = IpAddr::unspecified(af);
        let sockaddr = SocketAddr::from((addr, port));
        let socket =
            capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr))?;

        // Set socket options.
        match path_type {
            PathType::IpSingleHop => match af {
                AddressFamily::Ipv4 => {
                    socket.set_ipv4_minttl(255)?;
                }
                AddressFamily::Ipv6 => {
                    socket.set_min_hopcount_v6(255)?;
                }
            },
            PathType::IpMultihop => {
                // NOTE: since the same Rx socket is used for all multihop
                // sessions, incoming TTL checking should be done in the
                // userspace given that different peers might have different TTL
                // settings.
            }
        }

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(UdpSocket {})
    }
}

pub(crate) fn socket_tx(
    af: AddressFamily,
    addr: IpAddr,
    ttl: u8,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create socket.
        //
        // RFC 5881 says the following:
        // "The source port MUST be in the range 49152 through 65535.  The same
        // UDP source port number MUST be used for all BFD Control packets
        // associated with a particular session.  The source port number SHOULD
        // be unique among all BFD sessions on the system".
        //
        // For simplicity's sake, let's use 49152 as the source port for all
        // sessions. This shouldn't affect protocol operation, as the
        // remote peer should be able to match the incoming BFD packets
        // to the correct session regardless of the source port number.
        //
        // In any case, a separate Tx socket is required for each session since
        // they can be bound to different addresses.
        let port = *PORT_SRC_RANGE.start();
        let sockaddr = SocketAddr::from((addr, port));
        let socket =
            capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr))?;

        // Set socket options.
        match af {
            AddressFamily::Ipv4 => {
                socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_ttl(ttl as u32)?;
            }
            AddressFamily::Ipv6 => {
                socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_unicast_hops_v6(ttl as u32)?;
            }
        }

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(UdpSocket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet(
    socket: Arc<UdpSocket>,
    sockaddr: SocketAddr,
    packet: Packet,
    tx_packet_count: Arc<AtomicU64>,
    tx_error_count: Arc<AtomicU64>,
) {
    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    match socket.send_to(&buf, sockaddr).await {
        Ok(_) => {
            tx_packet_count.fetch_add(1, atomic::Ordering::Relaxed);
        }
        Err(error) => {
            IoError::UdpSendError(error).log();
            tx_error_count.fetch_add(1, atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<UdpSocket>,
    path_type: PathType,
    udp_packet_rxp: Sender<UdpRxPacketMsg>,
) -> Result<(), SendError<UdpRxPacketMsg>> {
    let mut buf = [0; 1024];

    loop {
        // Receive data from the network.
        let (_, src) = match socket.recv_from(&mut buf).await {
            Ok((num_bytes, src)) => (num_bytes, src),
            Err(error) => {
                IoError::UdpRecvError(error).log();
                continue;
            }
        };

        // Validate packet's source address.
        if !src.ip().is_usable() {
            Error::UdpInvalidSourceAddr(src.ip()).log();
            continue;
        }

        // Get packet's ancillary data.
        let packet_info = match path_type {
            PathType::IpSingleHop => PacketInfo::IpSingleHop { src },
            PathType::IpMultihop => {
                let src = src.ip();
                // TODO: get packet's destination using IP_PKTINFO/IPV6_PKTINFO.
                let dst = src;
                // TODO: get packet's TTL using IP_RECVTTL/IPV6_HOPLIMIT.
                let ttl = 255;
                PacketInfo::IpMultihop { src, dst, ttl }
            }
        };

        // Decode packet, dropping malformed ones.
        let packet = match Packet::decode(&buf) {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        // Notify the BFD main task about the received packet.
        let msg = UdpRxPacketMsg {
            packet_info,
            packet,
        };
        udp_packet_rxp.send(msg).await?;
    }
}
