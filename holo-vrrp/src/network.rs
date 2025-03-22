//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BufMut;
use holo_utils::socket::{AsyncFd, LinkAddrExt, Socket, SocketExt};
use holo_utils::{Sender, UnboundedReceiver, capabilities};
use libc::ETH_P_ARP;
use nix::sys::socket::{self, LinkAddr, SockaddrIn};
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;

use crate::consts::{VRRP_MULTICAST_ADDRESS, VRRP_PROTO_NUMBER};
use crate::debug::Debug;
use crate::error::IoError;
use crate::instance::InstanceMacvlan;
use crate::interface::InterfaceView;
use crate::packet::{ArpHdr, EthernetHdr, Ipv4Hdr, VrrpHdr, VrrpPacket};
use crate::tasks::messages::input::VrrpNetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

// ===== global functions =====

pub(crate) fn socket_vrrp_tx(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_multicast_ifindex_v4(mvlan.system.ifindex.unwrap())?;
        socket.set_header_included_v4(true)?;
        socket.set_multicast_ttl_v4(255)?;
        socket.set_tos(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;
        capabilities::raise(|| {
            socket.bind_device(Some(mvlan.name.as_bytes()))
        })?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_vrrp_rx(
    interface: &InterfaceView<'_>,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        capabilities::raise(|| {
            socket.bind_device(Some(interface.name.as_bytes()))
        })?;
        socket.set_nonblocking(true)?;
        socket.join_multicast_v4(
            &VRRP_MULTICAST_ADDRESS,
            &interface.system.addresses.first().unwrap().ip(),
        )?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_arp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(ETH_P_ARP)),
            )
        })?;
        capabilities::raise(|| socket.bind_device(Some(ifname.as_bytes())))?;
        socket.set_broadcast(true)?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
async fn send_packet_vrrp(
    socket: &AsyncFd<Socket>,
    packet: VrrpPacket,
) -> Result<usize, IoError> {
    Debug::PacketTx(&packet.vrrp).log();

    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: SockaddrIn =
        std::net::SocketAddrV4::new(VRRP_MULTICAST_ADDRESS, 0).into();
    socket
        .async_io(tokio::io::Interest::WRITABLE, |socket| {
            socket::sendmsg(
                socket.as_raw_fd(),
                &iov,
                &[],
                socket::MsgFlags::empty(),
                Some(&sockaddr),
            )
            .map_err(|errno| errno.into())
        })
        .await
        .map_err(IoError::SendError)
}

#[cfg(not(feature = "testing"))]
async fn send_packet_arp(
    socket: &AsyncFd<Socket>,
    vrid: u8,
    ifindex: u32,
    eth_hdr: EthernetHdr,
    arp_hdr: ArpHdr,
) -> Result<usize, IoError> {
    Debug::ArpTx(vrid, &arp_hdr.sender_proto_address).log();

    // Encode packet.
    let mut buf = eth_hdr.encode();
    buf.put(arp_hdr.encode());

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr =
        LinkAddr::new(libc::ETH_P_ARP as u16, ifindex, Some(eth_hdr.dst_mac));
    socket
        .async_io(tokio::io::Interest::WRITABLE, |socket| {
            socket::sendmsg(
                socket.as_raw_fd(),
                &iov,
                &[],
                socket::MsgFlags::empty(),
                Some(&sockaddr),
            )
            .map_err(|errno| errno.into())
        })
        .await
        .map_err(IoError::SendError)
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(msg) = net_tx_packetc.recv().await {
        match msg {
            NetTxPacketMsg::Vrrp { packet } => {
                if let Err(error) = send_packet_vrrp(&socket_vrrp, packet).await
                {
                    error.log();
                }
            }
            NetTxPacketMsg::Arp {
                vrid,
                ifindex,
                eth_hdr,
                arp_hdr,
            } => {
                if let Err(error) = send_packet_arp(
                    &socket_arp,
                    vrid,
                    ifindex,
                    eth_hdr,
                    arp_hdr,
                )
                .await
                {
                    error.log();
                }
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn vrrp_read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    let mut buf = [0u8; 16384];
    loop {
        match socket_vrrp
            .async_io(tokio::io::Interest::READABLE, |socket| {
                match socket::recv(
                    socket.as_raw_fd(),
                    &mut buf,
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        let data = &buf[0..msg];

                        // Since IP header length is given in number of words
                        // (4 bytes per word), we multiply by 4 to get the actual
                        // number of bytes.
                        let ip_header_len = ((data[0] & 0x0f) * 4) as usize;

                        let ip_pkt =
                            Ipv4Hdr::decode(&data[0..ip_header_len]).unwrap();
                        let vrrp_pkt = VrrpHdr::decode(&data[ip_header_len..]);
                        Ok((ip_pkt.src_address, vrrp_pkt))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, vrrp_pkt)) => {
                let msg = VrrpNetRxPacketMsg {
                    src,
                    packet: vrrp_pkt,
                };
                vrrp_net_packet_rxp.send(msg).await.unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // Retry if the syscall was interrupted (EINTR).
                continue;
            }
            Err(error) => {
                IoError::RecvError(error).log();
            }
        }
    }
}
