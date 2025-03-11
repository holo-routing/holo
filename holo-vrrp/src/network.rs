//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::io::{IoSlice, IoSliceMut};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use holo_utils::ip::AddressFamily;
use holo_utils::socket::{AsyncFd, RawSocketExt, Socket, SocketExt};
use holo_utils::{Sender, UnboundedReceiver, capabilities};
use internet_checksum::Checksum;
use ipnetwork::IpNetwork;
use libc::{AF_PACKET, ETH_P_ARP, ETH_P_IPV6};
use nix::sys::socket::{self, LinkAddr, SockaddrIn, SockaddrIn6, SockaddrLike};
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;

use crate::consts::{
    VRRP_PROTO_NUMBER, VRRP_V2_MULTICAST_ADDRESS, VRRP_V3_MULTICAST_ADDRESS,
};
use crate::debug::Debug;
use crate::error::IoError;
use crate::instance::{InstanceMacvlan, generate_solicitated_addr};
use crate::interface::InterfaceView;
use crate::packet::{
    ArpHdr, EthernetHdr, Ipv6Hdr, NeighborAdvertisement, Vrrp4Packet,
    Vrrp6Packet, VrrpHdr,
};
use crate::tasks::messages::input::VrrpNetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

// ===== global functions =====

pub(crate) fn socket_vrrp_tx4(
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
        socket.set_header_included(true)?;
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

pub(crate) fn socket_vrrp_tx6(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_multicast_ifindex_v6(mvlan.system.ifindex.unwrap())?;
        socket.set_ipv6_checksum(6)?;
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

pub(crate) fn socket_vrrp_rx4(
    interface: &InterfaceView,
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
        if let Some(addr) = &interface.system.addresses.first()
            && let IpNetwork::V4(v4_net) = addr
        {
            socket
                .join_multicast_v4(&VRRP_V2_MULTICAST_ADDRESS, &v4_net.ip())?;
        }

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_vrrp_rx6(
    interface: &InterfaceView,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        capabilities::raise(|| {
            socket.bind_device(Some(interface.name.as_bytes()))
        })?;
        socket.set_nonblocking(true)?;
        socket.join_multicast_v6(
            &VRRP_V3_MULTICAST_ADDRESS,
            interface.system.ifindex.unwrap(),
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

/// Network Advertisement socket
pub(crate) fn socket_nadv(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(ETH_P_IPV6)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;

        // Compute and join the Solicited-Node multicast address [RFC4291] for
        for addr in &mvlan.system.addresses {
            if let IpNetwork::V6(addr) = addr {
                // solicitated-node multicast address
                let sol_addr = generate_solicitated_addr(addr.ip());
                socket.join_multicast_v6(
                    &sol_addr,
                    mvlan.system.ifindex.unwrap(),
                )?;
            }
        }
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

/// Sends VRRP packets for IPV4 virtual addresses.
#[cfg(not(feature = "testing"))]
async fn send_packet_vrrp4(
    socket: &AsyncFd<Socket>,
    packet: Vrrp4Packet,
) -> Result<usize, IoError> {
    Debug::PacketTx(&packet.vrrp).log();

    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: SockaddrIn =
        std::net::SocketAddrV4::new(VRRP_V2_MULTICAST_ADDRESS, 0).into();
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

/// Sends VRRP packets for IPV6 virtual addresses.
#[cfg(not(feature = "testing"))]
async fn send_packet_vrrp6(
    socket: &AsyncFd<Socket>,
    packet: Vrrp6Packet,
) -> Result<usize, IoError> {
    Debug::PacketTx(&packet.vrrp).log();

    // Encode packet.
    let buf = packet.vrrp.encode();

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: SockaddrIn6 =
        std::net::SocketAddrV6::new(VRRP_V3_MULTICAST_ADDRESS, 0, 0, 0).into();

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

// send a neighbor advertisement
#[cfg(not(feature = "testing"))]
async fn send_packet_nadv(
    socket: &AsyncFd<Socket>,
    vrid: u8,
    ifindex: u32,
    eth_hdr: EthernetHdr,
    ip_hdr: Ipv6Hdr,
    adv_hdr: NeighborAdvertisement,
) -> Result<usize, IoError> {
    Debug::NeighborAdvertisementTx(vrid, &ip_hdr.source_address).log();

    // collect relevant data for checksum
    let mut check = Checksum::new();
    check.add_bytes(&ip_hdr.pseudo_header());
    check.add_bytes(&adv_hdr.encode());

    // Max size of a neighbor advertisement
    let mut buf = BytesMut::with_capacity(526);
    buf.put(eth_hdr.encode());
    buf.put(ip_hdr.encode());
    buf.put(adv_hdr.encode());
    buf[40..42].copy_from_slice(&check.checksum());

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let mut sll = libc::sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_IPV6 as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };
    sll.sll_addr[..6].copy_from_slice(&eth_hdr.dst_mac);
    let sll_len = size_of_val(&sll) as libc::socklen_t;
    let sockaddr = unsafe {
        LinkAddr::from_raw(&sll as *const _ as *const _, Some(sll_len))
    }
    .unwrap();
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
                if let Err(error) =
                    send_packet_vrrp4(&socket_vrrp, packet).await
                {
                    error.log();
                }
            }
            NetTxPacketMsg::Vrrp6 { packet } => {
                if let Err(error) =
                    send_packet_vrrp6(&socket_vrrp, packet).await
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

            // Neighbor Advertisement
            NetTxPacketMsg::NAdv {
                vrid,
                ifindex,
                eth_hdr,
                ip_hdr,
                nadv_hdr,
            } => {
                if let Err(error) = send_packet_nadv(
                    &socket_arp,
                    vrid,
                    ifindex,
                    eth_hdr,
                    ip_hdr,
                    nadv_hdr,
                )
                .await
                {
                    error.log()
                }
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
fn get_packet_src(sa: Option<&socket::SockaddrStorage>) -> Option<SocketAddr> {
    sa.and_then(|sa| {
        sa.as_sockaddr_in()
            .map(|sa| SocketAddrV4::from(*sa).into())
            .or_else(|| {
                sa.as_sockaddr_in6()
                    .map(|sa| SocketAddrV6::from(*sa).into())
            })
    })
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
    af: AddressFamily,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    let mut buf = [0u8; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = match af {
        AddressFamily::Ipv4 => {
            nix::cmsg_space!(libc::in_pktinfo)
        }

        AddressFamily::Ipv6 => {
            nix::cmsg_space!(libc::in6_pktinfo)
        }
    };

    loop {
        match socket_vrrp
            .async_io(tokio::io::Interest::READABLE, |socket| {
                match socket::recvmsg(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        let src = get_packet_src(msg.address.as_ref());
                        Ok((src, msg.bytes))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, bytes)) => match src {
                Some(addr) => {
                    let addr = addr.ip();
                    let mut buf: &[u8] =
                        &Bytes::copy_from_slice(iov[0].deref());
                    if let AddressFamily::Ipv4 = af {
                        buf = &buf[20..bytes];
                    }

                    let vrrp_pkt = VrrpHdr::decode(buf, af);

                    let msg = VrrpNetRxPacketMsg {
                        src: addr,
                        packet: vrrp_pkt,
                    };
                    vrrp_net_packet_rxp.send(msg).await.unwrap();
                }
                None => {
                    // TODO: add an unavailable address error
                    continue;
                }
            },
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
