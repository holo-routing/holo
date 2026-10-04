//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::io::{IoSlice, IoSliceMut};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, atomic};

use const_addrs::{ip4, ip6};
use holo_utils::bytes::Bytes;
use holo_utils::capabilities;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use holo_utils::socket::{
    AsyncFd, LinkAddrExt, RawSocketExt, Socket, SocketExt,
};
use internet_checksum::Checksum;
use ipnetwork::IpNetwork;
#[cfg(network_backend = "linux")]
use nix::sys::socket::{self, LinkAddr, SockaddrIn, SockaddrIn6};
#[cfg(network_backend = "linux")]
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::debug::Debug;
use crate::error::IoError;
use crate::instance::InstanceMacvlan;
use crate::interface::InterfaceView;
use crate::packet::VrrpHdr;
use crate::tasks::messages::input::VrrpNetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

// VRRP protocol number.
pub const VRRP_PROTO_NUMBER: i32 = 112;
pub const ICMP_PROTO_NUMBER: i32 = 58;

// EtherTypes.
pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

// VRRP multicast addresses.
pub static VRRP_MULTICAST_ADDR_IPV4: Ipv4Addr = ip4!("224.0.0.18");
pub static VRRP_MULTICAST_ADDR_IPV6: Ipv6Addr = ip6!("ff02::12");
pub static SOLICITATION_BASE_ADDR: Ipv6Addr = ip6!("ff02::1:ff00:0");

// ===== global functions =====

pub(crate) fn socket_vrrp_tx4(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
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
        socket.set_tos_v4(libc::IPTOS_PREC_INTERNETCONTROL.into())?;
        capabilities::raise(|| {
            socket.bind_device(Some(mvlan.name.as_bytes()))
        })?;

        Ok(socket)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_vrrp_tx6(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
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
        socket.set_ipv6_checksum(VrrpHdr::CHECKSUM_OFFSET)?;
        socket.set_multicast_ifindex_v6(mvlan.system.ifindex.unwrap())?;
        socket.set_tclass_v6(libc::IPTOS_PREC_INTERNETCONTROL.into())?;
        capabilities::raise(|| {
            socket.bind_device(Some(mvlan.name.as_bytes()))
        })?;

        Ok(socket)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_vrrp_rx4(
    interface: &InterfaceView<'_>,
) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
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
        socket.join_multicast_ifindex_v4(
            &VRRP_MULTICAST_ADDR_IPV4,
            interface.system.ifindex.unwrap(),
        )?;

        Ok(socket)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_vrrp_rx6(
    interface: &InterfaceView<'_>,
) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
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
        socket.set_ipv6_checksum(VrrpHdr::CHECKSUM_OFFSET)?;
        socket.join_multicast_v6(
            &VRRP_MULTICAST_ADDR_IPV6,
            interface.system.ifindex.unwrap(),
        )?;

        Ok(socket)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_arp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(ETHERTYPE_ARP as i32)),
            )
        })?;
        capabilities::raise(|| socket.bind_device(Some(ifname.as_bytes())))?;
        socket.set_broadcast(true)?;

        Ok(socket)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_nadv(
    mvlan: &InstanceMacvlan,
) -> Result<Socket, std::io::Error> {
    #[cfg(network_backend = "linux")]
    {
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(ICMP_PROTO_NUMBER)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_multicast_ifindex_v6(mvlan.system.ifindex.unwrap())?;
        socket.set_tclass_v6(libc::IPTOS_PREC_INTERNETCONTROL.into())?;

        // Compute and join the Solicited-Node multicast address [RFC4291] for
        // solicitated-node multicast address.
        for addr in &mvlan.system.addresses {
            if let IpNetwork::V6(addr) = addr
                && !addr.ip().is_unicast_link_local()
            {
                let sol_addr = generate_solicited_addr(addr.ip());
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
    #[cfg(network_backend = "null")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    trace_opts_packets: Arc<AtomicBool>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(msg) = net_tx_packetc.recv().await {
        match msg {
            NetTxPacketMsg::Vrrp { packet } => {
                if trace_opts_packets.load(atomic::Ordering::Relaxed) {
                    Debug::PacketTx(&packet.vrrp).log();
                }

                // Encode packet.
                let buf = packet.encode();

                // Send packet.
                if let Err(error) = send_vrrp4(&socket_vrrp, &buf).await {
                    error.log();
                }
            }
            NetTxPacketMsg::Vrrp6 {
                packet,
                src_ip,
                ifindex,
            } => {
                let IpAddr::V6(addr) = src_ip else {
                    continue;
                };

                if trace_opts_packets.load(atomic::Ordering::Relaxed) {
                    Debug::PacketTx(&packet).log();
                }

                // Encode packet.
                let buf = packet.encode();

                // Send packet.
                if let Err(error) =
                    send_vrrp6(&socket_vrrp, &buf, addr, ifindex).await
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
                if trace_opts_packets.load(atomic::Ordering::Relaxed) {
                    Debug::ArpTx(vrid, &arp_hdr.sender_proto_address).log();
                }

                // Encode packet.
                let mut buf = eth_hdr.encode();
                buf.put_slice(&arp_hdr.encode());

                // Send packet.
                if let Err(error) =
                    send_arp(&socket_arp, &buf, ifindex, eth_hdr.dst_mac).await
                {
                    error.log();
                }
            }
            NetTxPacketMsg::NAdv {
                vrid,
                ifindex,
                nadv_hdr,
            } => {
                if trace_opts_packets.load(atomic::Ordering::Relaxed) {
                    Debug::NeighborAdvertisementTx(
                        vrid,
                        &nadv_hdr.target_address,
                    )
                    .log();
                }

                // Collect relevant data for checksum.
                let mut check = Checksum::new();
                check.add_bytes(&nadv_hdr.pseudo_header());
                check.add_bytes(&nadv_hdr.encode());

                // Max size of a neighbor advertisement.
                let buf = &mut nadv_hdr.encode();
                buf[2..4].copy_from_slice(&check.checksum());

                // Send packet.
                if let Err(error) = send_nadv(
                    &socket_arp,
                    buf,
                    nadv_hdr.target_address,
                    ifindex,
                )
                .await
                {
                    error.log();
                }
            }
        }
    }
}

pub(crate) async fn read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
    af: AddressFamily,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    #[cfg(network_backend = "linux")]
    {
        let mut buf = [0u8; 16384];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);

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
                Ok((src, bytes)) => {
                    let Some(src) = src else {
                        IoError::RecvMissingSourceAddr.log();
                        continue;
                    };

                    let mut buf: &[u8] =
                        &Bytes::copy_from_slice(iov[0].deref());
                    match af {
                        AddressFamily::Ipv4 => buf = &buf[20..bytes],
                        AddressFamily::Ipv6 => buf = &buf[0..bytes],
                    }
                    let vrrp_pkt = VrrpHdr::decode(buf, af);
                    let msg = VrrpNetRxPacketMsg {
                        src: src.ip(),
                        packet: vrrp_pkt,
                    };
                    vrrp_net_packet_rxp.send(msg).await?;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted =>
                {
                    // Retry if the syscall was interrupted (EINTR).
                    continue;
                }
                Err(error) => {
                    IoError::RecvError(error).log();
                }
            }
        }
    }
    #[cfg(network_backend = "null")]
    {
        std::future::pending().await
    }
}

// ===== helper functions =====

#[cfg(network_backend = "linux")]
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

fn generate_solicited_addr(addr: Ipv6Addr) -> Ipv6Addr {
    let addr_bits: u128 = (addr.to_bits() << 104) >> 104;
    let solic_addr = SOLICITATION_BASE_ADDR.to_bits() | addr_bits;
    Ipv6Addr::from(solic_addr)
}

async fn send_vrrp4(
    socket: &AsyncFd<Socket>,
    buf: &[u8],
) -> Result<usize, IoError> {
    #[cfg(network_backend = "linux")]
    {
        let iov = [IoSlice::new(buf)];
        let sockaddr: SockaddrIn =
            std::net::SocketAddrV4::new(VRRP_MULTICAST_ADDR_IPV4, 0).into();
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
    #[cfg(network_backend = "null")]
    {
        Ok(buf.len())
    }
}

async fn send_vrrp6(
    socket: &AsyncFd<Socket>,
    buf: &[u8],
    addr: Ipv6Addr,
    ifindex: u32,
) -> Result<usize, IoError> {
    #[cfg(network_backend = "linux")]
    {
        let iov = [IoSlice::new(buf)];
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: addr.octets(),
            },
            ipi6_ifindex: ifindex,
        };
        let cmsg = [socket::ControlMessage::Ipv6PacketInfo(&pktinfo)];
        let sockaddr: SockaddrIn6 = std::net::SocketAddrV6::new(
            VRRP_MULTICAST_ADDR_IPV6,
            0,
            0,
            ifindex,
        )
        .into();
        socket
            .async_io(tokio::io::Interest::WRITABLE, |socket| {
                socket::sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &cmsg,
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(|errno| errno.into())
            })
            .await
            .map_err(IoError::SendError)
    }
    #[cfg(network_backend = "null")]
    {
        Ok(buf.len())
    }
}

async fn send_arp(
    socket: &AsyncFd<Socket>,
    buf: &[u8],
    ifindex: u32,
    dst_mac: MacAddr,
) -> Result<usize, IoError> {
    #[cfg(network_backend = "linux")]
    {
        let iov = [IoSlice::new(buf)];
        let sockaddr =
            LinkAddr::new(ETHERTYPE_ARP, ifindex, Some(dst_mac.as_bytes()));
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
    #[cfg(network_backend = "null")]
    {
        Ok(buf.len())
    }
}

async fn send_nadv(
    nadv_socket: &AsyncFd<Socket>,
    buf: &[u8],
    target: Ipv6Addr,
    ifindex: u32,
) -> Result<usize, IoError> {
    #[cfg(network_backend = "linux")]
    {
        let iov = [IoSlice::new(buf)];
        let sockaddr: SockaddrIn6 =
            std::net::SocketAddrV6::new(target, 0, 0, ifindex).into();
        nadv_socket
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
    #[cfg(network_backend = "null")]
    {
        Ok(buf.len())
    }
}
