//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::io::IoSliceMut;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};

use holo_utils::bfd::PathType;
use holo_utils::capabilities;
use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::socket::{SocketExt, TTL_MAX, UdpSocket, UdpSocketExt};
use nix::sys::socket::{self, ControlMessageOwned};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
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
                    socket.set_ipv4_pktinfo(true)?;
                    socket.set_ipv4_minttl(TTL_MAX)?;
                }
                AddressFamily::Ipv6 => {
                    socket.set_ipv6_pktinfo(true)?;
                    socket.set_ipv6_min_hopcount(TTL_MAX)?;
                }
            },
            PathType::IpMultihop => {
                // NOTE: since the same Rx socket is used for all multihop
                // sessions, incoming TTL checking should be done in the
                // userspace given that different peers might have different TTL
                // settings.
                match af {
                    AddressFamily::Ipv4 => {
                        socket.set_ipv4_pktinfo(true)?;
                    }
                    AddressFamily::Ipv6 => {
                        socket.set_ipv6_pktinfo(true)?;
                    }
                }
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
    ifname: Option<&str>,
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

        // Bind to interface.
        if let Some(ifname) = ifname {
            socket.bind_device(Some(ifname.as_bytes()))?;
        }

        // Set socket options.
        match af {
            AddressFamily::Ipv4 => {
                socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_ipv4_ttl(ttl)?;
            }
            AddressFamily::Ipv6 => {
                socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_ipv6_unicast_hops(ttl)?;
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
fn get_packet_dst(cmsgs: socket::CmsgIterator<'_>) -> Option<IpAddr> {
    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                return Some(
                    Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be()).into(),
                );
            }
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr).into());
            }
            _ => {}
        }
    }

    None
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<UdpSocket>,
    path_type: PathType,
    udp_packet_rxp: Sender<UdpRxPacketMsg>,
) -> Result<(), SendError<UdpRxPacketMsg>> {
    let mut buf = [0; 1024];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);

    loop {
        // Receive data from the network.
        match socket
            .async_io(tokio::io::Interest::READABLE, || {
                match socket::recvmsg::<socket::SockaddrStorage>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        // Retrieve source and destination addresses.
                        let src = get_packet_src(msg.address.as_ref());
                        let dst = get_packet_dst(msg.cmsgs().unwrap());
                        Ok((src, dst, msg.bytes))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, dst, bytes)) => {
                let src = match src {
                    Some(addr) => addr,
                    None => {
                        IoError::UdpRecvMissingSourceAddr.log();
                        return Ok(());
                    }
                };
                let dst = match dst {
                    Some(addr) => addr,
                    None => {
                        IoError::UdpRecvMissingAncillaryData.log();
                        return Ok(());
                    }
                };

                // Validate packet's source address.
                if !src.ip().is_usable() {
                    Error::UdpInvalidSourceAddr(src.ip()).log();
                    continue;
                }

                // Decode packet, discarding malformed ones.
                let packet = match Packet::decode(&iov[0].deref()[0..bytes]) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };

                // Notify the BFD main task about the received packet.
                let packet_info = match path_type {
                    PathType::IpSingleHop => PacketInfo::IpSingleHop { src },
                    PathType::IpMultihop => {
                        let src = src.ip();
                        // TODO: get packet's TTL using IP_RECVTTL/IPV6_HOPLIMIT
                        let ttl = TTL_MAX;
                        PacketInfo::IpMultihop { src, dst, ttl }
                    }
                };
                let msg = UdpRxPacketMsg {
                    packet_info,
                    packet,
                };
                udp_packet_rxp.send(msg).await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // Retry if the syscall was interrupted (EINTR).
                continue;
            }
            Err(error) => {
                IoError::UdpRecvError(error).log();
            }
        }
    }
}
