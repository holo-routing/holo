//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::{Arc, LazyLock as Lazy};

use bytes::{Buf, Bytes};
use holo_utils::capabilities;
use holo_utils::socket::{AsyncFd, RawSocketExt, Socket};
use nix::sys::socket::{self, SockaddrIn};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::error::IoError;
use crate::packet::Packet;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

// IGMP IP protocol number.
pub const IGMP_IP_PROTO: i32 = 2;

// Multicast addresses.
pub static ALL_SYSTEMS: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.1").unwrap());
pub static ALL_ROUTERS: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.2").unwrap());

// ===== global functions =====

pub(crate) fn socket_tx(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};

        // Create raw socket.
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(IGMP_IP_PROTO)),
            )
        })?;
        capabilities::raise(|| socket.bind_device(Some(ifname.as_bytes())))?;
        socket.set_nonblocking(true)?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_ipv4_pktinfo(true)?;
        socket.set_tos(libc::IPTOS_PREC_INTERNETCONTROL as u32)?;
        // TODO: set router alert

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub(crate) fn socket_rx() -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};

        // Create raw socket.
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(IGMP_IP_PROTO)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_ipv4_pktinfo(true)?;
        socket.set_mrt_init(true)?;

        Ok(socket)
    }

    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket: Arc<AsyncFd<Socket>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(NetTxPacketMsg { dst, packet, .. }) =
        net_tx_packetc.recv().await
    {
        // Send packet out the interface.
        if let Err(error) = send_packet(&socket, dst, &packet).await {
            error.log();
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<AsyncFd<Socket>>,
    net_packet_rxp: Sender<NetRxPacketMsg>,
) -> Result<(), SendError<NetRxPacketMsg>> {
    let mut buf = [0; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);

    loop {
        // Receive data packet.
        match socket
            .async_io(tokio::io::Interest::READABLE, |socket| {
                match socket::recvmsg::<SockaddrIn>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        let ifindex = msg.cmsgs().unwrap().find_map(|cmsg| {
                            if let socket::ControlMessageOwned::Ipv4PacketInfo(
                                pktinfo,
                            ) = cmsg
                            {
                                Some(pktinfo.ipi_ifindex as u32)
                            } else {
                                None
                            }
                        });
                        Ok((ifindex, msg.address, msg.bytes))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((ifindex, src, bytes)) => {
                let Some(ifindex) = ifindex else {
                    IoError::RecvMissingAncillaryData.log();
                    return Ok(());
                };
                let Some(src) = src else {
                    IoError::RecvMissingSourceAddr.log();
                    return Ok(());
                };

                // Move past the IPv4 header.
                let mut buf = Bytes::copy_from_slice(&iov[0].deref()[0..bytes]);
                let hdr_len = buf.get_u8() & 0x0F;
                let _tos = buf.get_u8();
                let _total_len = buf.get_u16();
                buf.advance(((hdr_len << 2) - 4) as usize);

                // Decode IGMP packet.
                let packet = Packet::decode(&mut buf);
                let msg = NetRxPacketMsg {
                    ifindex,
                    src: src.ip(),
                    packet,
                };
                net_packet_rxp.send(msg).await.unwrap();
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

// ===== helper functions =====

#[cfg(not(feature = "testing"))]
async fn send_packet(
    socket: &AsyncFd<Socket>,
    dst: Ipv4Addr,
    packet: &Packet,
) -> Result<usize, IoError> {
    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: SockaddrIn = SocketAddrV4::new(dst, 0).into();
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
