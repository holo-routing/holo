//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::ffi::CString;
//use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;

//use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use libc::{if_nametoindex, AF_PACKET, ETH_P_ARP, SOCK_RAW};
use nix::sys::socket::{self, MsgFlags};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::error::SendError;

use crate::error::IoError;
use crate::packet::{ArpPacket, EthernetFrame, Ipv4Packet, VrrpPacket};
use crate::tasks::messages::input::{ArpNetRxPacketMsg, VrrpNetRxPacketMsg};
use crate::tasks::messages::output::NetTxPacketMsg;

pub fn socket_vrrp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let sock = capabilities::raise(|| {
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112)))
        })?;

        capabilities::raise(|| sock.bind_device(Some(ifname.as_bytes())))?;
        capabilities::raise(|| sock.set_broadcast(true))?;
        capabilities::raise(|| sock.set_nonblocking(true))?;
        capabilities::raise(|| join_multicast(&sock, ifname))?;

        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub fn socket_arp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let sock = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from(ETH_P_ARP)),
            )
        })?;
        capabilities::raise(|| {
            let _ = sock.bind_device(Some(ifname.as_bytes()));
            let _ = sock.set_broadcast(true);
        });
        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet_vrrp(
    socket: &AsyncFd<Socket>,
    packet: VrrpPacket,
) -> Result<usize, IoError> {
    let buf: &[u8] = &packet.encode();
    let saddr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 8), 0);

    socket
        .async_io(tokio::io::Interest::WRITABLE, |sock| {
            sock.send_to(buf, &saddr.into())
        })
        .await
        .map_err(IoError::SendError)
}

#[cfg(not(feature = "testing"))]
pub async fn send_packet_arp(
    sock: &AsyncFd<Socket>,
    ifname: &str,
    eth_frame: EthernetFrame,
    arp_packet: ArpPacket,
) -> Result<usize, IoError> {
    use std::ffi::CString;

    use libc::{c_void, sendto, sockaddr, sockaddr_ll};

    use crate::packet::ARPframe;
    let mut arpframe = ARPframe::new(eth_frame, arp_packet);

    let c_ifname = match CString::new(ifname) {
        Ok(c_ifname) => c_ifname,
        Err(err) => {
            return Err(IoError::SocketError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                err,
            )))
        }
    };
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };

    let mut sa = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: 0x806_u16.to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    unsafe {
        let ptr_sockaddr =
            std::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa);

        match sendto(
            sock.as_raw_fd(),
            &mut arpframe as *mut _ as *const c_void,
            std::mem::size_of_val(&arpframe),
            0,
            ptr_sockaddr,
            std::mem::size_of_val(&sa) as u32,
        ) {
            -1 => Err(IoError::SendError(std::io::Error::last_os_error())),
            fd => Ok(fd as usize),
        }
    }
}

fn join_multicast(sock: &Socket, ifname: &str) -> Result<(), std::io::Error> {
    let sock = socket2::SockRef::from(sock);
    let ifname = CString::new(ifname).unwrap();
    let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };

    sock.join_multicast_v4_n(
        &Ipv4Addr::new(224, 0, 0, 18),
        &InterfaceIndexOrAddress::Index(ifindex),
    )
}

//#[cfg(not(feature = "testing"))]
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
                name,
                eth_frame,
                arp_packet,
            } => {
                if let Err(error) =
                    send_packet_arp(&socket_arp, &name, eth_frame, arp_packet)
                        .await
                {
                    error.log();
                }
            }
        }
    }
}

pub(crate) async fn arp_read_loop(
    ifname: &str,
    arp_net_packet_rxp: Sender<ArpNetRxPacketMsg>,
) -> Result<(), SendError<ArpNetRxPacketMsg>> {
    let fd = unsafe {
        match libc::socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be()) {
            -1 => return Ok(()),
            fd => fd,
        }
    };
    let sock = unsafe { Socket::from_raw_fd(fd) };
    let _ = sock.bind_device(Some(ifname.as_bytes()));
    let af_sock = AsyncFd::new(sock).unwrap();

    let mut buf = [0u8; 42];

    loop {
        match af_sock
            .async_io(tokio::io::Interest::READABLE, |_s| {
                match nix::sys::socket::recv(fd, &mut buf, MsgFlags::empty()) {
                    Ok(_len) => {
                        let _eth_frame = EthernetFrame::decode(&buf[..14]);
                        let arp_packet = ArpPacket::decode(&buf[14..]);
                        Ok(arp_packet)
                    }
                    Err(err) => Err(err.into()),
                }
            })
            .await
        {
            Ok(packet) => {
                let msg = ArpNetRxPacketMsg { packet };
                let _ = arp_net_packet_rxp.send(msg).await;
            }
            Err(_err) => {
                // remember to introduce error logging here...
                continue;
            }
        }
    }
}

//#[cfg(not(feature = "testing"))]
pub(crate) async fn vrrp_read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    let mut buf = [0; 128];
    loop {
        match socket_vrrp
            .async_io(tokio::io::Interest::READABLE, |sock| {
                match socket::recv(
                    sock.as_raw_fd(),
                    &mut buf,
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        let data = &buf[0..msg];

                        // since ip header length is given in number of words
                        // (4 bytes per word), we multiply by 4 to get the actual
                        // number of bytes
                        let ip_header_len = ((data[0] & 0x0f) * 4) as usize;

                        let ip_pkt =
                            Ipv4Packet::decode(&data[0..ip_header_len])
                                .unwrap();
                        let vrrp_pkt =
                            VrrpPacket::decode(&data[ip_header_len..]);
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
                // retry if the syscall was interrupted
                continue;
            }
            Err(error) => {
                IoError::RecvError(error).log();
            }
        }
    }
}
