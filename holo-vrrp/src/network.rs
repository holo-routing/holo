//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::io;
use std::net::{IpAddr, SocketAddrV4, Ipv4Addr};
use std::os::fd::FromRawFd;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use libc::{socket, AF_PACKET, ETH_P_ALL, ETH_P_ARP, SOCK_RAW};
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;

use crate::error::IoError;
use crate::packet::{VrrpPacket, ArpPacket, EthernetFrame};
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

pub(crate) fn socket_vrrp(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = capabilities::raise(|| {
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112)))
        })?;
        
        capabilities::raise(|| {
            socket.bind_device(Some(ifname.as_bytes()))
        })?;
        socket.set_broadcast(true)?;
        Ok(socket)
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
            Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(ETH_P_ARP)))
        })?;
        capabilities::raise(|| {
            sock.bind_device(Some(ifname.as_bytes()));
            sock.set_broadcast(true);
        });
        Ok(sock)
        
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket { })
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet_vrrp(
    socket: &AsyncFd<Socket>,
    _src: IpAddr,
    _dst: IpAddr,
    packet: VrrpPacket,
) -> Result<usize, IoError> {

    let buf: &[u8] = &packet.encode();
    let saddr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 8), 0);

    socket
        .async_io(tokio::io::Interest::WRITABLE, |sock| {
            sock.send_to(buf, &saddr.into())
                .map_err(|errno| errno.into())
        })
        .await
        .map_err(IoError::SendError)
}

#[cfg(not(feature = "testing"))]
pub fn send_packet_arp(
    sock: Socket,
    ifname: &str,
    eth_frame: EthernetFrame,
    arp_packet: ArpPacket,
) -> Result<usize, IoError> {
    use std::{ffi::{CString, NulError}, os::{self, fd::AsRawFd}};

    use bytes::Buf;
    use libc::{c_void, if_indextoname, if_nametoindex, sendto, sockaddr, sockaddr_ll};

    use crate::packet::ARPframe;
    let mut arpframe = ARPframe::new(eth_frame, arp_packet);

    let c_ifname = match CString::new(ifname.clone()){
        Ok(c_ifname) => c_ifname,
        Err(err) => return Err(IoError::SocketError(std::io::Error::new(io::ErrorKind::NotFound, err))),
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
        let ptr_sockaddr = std::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa);
        
        match sendto(
            sock.as_raw_fd(), 
            &mut arpframe as *mut _ as *const c_void, 
            std::mem::size_of_val(&arpframe), 
            0, 
            ptr_sockaddr, 
            std::mem::size_of_val(&sa) as u32
        ) {
            -1 => {
                Err(IoError::SendError(io::Error::last_os_error()))
            },
            fd => {
                Ok(fd as usize)
            }
        }

    }

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

                // if let Err(error) = send_packet_arp(&socket_arp).await {
                //     error.log();
                // }

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
