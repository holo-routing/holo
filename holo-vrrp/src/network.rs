//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use libc::ETH_P_ARP;
use nix::sys::socket;
use socket2::{Domain, Protocol, Type};
use tokio::sync::mpsc::error::SendError;

use crate::error::IoError;
use crate::interface::{Interface, VRRP_MULTICAST_ADDRESS, VRRP_PROTO_NUMBER};
use crate::packet::{ArpPacket, EthernetHdr, Ipv4Hdr, VrrpHdr, VrrpPacket};
use crate::tasks::messages::input::VrrpNetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;

pub const MAX_VRRP_HDR_LENGTH: usize = 96;

pub fn socket_vrrp_tx(
    interface: &Interface,
    vrid: u8,
) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let instance = interface.instances.get(&vrid).unwrap();
        let sock = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        sock.set_nonblocking(true)?;
        if let Some(addr) = instance.mac_vlan.system.addresses.first() {
            sock.set_multicast_if_v4(&addr.ip())?;
        }

        sock.set_header_included(true)?;

        // Confirm if we should bind to the primary interface's address...
        // bind it to the primary interface's name
        capabilities::raise(|| {
            sock.bind_device(Some(instance.mac_vlan.name.as_bytes()))
        })?;
        let _ = sock.set_reuse_address(true);

        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub fn socket_vrrp_rx(iface: &Interface) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        let sock = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(VRRP_PROTO_NUMBER)),
            )
        })?;
        capabilities::raise(|| sock.bind_device(Some(iface.name.as_bytes())))?;
        sock.set_nonblocking(true)?;
        join_multicast(&sock, iface)?;

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
        });
        let _ = sock.set_broadcast(true);
        Ok(sock)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet_vrrp(
    sock: &AsyncFd<Socket>,
    ifname: &str,
    pkt: VrrpPacket,
) -> Result<usize, IoError> {
    let c_ifname = CString::new(ifname).unwrap();
    unsafe {
        let ifindex = libc::if_nametoindex(c_ifname.as_ptr());
        let mut sa = libc::sockaddr_ll {
            sll_family: libc::AF_INET as u16,
            sll_protocol: (VRRP_PROTO_NUMBER as u16).to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ptr_sockaddr = std::mem::transmute::<
            *mut libc::sockaddr_ll,
            *mut libc::sockaddr,
        >(&mut sa);
        let buf: &[u8] = &pkt.encode();

        match libc::sendto(
            sock.as_raw_fd(),
            buf.as_ptr().cast(),
            std::cmp::min(buf.len(), 130),
            0,
            ptr_sockaddr,
            std::mem::size_of_val(&sa) as u32,
        ) {
            -1 => Err(IoError::SendError(std::io::Error::last_os_error())),
            fd => Ok(fd as usize),
        }
    }
}

#[cfg(not(feature = "testing"))]
pub async fn send_packet_arp(
    sock: &AsyncFd<Socket>,
    ifname: &str,
    eth_frame: EthernetHdr,
    arp_packet: ArpPacket,
) -> Result<usize, IoError> {
    use std::ffi::CString;

    use libc::{c_void, sendto, sockaddr, sockaddr_ll, AF_INET};

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
        sll_family: AF_INET as u16,
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

// for joining the VRRP multicast
#[cfg(not(feature = "testing"))]
pub fn join_multicast(
    sock: &Socket,
    iface: &Interface,
) -> Result<(), std::io::Error> {
    let sock = socket2::SockRef::from(sock);
    if let Some(addr) = iface.system.addresses.first() {
        let ip = addr.ip();
        return sock.join_multicast_v4(&VRRP_MULTICAST_ADDRESS, &ip);
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg>,
) {
    while let Some(msg) = net_tx_packetc.recv().await {
        match msg {
            NetTxPacketMsg::Vrrp { ifname, pkt } => {
                if let Err(error) =
                    send_packet_vrrp(&socket_vrrp, &ifname, pkt).await
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

#[cfg(not(feature = "testing"))]
pub(crate) async fn vrrp_read_loop(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    vrrp_net_packet_rxp: Sender<VrrpNetRxPacketMsg>,
) -> Result<(), SendError<VrrpNetRxPacketMsg>> {
    let mut buf = [0u8; MAX_VRRP_HDR_LENGTH];
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
                // retry if the syscall was interrupted
                continue;
            }
            Err(error) => {
                IoError::RecvError(error).log();
            }
        }
    }
}
