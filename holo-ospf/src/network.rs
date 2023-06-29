//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::Bytes;
use derive_new::new;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{Sender, UnboundedReceiver};
use nix::sys::socket::{self, SockaddrLike};
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;

use crate::collections::{AreaId, InterfaceId};
use crate::debug::Debug;
use crate::error::IoError;
use crate::packet::auth::AuthCtx;
use crate::packet::error::DecodeResult;
use crate::packet::Packet;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::version::Version;

// OSPF IP protocol number.
pub const OSPF_IP_PROTO: i32 = 89;

#[derive(Clone, Debug, Eq, PartialEq, new, Serialize)]
pub struct SendDestination<I: IpAddrKind> {
    pub ifindex: u32,
    pub addrs: DestinationAddrs<I>,
}

#[derive(Clone, Debug, Eq, PartialEq, new, Serialize)]
pub enum DestinationAddrs<I: IpAddrKind> {
    Single(I),
    Multiple(Vec<I>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum MulticastAddr {
    AllSpfRtrs,
    AllDrRtrs,
}

// OSPF version-specific code.
pub trait NetworkVersion<V: Version> {
    type NetIpAddr: IpAddrKind;
    type NetIpNetwork: IpNetworkKind<Self::NetIpAddr>;
    type SocketAddr: SockaddrLike + Send + Sync;
    type Pktinfo: Send + Sync;

    // Create OSPF socket.
    fn socket(ifname: &str) -> Result<Socket, std::io::Error>;

    // Enable or disable checksum offloading.
    fn set_cksum_offloading(
        socket: &Socket,
        enable: bool,
    ) -> Result<(), std::io::Error>;

    // Return the IP address of the specified OSPF multicast group.
    fn multicast_addr(addr: MulticastAddr) -> &'static V::NetIpAddr;

    // Join the specified OSPF multicast group.
    fn join_multicast(
        socket: &Socket,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Leave the specified OSPF multicast group.
    fn leave_multicast(
        socket: &Socket,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Create new IP_PKTINFO/IPV6_PKTINFO struct.
    fn new_pktinfo(src: V::NetIpAddr, ifindex: u32) -> V::Pktinfo;

    // Initialize the control message used by `sendmsg`.
    fn set_cmsg_data(pktinfo: &V::Pktinfo) -> socket::ControlMessage<'_>;

    // Get destination address from the control message of a received packet.
    fn get_cmsg_data(cmsgs: socket::CmsgIterator<'_>) -> Option<V::NetIpAddr>;

    // Convert packet destination to socket address.
    fn dst_to_sockaddr(ifindex: u32, addr: V::NetIpAddr) -> V::SocketAddr;

    // Convert socket address to packet source address.
    fn src_from_sockaddr(sockaddr: &V::SocketAddr) -> V::NetIpAddr;

    // Validate the IP header of the received packet.
    fn validate_ip_hdr(buf: &mut Bytes) -> DecodeResult<()>;
}

// ===== impl DestinationAddrs =====

impl<I> DestinationAddrs<I>
where
    I: IpAddrKind + 'static,
{
    #[cfg(not(feature = "testing"))]
    fn into_iter(self) -> Box<dyn Iterator<Item = I> + 'static + Send> {
        match self {
            DestinationAddrs::Single(addr) => Box::new(std::iter::once(addr)),
            DestinationAddrs::Multiple(addrs) => Box::new(addrs.into_iter()),
        }
    }
}

// ===== global functions =====

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet<V>(
    socket: &AsyncFd<Socket>,
    src: V::NetIpAddr,
    dst_ifindex: u32,
    dst_addr: V::NetIpAddr,
    packet: &Packet<V>,
    auth: Option<&AuthCtx>,
) -> Result<usize, IoError>
where
    V: Version,
{
    Debug::<V>::PacketTx(dst_ifindex, &dst_addr, packet).log();

    // Encode packet.
    let buf = packet.encode(auth);

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: V::SocketAddr = V::dst_to_sockaddr(dst_ifindex, dst_addr);
    let pktinfo = V::new_pktinfo(src, dst_ifindex);
    let cmsg = [V::set_cmsg_data(&pktinfo)];
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

#[cfg(not(feature = "testing"))]
pub(crate) async fn write_loop<V>(
    socket: Arc<AsyncFd<Socket>>,
    auth: Option<AuthCtx>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg<V>>,
) where
    V: Version,
{
    while let Some(NetTxPacketMsg { packet, src, dst }) =
        net_tx_packetc.recv().await
    {
        for dst_addr in dst.addrs.into_iter() {
            if let Err(error) = send_packet::<V>(
                &socket,
                src,
                dst.ifindex,
                dst_addr,
                &packet,
                auth.as_ref(),
            )
            .await
            {
                error.log();
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop<V>(
    socket: Arc<AsyncFd<Socket>>,
    area_id: AreaId,
    iface_id: InterfaceId,
    af: AddressFamily,
    auth: Option<AuthCtx>,
    net_packet_rxp: Sender<NetRxPacketMsg<V>>,
) -> Result<(), SendError<NetRxPacketMsg<V>>>
where
    V: Version,
{
    let mut buf = [0; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(V::Pktinfo);

    loop {
        // Receive data packet.
        match socket
            .async_io(tokio::io::Interest::READABLE, |socket| {
                match socket::recvmsg::<V::SocketAddr>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        // Retrieve source and destination addresses.
                        let src = msg
                            .address
                            .as_ref()
                            .map(|addr| V::src_from_sockaddr(addr));
                        let dst = V::get_cmsg_data(msg.cmsgs());
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
                        IoError::RecvMissingSourceAddr.log();
                        return Ok(());
                    }
                };
                let dst = match dst {
                    Some(addr) => addr,
                    None => {
                        IoError::RecvMissingAncillaryData.log();
                        return Ok(());
                    }
                };

                // Decode packet.
                let mut buf = Bytes::copy_from_slice(&iov[0].deref()[0..bytes]);
                let packet = V::validate_ip_hdr(&mut buf)
                    .and_then(|_| Packet::decode(af, &mut buf, auth.as_ref()));
                let msg = NetRxPacketMsg {
                    area_key: area_id.into(),
                    iface_key: iface_id.into(),
                    src,
                    dst,
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
