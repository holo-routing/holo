//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::io::{BorrowedFd, OwnedFd};

use derive_new::new;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::socket::Socket;
use holo_utils::{Sender, UnboundedReceiver};
use nix::sys::socket::{self, SockaddrLike};
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;

use crate::debug::Debug;
use crate::error::IoError;
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
    type SocketAddr: SockaddrLike;
    type Pktinfo;

    // Create OSPF socket.
    fn socket() -> Result<Socket, std::io::Error>;

    // Return the IP address of the specified OSPF multicast group.
    fn multicast_addr(addr: MulticastAddr) -> &'static V::NetIpAddr;

    // Join the specified OSPF multicast group.
    fn join_multicast(
        socket: BorrowedFd<'_>,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Leave the specified OSPF multicast group.
    fn leave_multicast(
        socket: BorrowedFd<'_>,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error>;

    // Create new IP_PKTINFO/IPV6_PKTINFO struct.
    fn new_pktinfo(src: Option<V::NetIpAddr>, ifindex: u32) -> V::Pktinfo;

    // Initialize the control message used by `sendmsg`.
    fn set_cmsg_data(pktinfo: &V::Pktinfo) -> socket::ControlMessage<'_>;

    // Get the ifindex and source address from the control message of a received
    // packet.
    fn get_cmsg_data(
        cmsgs: socket::CmsgIterator<'_>,
    ) -> Option<(u32, V::NetIpAddr)>;

    // Convert packet destination to socket address.
    fn dst_to_sockaddr(ifindex: u32, addr: V::NetIpAddr) -> V::SocketAddr;

    // Convert socket address to packet source address.
    fn src_from_sockaddr(sockaddr: &V::SocketAddr) -> V::NetIpAddr;

    // Decode OSPF packet from a bytes buffer filled by `recvmsg`.
    fn decode_packet(af: AddressFamily, data: &[u8])
        -> DecodeResult<Packet<V>>;
}

// ===== impl DestinationAddrs =====

impl<I> DestinationAddrs<I>
where
    I: IpAddrKind + 'static,
{
    #[cfg(not(feature = "testing"))]
    fn into_iter(self) -> Box<dyn Iterator<Item = I> + 'static> {
        match self {
            DestinationAddrs::Single(addr) => Box::new(std::iter::once(addr)),
            DestinationAddrs::Multiple(addrs) => Box::new(addrs.into_iter()),
        }
    }
}

// ===== global functions =====

#[cfg(not(feature = "testing"))]
pub(crate) fn send_packet<V>(
    socket: &RawFd,
    src: Option<V::NetIpAddr>,
    dst_ifindex: u32,
    dst_addr: V::NetIpAddr,
    packet: &Packet<V>,
) -> Result<usize, IoError>
where
    V: Version,
{
    Debug::<V>::PacketTx(dst_ifindex, &dst_addr, packet).log();

    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: V::SocketAddr = V::dst_to_sockaddr(dst_ifindex, dst_addr);
    let pktinfo = V::new_pktinfo(src, dst_ifindex);
    let cmsg = [V::set_cmsg_data(&pktinfo)];
    socket::sendmsg(
        *socket,
        &iov,
        &cmsg,
        socket::MsgFlags::empty(),
        Some(&sockaddr),
    )
    .map_err(IoError::SendError)
}

#[cfg(not(feature = "testing"))]
pub(crate) fn write_loop<V>(
    socket: OwnedFd,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg<V>>,
) where
    V: Version,
{
    let socket = socket.as_raw_fd();

    while let Some(NetTxPacketMsg { packet, src, dst }) =
        net_tx_packetc.blocking_recv()
    {
        for dst_addr in dst.addrs.into_iter() {
            if let Err(error) =
                send_packet::<V>(&socket, src, dst.ifindex, dst_addr, &packet)
            {
                error.log();
            }
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) fn read_loop<V>(
    socket: BorrowedFd<'_>,
    af: AddressFamily,
    net_packet_rxp: Sender<NetRxPacketMsg<V>>,
) -> Result<(), SendError<NetRxPacketMsg<V>>>
where
    V: Version,
{
    let socket = socket.as_raw_fd();
    let mut buf = [0; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(V::Pktinfo);

    loop {
        // Receive data packet.
        let msg = match socket::recvmsg::<V::SocketAddr>(
            socket,
            &mut iov,
            Some(&mut cmsgspace),
            socket::MsgFlags::empty(),
        ) {
            Ok(msg) => msg,
            Err(error) => {
                IoError::RecvError(error).log();
                return Ok(());
            }
        };

        // Retrieve source address.
        let src = match &msg.address {
            Some(addr) => V::src_from_sockaddr(addr),
            None => {
                IoError::RecvMissingSourceAddr.log();
                return Ok(());
            }
        };

        // Retrieve ancillary data.
        let (ifindex, dst) = match V::get_cmsg_data(msg.cmsgs()) {
            Some(value) => value,
            None => {
                IoError::RecvMissingAncillaryData.log();
                return Ok(());
            }
        };

        // Decode packet.
        let packet = V::decode_packet(af, &iov[0].deref()[0..msg.bytes]);

        let msg = NetRxPacketMsg {
            ifindex,
            src,
            dst,
            packet,
        };
        net_packet_rxp.blocking_send(msg)?;
    }
}
