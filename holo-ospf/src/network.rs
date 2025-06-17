//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use arc_swap::ArcSwap;
use bytes::Bytes;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::{Sender, UnboundedReceiver};
use nix::sys::socket::{self, SockaddrLike};
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;

use crate::collections::{AreaId, InterfaceId};
use crate::debug::Debug;
use crate::error::{Error, IoError};
use crate::northbound::configuration::TraceOptionPacketResolved;
use crate::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use crate::packet::error::DecodeResult;
use crate::packet::{Packet, PacketHdrVersion};
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::version::Version;

// OSPF IP protocol number.
pub const OSPF_IP_PROTO: i32 = 89;

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

// ===== global functions =====

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet<V>(
    socket: &AsyncFd<Socket>,
    ifname: &str,
    ifindex: u32,
    src: V::NetIpAddr,
    dst: V::NetIpAddr,
    packet: &Packet<V>,
    auth: Option<AuthEncodeCtx<'_>>,
    trace_opts: &Arc<ArcSwap<TraceOptionPacketResolved>>,
) -> Result<usize, IoError>
where
    V: Version,
{
    // Log packet being sent.
    if trace_opts.load().tx(packet.hdr().pkt_type()) {
        Debug::<V>::PacketTx(ifname, &dst, packet).log();
    }

    // Encode packet.
    let buf = packet.encode(auth);

    // Send packet.
    let iov = [IoSlice::new(&buf)];
    let sockaddr: V::SocketAddr = V::dst_to_sockaddr(ifindex, dst);
    let pktinfo = V::new_pktinfo(src, ifindex);
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
    ifname: String,
    ifindex: u32,
    src: V::NetIpAddr,
    auth: Option<AuthMethod>,
    auth_seqno: Arc<AtomicU64>,
    trace_opts: Arc<ArcSwap<TraceOptionPacketResolved>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPacketMsg<V>>,
) where
    V: Version,
{
    while let Some(NetTxPacketMsg { packet, dst }) = net_tx_packetc.recv().await
    {
        // Prepare authentication context.
        let auth = match &auth {
            Some(auth) => {
                let auth_key = match auth {
                    AuthMethod::ManualKey(key) => key,
                    AuthMethod::Keychain(keychain) => {
                        match keychain.key_lookup_send() {
                            Some(key) => key,
                            None => {
                                Error::<V>::PacketAuthMissingKey.log();
                                continue;
                            }
                        }
                    }
                };
                Some(AuthEncodeCtx::new(auth_key, &auth_seqno, src.into()))
            }
            None => None,
        };

        // Send packet to all requested destinations.
        for dst in dst {
            if let Err(error) = send_packet(
                &socket,
                &ifname,
                ifindex,
                src,
                dst,
                &packet,
                auth,
                &trace_opts,
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
    auth: Option<AuthMethod>,
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
                        let dst = V::get_cmsg_data(msg.cmsgs().unwrap());
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
                let packet = V::validate_ip_hdr(&mut buf).and_then(|_| {
                    let auth = auth
                        .as_ref()
                        .map(|auth| AuthDecodeCtx::new(auth, src.into()));
                    Packet::decode(af, &mut buf, auth)
                });
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
