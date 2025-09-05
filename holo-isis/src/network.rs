//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use holo_utils::capabilities;
use holo_utils::keychain::Key;
use holo_utils::mac_addr::MacAddr;
use holo_utils::socket::{AsyncFd, LinkAddrExt, Socket};
use nix::sys::socket;
use nix::sys::socket::LinkAddr;
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::collections::InterfaceId;
use crate::debug::Debug;
use crate::error::IoError;
use crate::northbound::configuration::TraceOptionPacketResolved;
use crate::packet::auth::AuthMethod;
use crate::packet::pdu::Pdu;
use crate::tasks::messages::input::NetRxPduMsg;
use crate::tasks::messages::output::NetTxPduMsg;

// Ethernet LLC header.
pub const LLC_HDR: [u8; 3] = [0xFE, 0xFE, 0x03];

// GRE protocol type for ISO.
pub const GRE_PROTO_TYPE_ISO: u16 = 0x00FE;

// IS-IS ethernet multicast addresses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Serialize)]
pub enum MulticastAddr {
    AllIss,
    AllL1Iss,
    AllL2Iss,
}

// BPF filter that accepts IS-IS over LLC and IS-IS over ethertype 0x00FE
// (e.g. GRE tunnels). Shamelessly copied from FRR!
const ISIS_BPF_FILTER: [libc::sock_filter; 10] = [
    // l0: ldh [0]
    bpf_filter_block(0x28, 0, 0, 0x00000000),
    // l1: jeq #0xfefe, l2, l4
    bpf_filter_block(0x15, 0, 2, 0x0000fefe),
    // l2: ldb [3]
    bpf_filter_block(0x30, 0, 0, 0x00000003),
    // l3: jmp l7
    bpf_filter_block(0x05, 0, 0, 0x00000003),
    // l4: ldh proto
    bpf_filter_block(0x28, 0, 0, 0xfffff000),
    // l5: jeq #0x00fe, l6, l9
    bpf_filter_block(0x15, 0, 3, 0x000000fe),
    // l6: ldb [0]
    bpf_filter_block(0x30, 0, 0, 0x00000000),
    // l7: jeq #0x83, l8, l9
    bpf_filter_block(0x15, 0, 1, 0x00000083),
    // l8: ret #0x40000
    bpf_filter_block(0x06, 0, 0, 0x00040000),
    // l9: ret #0
    bpf_filter_block(0x06, 0, 0, 0x00000000),
];

// ===== impl MulticastAddr =====

impl MulticastAddr {
    pub(crate) const fn as_bytes(&self) -> [u8; 6] {
        match self {
            MulticastAddr::AllIss => [0x09, 0x00, 0x2B, 0x00, 0x00, 0x05],
            MulticastAddr::AllL1Iss => [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14],
            MulticastAddr::AllL2Iss => [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15],
        }
    }
}

// ===== global functions =====

pub(crate) fn socket(ifindex: u32) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};

        // Create raw socket.
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::PACKET,
                Type::DGRAM,
                Some(Protocol::from(libc::ETH_P_ALL)),
            )
        })?;
        socket.set_nonblocking(true)?;

        // Bind to local interface.
        let sockaddr = LinkAddr::new(libc::ETH_P_ALL as u16, ifindex, None);
        socket::bind(socket.as_raw_fd(), &sockaddr)?;

        // Attach BPF filter.
        socket.attach_filter(&ISIS_BPF_FILTER)?;

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
    broadcast: bool,
    ifname: String,
    ifindex: u32,
    hello_padding: Option<u16>,
    hello_auth: Option<AuthMethod>,
    global_auth: Option<AuthMethod>,
    trace_opts: Arc<ArcSwap<TraceOptionPacketResolved>>,
    mut net_tx_packetc: UnboundedReceiver<NetTxPduMsg>,
) {
    while let Some(NetTxPduMsg { mut pdu, dst }) = net_tx_packetc.recv().await {
        // Get authentication key.
        let auth = match &pdu {
            Pdu::Hello(..) => hello_auth.as_ref(),
            Pdu::Lsp(..) | Pdu::Snp(..) => global_auth.as_ref(),
        };
        let auth = auth.and_then(|auth| auth.get_key_send());

        // Add Hello padding.
        //
        // Padding cannot be pre-computed and needs to be added on a per-packet
        // basis, because the size of the authentication digest or password may
        // change over time when a key-chain is used.
        if let Pdu::Hello(hello) = &mut pdu
            && let Some(mut max_size) = hello_padding
        {
            // Take into account the authentication TLV.
            if let Some(auth) = auth {
                max_size -= Pdu::auth_tlv_len(auth) as u16;
            }
            hello.add_padding(max_size);
        }

        // Send PDU out the interface.
        if let Err(error) = send_pdu(
            &socket,
            broadcast,
            &ifname,
            ifindex,
            dst,
            &pdu,
            auth,
            &trace_opts,
        )
        .await
        {
            error.log();
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<AsyncFd<Socket>>,
    broadcast: bool,
    iface_id: InterfaceId,
    hello_auth: Option<AuthMethod>,
    global_auth: Option<AuthMethod>,
    net_packet_rxp: Sender<NetRxPduMsg>,
) -> Result<(), SendError<NetRxPduMsg>> {
    let mut buf = [0; 16384];
    let mut iov = [IoSliceMut::new(&mut buf)];

    loop {
        // Receive data packet.
        match socket
            .async_io(tokio::io::Interest::READABLE, |socket| {
                match socket::recvmsg::<LinkAddr>(
                    socket.as_raw_fd(),
                    &mut iov,
                    None,
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => Ok((msg.address.unwrap(), msg.bytes)),
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, bytes)) => {
                // Filter out non-IS-IS packets by checking the LLC header in
                // broadcast interfaces.
                if broadcast && iov[0].deref()[0..3] != LLC_HDR {
                    continue;
                }
                // For non-broadcast media types, only GRE is supported.
                if !broadcast && src.protocol() != GRE_PROTO_TYPE_ISO.to_be() {
                    continue;
                }

                // Extract the source MAC address from the packet metadata.
                let Some(src) = src.addr() else {
                    IoError::RecvMissingSourceAddr.log();
                    continue;
                };

                // Decode packet.
                let offset = if broadcast { LLC_HDR.len() } else { 0 };
                let bytes =
                    Bytes::copy_from_slice(&iov[0].deref()[offset..bytes]);
                let pdu = Pdu::decode(
                    bytes.clone(),
                    hello_auth.as_ref(),
                    global_auth.as_ref(),
                );
                let msg = NetRxPduMsg {
                    iface_key: iface_id.into(),
                    src: MacAddr::from(src),
                    bytes,
                    pdu,
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
async fn send_pdu(
    socket: &AsyncFd<Socket>,
    broadcast: bool,
    ifname: &str,
    ifindex: u32,
    dst: MulticastAddr,
    pdu: &Pdu,
    auth: Option<&Key>,
    trace_opts: &Arc<ArcSwap<TraceOptionPacketResolved>>,
) -> Result<usize, IoError> {
    // Log PDU being sent.
    if trace_opts.load().tx(pdu.pdu_type()) {
        Debug::PduTx(ifname, dst, pdu).log();
    }

    // Encode PDU.
    let buf = pdu.encode(auth);

    // Send PDU.
    socket
        .async_io(tokio::io::Interest::WRITABLE, |socket| {
            if broadcast {
                // Prepend LLC header before IS-IS PDU.
                let iov = [IoSlice::new(&LLC_HDR), IoSlice::new(&buf)];
                let sockaddr = LinkAddr::new(
                    (LLC_HDR.len() + buf.len()) as u16,
                    ifindex,
                    Some(dst.as_bytes()),
                );
                socket::sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &[],
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
            } else {
                // For non-broadcast media types, only GRE is supported.
                let sockaddr = LinkAddr::new(
                    GRE_PROTO_TYPE_ISO,
                    ifindex,
                    Some(dst.as_bytes()),
                );
                socket::sendto(
                    socket.as_raw_fd(),
                    &buf,
                    &sockaddr,
                    socket::MsgFlags::empty(),
                )
            }
            .map_err(|errno| errno.into())
        })
        .await
        .map_err(IoError::SendError)
}

const fn bpf_filter_block(
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
