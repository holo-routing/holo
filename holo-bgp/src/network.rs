//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use holo_utils::capabilities;
use holo_utils::ip::{AddressFamily, IpAddrExt, IpAddrKind};
use holo_utils::socket::{
    OwnedReadHalf, OwnedWriteHalf, SocketExt, TTL_MAX, TcpConnInfo,
    TcpListener, TcpSocket, TcpSocketExt, TcpStream, TcpStreamExt,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::error::{Error, IoError, NbrRxError};
use crate::packet::message::{DecodeCxt, EncodeCxt, Message};
use crate::tasks::messages::input::{NbrRxMsg, TcpAcceptMsg};
use crate::tasks::messages::output::NbrTxMsg;

const BGP_PORT: u16 = 179;

// ===== global functions =====

pub(crate) fn listen_socket(
    af: AddressFamily,
) -> Result<TcpListener, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create TCP socket.
        let socket = socket(af)?;

        // Bind socket.
        let sockaddr = SocketAddr::from((IpAddr::unspecified(af), BGP_PORT));
        socket.set_reuseaddr(true)?;
        capabilities::raise(|| socket.bind(sockaddr))?;

        // GTSM Procedure: set TTL to max for outgoing packets.
        match af {
            AddressFamily::Ipv4 => {
                socket.set_ipv4_ttl(TTL_MAX)?;
            }
            AddressFamily::Ipv6 => {
                socket.set_ipv6_unicast_hops(TTL_MAX)?;
            }
        }

        // Convert the socket into a TcpListener.
        let socket = socket.listen(4096)?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(TcpListener {})
    }
}

pub(crate) fn listen_socket_md5sig_update(
    socket: &TcpListener,
    nbr_addr: &IpAddr,
    password: Option<&str>,
) {
    #[cfg(not(feature = "testing"))]
    {
        if let Err(error) = socket.set_md5sig(nbr_addr, password) {
            IoError::TcpAuthError(error).log();
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn listen_loop(
    listener: Arc<TcpListener>,
    tcp_acceptp: Sender<TcpAcceptMsg>,
) -> Result<(), SendError<TcpAcceptMsg>> {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => match stream.conn_info() {
                Ok(conn_info) => {
                    let msg = TcpAcceptMsg {
                        stream: Some(stream),
                        conn_info,
                    };
                    tcp_acceptp.send(msg).await?;
                }
                Err(error) => {
                    IoError::TcpInfoError(error).log();
                }
            },
            Err(error) => {
                IoError::TcpAcceptError(error).log();
            }
        }
    }
}

pub(crate) fn accepted_stream_init(
    stream: &TcpStream,
    af: AddressFamily,
    ttl: u8,
    ttl_security: Option<u8>,
    tcp_mss: Option<u16>,
) -> Result<(), std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Set TTL.
        match af {
            AddressFamily::Ipv4 => stream.set_ipv4_ttl(ttl)?,
            AddressFamily::Ipv6 => stream.set_ipv6_unicast_hops(ttl)?,
        }

        // Set TTL security check.
        if let Some(ttl_security_hops) = ttl_security {
            let ttl = TTL_MAX - ttl_security_hops + 1;
            match af {
                AddressFamily::Ipv4 => stream.set_ipv4_minttl(ttl)?,
                AddressFamily::Ipv6 => stream.set_ipv6_min_hopcount(ttl)?,
            }
        }

        // Set the TCP Maximum Segment Size.
        if let Some(tcp_mss) = tcp_mss {
            stream.set_mss(tcp_mss.into())?;
        }
    }

    Ok(())
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn connect(
    remote_addr: IpAddr,
    local_addr: Option<IpAddr>,
    ttl: u8,
    ttl_security: Option<u8>,
    tcp_mss: Option<u16>,
    tcp_password: &Option<String>,
) -> Result<(TcpStream, TcpConnInfo), Error> {
    let af = remote_addr.address_family();

    // Create TCP socket.
    let socket = socket(af).map_err(IoError::TcpSocketError)?;

    // Bind socket.
    if let Some(local_addr) = local_addr {
        let sockaddr = SocketAddr::from((local_addr, 0));
        socket
            .set_reuseaddr(true)
            .map_err(IoError::TcpSocketError)?;
        capabilities::raise(|| socket.bind(sockaddr))
            .map_err(IoError::TcpSocketError)?;
    }

    // Set TTL.
    match af {
        AddressFamily::Ipv4 => socket.set_ipv4_ttl(ttl),
        AddressFamily::Ipv6 => socket.set_ipv6_unicast_hops(ttl),
    }
    .map_err(IoError::TcpSocketError)?;

    // Set TTL security check.
    if let Some(ttl_security_hops) = ttl_security {
        let ttl = TTL_MAX - ttl_security_hops + 1;
        match af {
            AddressFamily::Ipv4 => socket.set_ipv4_minttl(ttl),
            AddressFamily::Ipv6 => socket.set_ipv6_min_hopcount(ttl),
        }
        .map_err(IoError::TcpSocketError)?;
    }

    // Set the TCP Maximum Segment Size.
    if let Some(tcp_mss) = tcp_mss {
        socket
            .set_mss(tcp_mss.into())
            .map_err(IoError::TcpSocketError)?;
    }

    // Set the TCP MD5 password.
    if let Some(tcp_password) = tcp_password {
        socket
            .set_md5sig(&remote_addr, Some(tcp_password))
            .map_err(IoError::TcpAuthError)?;
    }

    // Connect to remote address on the BGP port.
    let sockaddr = SocketAddr::from((remote_addr, BGP_PORT));
    let stream = socket
        .connect(sockaddr)
        .await
        .map_err(IoError::TcpConnectError)?;

    // Obtain TCP connection address/port information.
    let conn_info = stream.conn_info().map_err(IoError::TcpInfoError)?;

    Ok((stream, conn_info))
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_write_loop(
    mut stream: OwnedWriteHalf,
    mut cxt: EncodeCxt,
    mut nbr_msg_txc: UnboundedReceiver<NbrTxMsg>,
) {
    while let Some(msg) = nbr_msg_txc.recv().await {
        match msg {
            // Send message to the peer.
            NbrTxMsg::SendMessage { msg, .. } => {
                let buf = msg.encode(&cxt);
                if let Err(error) = stream.write_all(&buf).await {
                    IoError::TcpSendError(error).log();
                }
            }
            // Send list of messages to the peer.
            NbrTxMsg::SendMessageList { msg_list, .. } => {
                for msg in msg_list {
                    let buf = msg.encode(&cxt);
                    if let Err(error) = stream.write_all(&buf).await {
                        IoError::TcpSendError(error).log();
                    }
                }
            }
            // Update negotiated capabilities.
            NbrTxMsg::UpdateCapabilities(caps) => cxt.capabilities = caps,
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_read_loop(
    mut stream: OwnedReadHalf,
    nbr_addr: IpAddr,
    mut cxt: DecodeCxt,
    nbr_msg_rxp: Sender<NbrRxMsg>,
) -> Result<(), SendError<NbrRxMsg>> {
    const BUF_SIZE: usize = 65535;
    let mut buf = [0; BUF_SIZE];
    let mut data = Vec::with_capacity(BUF_SIZE);

    loop {
        // Read data from the network.
        match stream.read(&mut buf).await {
            Ok(0) => {
                // Notify that the connection was closed by the remote end.
                let msg = NbrRxMsg {
                    nbr_addr,
                    msg: Err(NbrRxError::TcpConnClosed),
                };
                nbr_msg_rxp.send(msg).await?;
                return Ok(());
            }
            Ok(num_bytes) => data.extend_from_slice(&buf[..num_bytes]),
            Err(error) => {
                IoError::TcpRecvError(error).log();
                continue;
            }
        };

        // Decode message(s).
        while let Some(msg_size) = Message::get_message_len(&data) {
            let msg = Message::decode(&data[0..msg_size], &cxt)
                .map_err(NbrRxError::MsgDecodeError);
            data.drain(..msg_size);

            // Keep track of received capabilities as they influence how some
            // messages should be decoded.
            if let Ok(Message::Open(msg)) = &msg {
                let capabilities = msg
                    .capabilities
                    .iter()
                    .map(|cap| cap.as_negotiated())
                    .collect::<BTreeSet<_>>();
                cxt.capabilities = capabilities;
            }

            // Notify that the BGP message was received.
            let msg = NbrRxMsg { nbr_addr, msg };
            nbr_msg_rxp.send(msg).await?;
        }
    }
}

// ===== helper functions =====

#[cfg(not(feature = "testing"))]
fn socket(af: AddressFamily) -> Result<TcpSocket, std::io::Error> {
    let socket = match af {
        AddressFamily::Ipv4 => TcpSocket::new_v4()?,
        AddressFamily::Ipv6 => {
            let socket = TcpSocket::new_v6()?;
            socket.set_ipv6_only(true)?;
            socket
        }
    };

    // Set socket options.
    match af {
        AddressFamily::Ipv4 => {
            socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
        }
        AddressFamily::Ipv6 => {
            socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;
        }
    }

    Ok(socket)
}
