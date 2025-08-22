//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use holo_utils::capabilities;
use holo_utils::socket::{
    OwnedReadHalf, OwnedWriteHalf, SocketExt, TTL_MAX, TcpConnInfo,
    TcpListener, TcpSocket, TcpSocketExt, TcpStream, TcpStreamExt,
};
use holo_utils::task::TimeoutTask;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::collections::NeighborId;
use crate::error::{Error, IoError};
use crate::network;
use crate::packet::error::DecodeError;
use crate::packet::{DecodeCxt, Message, PacketInfo, Pdu};
use crate::tasks::messages::input::{NbrRxPduMsg, TcpAcceptMsg};
use crate::tasks::messages::output::NbrTxPduMsg;

// ===== global functions =====

pub(crate) fn listen_socket(
    addr: IpAddr,
) -> Result<TcpListener, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use tokio::{runtime, task};

        // Create and bind socket.
        let sockaddr = SocketAddr::from((addr, network::LDP_PORT));
        let socket = capabilities::raise(|| {
            task::block_in_place(move || {
                runtime::Handle::current().block_on(TcpListener::bind(sockaddr))
            })
        })?;

        // Set socket options.
        socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
        socket.set_ipv4_ttl(TTL_MAX)?;

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

#[cfg(not(feature = "testing"))]
fn connect_socket(
    local_addr: IpAddr,
    gtsm: bool,
) -> Result<TcpSocket, std::io::Error> {
    let sockaddr = SocketAddr::from((local_addr, 0));
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
    if gtsm {
        socket.set_ipv4_ttl(TTL_MAX)?;
        socket.set_ipv4_minttl(TTL_MAX)?;
    }

    socket.bind(sockaddr)?;
    Ok(socket)
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn connect(
    local_addr: IpAddr,
    remote_addr: IpAddr,
    gtsm: bool,
    password: &Option<String>,
) -> Result<(TcpStream, TcpConnInfo), Error> {
    // Create TCP socket.
    let socket =
        connect_socket(local_addr, gtsm).map_err(IoError::TcpSocketError)?;

    // Set the TCP MD5 password.
    if let Some(password) = password {
        socket
            .set_md5sig(&remote_addr, Some(password))
            .map_err(IoError::TcpAuthError)?;
    }

    // Connect to remote address on the LDP port.
    let sockaddr = SocketAddr::from((remote_addr, network::LDP_PORT));
    let stream = socket
        .connect(sockaddr)
        .await
        .map_err(IoError::TcpConnectError)?;

    // Obtain TCP connection address/port information.
    let conn_info = stream.conn_info().map_err(IoError::TcpInfoError)?;

    Ok((stream, conn_info))
}

#[cfg(not(feature = "testing"))]
async fn nbr_send_messages(
    stream: &mut OwnedWriteHalf,
    local_lsr_id: Ipv4Addr,
    max_pdu_len: u16,
    messages: &mut VecDeque<Message>,
) {
    let mut pdu = Pdu::new(local_lsr_id, 0);
    std::mem::swap(&mut pdu.messages, messages);
    let buf = pdu.encode(max_pdu_len);
    if let Err(error) = stream.write_all(&buf).await {
        IoError::TcpSendError(error).log();
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_write_loop(
    stream: OwnedWriteHalf,
    local_lsr_id: Ipv4Addr,
    max_pdu_len: u16,
    mut pdu_txc: UnboundedReceiver<NbrTxPduMsg>,
) {
    let stream_mtx = Arc::new(Mutex::new(stream));
    let messages_mtx = Arc::new(Mutex::new(VecDeque::new()));
    let mut _timeout;

    while let Some(NbrTxPduMsg { msg, flush, .. }) = pdu_txc.recv().await {
        let stream_mtx = stream_mtx.clone();
        let messages_mtx = messages_mtx.clone();

        // Enqueue message.
        messages_mtx.lock().await.push_back(msg);

        // When the `flush` variable is set, send all enqueued messages right
        // away.
        if flush {
            let mut stream = stream_mtx.lock().await;
            let mut messages = messages_mtx.lock().await;
            nbr_send_messages(
                &mut stream,
                local_lsr_id,
                max_pdu_len,
                &mut messages,
            )
            .await;
            continue;
        }

        // Schedule the transmission as an attempt to group more messages into
        // the same PDU.
        _timeout =
            TimeoutTask::new(Duration::from_millis(100), move || async move {
                let stream_mtx = stream_mtx.clone();
                let messages_mtx = messages_mtx.clone();
                let mut stream = stream_mtx.lock().await;
                let mut messages = messages_mtx.lock().await;

                nbr_send_messages(
                    &mut stream,
                    local_lsr_id,
                    max_pdu_len,
                    &mut messages,
                )
                .await;
            });
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_read_loop(
    mut stream: OwnedReadHalf,
    nbr_id: NeighborId,
    nbr_lsr_id: Ipv4Addr,
    nbr_raddr: IpAddr,
    nbr_pdu_rxp: Sender<NbrRxPduMsg>,
) -> Result<(), SendError<NbrRxPduMsg>> {
    let mut buf = [0; Pdu::MAX_SIZE];
    let mut data = Vec::with_capacity(Pdu::MAX_SIZE);

    // PDU header validation closure.
    let validate_pdu_hdr = move |lsr_id, label_space| {
        if lsr_id != nbr_lsr_id || label_space != 0 {
            return Err(DecodeError::InvalidLsrId(lsr_id));
        }
        Ok(())
    };

    // Decode context.
    let cxt = DecodeCxt {
        pkt_info: PacketInfo {
            src_addr: nbr_raddr,
            multicast: None,
        },
        pdu_max_len: Pdu::DFLT_MAX_LEN,
        validate_pdu_hdr: Some(Box::new(validate_pdu_hdr)),
        validate_msg_hdr: None,
    };

    loop {
        // Read data from the network.
        match stream.read(&mut buf).await {
            Ok(0) => {
                // Notify that the connection was closed by the remote end.
                let msg = NbrRxPduMsg {
                    nbr_id,
                    pdu: Err(Error::TcpConnClosed(nbr_lsr_id)),
                };
                nbr_pdu_rxp.send(msg).await?;
                return Ok(());
            }
            Ok(num_bytes) => data.extend_from_slice(&buf[0..num_bytes]),
            Err(error) => {
                IoError::TcpRecvError(error).log();
                continue;
            }
        };

        // Decode PDU(s).
        while let Ok(pdu_size) = Pdu::get_pdu_size(&data, &cxt) {
            let pdu = Pdu::decode(&data[0..pdu_size], &cxt)
                .map_err(|error| Error::NbrPduDecodeError(nbr_lsr_id, error));
            data.drain(0..pdu_size);

            // Notify that the LDP message was received.
            let msg = NbrRxPduMsg { nbr_id, pdu };
            nbr_pdu_rxp.send(msg).await?;
        }
    }
}
