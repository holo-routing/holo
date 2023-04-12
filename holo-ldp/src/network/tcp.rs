//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use holo_utils::socket::{
    OwnedReadHalf, OwnedWriteHalf, TcpListener, TcpListenerExt, TcpSocket,
    TcpSocketExt, TcpStream,
};
use holo_utils::task::TimeoutTask;
use holo_utils::{capabilities, Sender, UnboundedReceiver};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::Mutex;

use crate::collections::NeighborId;
use crate::error::{Error, IoError};
use crate::network;
use crate::packet::error::DecodeError;
use crate::packet::{DecodeCxt, Message, PacketInfo, Pdu};
use crate::tasks::messages::input::{NbrRxPduMsg, TcpAcceptMsg};
use crate::tasks::messages::output::NbrTxPduMsg;

#[derive(Debug, Deserialize, Serialize)]
pub struct ConnectionInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

// ===== impl ConnectionInfo =====

impl ConnectionInfo {
    #[cfg(not(feature = "testing"))]
    pub(crate) fn new(stream: &TcpStream) -> std::io::Result<ConnectionInfo> {
        let local_addr = stream.local_addr()?;
        let remote_addr = stream.peer_addr()?;

        Ok(ConnectionInfo {
            local_addr: local_addr.ip(),
            local_port: local_addr.port(),
            remote_addr: remote_addr.ip(),
            remote_port: remote_addr.port(),
        })
    }
}

// ===== global functions =====

pub(crate) async fn listen_socket(
    addr: IpAddr,
) -> Result<TcpListener, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create and bind socket.
        let sockaddr = SocketAddr::from((addr, network::LDP_PORT));
        let socket =
            capabilities::raise_async(|| Box::pin(TcpListener::bind(sockaddr)))
                .await?;

        // Set socket options.
        socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
        socket.set_ttl(255)?;

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(TcpListener {})
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn listen_loop(
    listener: TcpListener,
    tcp_acceptp: Sender<TcpAcceptMsg>,
) -> Result<(), SendError<TcpAcceptMsg>> {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => match ConnectionInfo::new(&stream) {
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
        socket.set_ipv4_ttl(255)?;
        socket.set_ipv4_minttl(255)?;
    }
    socket.bind(sockaddr)?;
    Ok(socket)
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn connect(
    local_addr: IpAddr,
    remote_addr: IpAddr,
    gtsm: bool,
) -> Result<(TcpStream, ConnectionInfo), Error> {
    // Create TCP socket.
    let socket =
        connect_socket(local_addr, gtsm).map_err(IoError::TcpSocketError)?;

    // Connect to remote address on the LDP port.
    let sockaddr = SocketAddr::from((remote_addr, network::LDP_PORT));
    let stream = socket
        .connect(sockaddr)
        .await
        .map_err(IoError::TcpConnectError)?;

    // Obtain TCP connection address/port information.
    let conn_info =
        ConnectionInfo::new(&stream).map_err(IoError::TcpInfoError)?;

    Ok((stream, conn_info))
}

#[cfg(not(feature = "testing"))]
async fn nbr_send_messages(
    stream: &mut OwnedWriteHalf,
    local_lsr_id: Ipv4Addr,
    messages: &mut VecDeque<Message>,
) {
    // TODO: might need multiple PDUs to encode all messages.
    let mut pdu = Pdu::new(local_lsr_id, 0);
    std::mem::swap(&mut pdu.messages, messages);
    let buf = pdu.encode();
    if let Err(error) = stream.write_all(&buf).await {
        IoError::TcpSendError(error).log();
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_write_loop(
    stream: OwnedWriteHalf,
    local_lsr_id: Ipv4Addr,
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
            nbr_send_messages(&mut stream, local_lsr_id, &mut messages).await;
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

                nbr_send_messages(&mut stream, local_lsr_id, &mut messages)
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
    let mut buf: [u8; Pdu::MAX_SIZE] = [0; Pdu::MAX_SIZE];
    let mut data: Vec<u8> = vec![];

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

    'network_loop: loop {
        // Read data from the network.
        let num_bytes = match stream.read(&mut buf).await {
            Ok(num_bytes) => num_bytes,
            Err(error) => {
                IoError::TcpRecvError(error).log();
                continue;
            }
        };
        if num_bytes == 0 {
            // Notify that the connection was closed by the remote end.
            let msg = NbrRxPduMsg {
                nbr_id,
                pdu: Err(Error::TcpConnClosed(nbr_lsr_id)),
            };
            nbr_pdu_rxp.send(msg).await?;
            return Ok(());
        }
        data.extend_from_slice(&buf[0..num_bytes]);

        // Decode PDU(s).
        loop {
            match Pdu::get_pdu_size(&data, &cxt) {
                Ok(pdu_size) => {
                    let pdu = Pdu::decode(&data[0..pdu_size], &cxt).map_err(
                        |error| Error::NbrPduDecodeError(nbr_lsr_id, error),
                    );
                    data.drain(0..pdu_size);

                    // Notify that the LDP message was received.
                    let msg = NbrRxPduMsg { nbr_id, pdu };
                    nbr_pdu_rxp.send(msg).await?;
                }
                Err(_) => {
                    // Try again later once more data arrives.
                    continue 'network_loop;
                }
            }
        }
    }
}
