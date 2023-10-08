//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod error;
pub mod ffi;
pub mod messages;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::{Sender, UnboundedReceiver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tracing::{debug, debug_span};

use crate::zclient::error::{DecodeError, DecodeResult, Error};
use crate::zclient::messages::{ZapiRxMsg, ZapiTxMsg};

#[derive(Clone, Debug)]
pub struct Zclient {
    pub vrf_id: u32,
    pub session_id: u32,
    pub instance: u16,
    pub redist_default: ffi::RouteType,
    pub receive_notify: bool,
}

#[derive(Debug)]
pub enum Debug {
    Connected,
}

// ===== impl Zclient =====

impl Zclient {
    pub fn new(
        vrf_id: u32,
        instance: u16,
        redist_default: ffi::RouteType,
        receive_notify: bool,
    ) -> Zclient {
        Zclient {
            vrf_id,
            session_id: 0,
            instance,
            redist_default,
            receive_notify,
        }
    }

    // Connects to zebra.
    pub(crate) async fn connect(&self) -> Result<UnixStream, Error> {
        let stream = UnixStream::connect("/var/run/frr/zserv.api")
            .await
            .map_err(Error::ZebraConnectError)?;
        Debug::Connected.log();
        Ok(stream)
    }

    // Encodes a ZAPI header.
    fn encode_zapi_header(&self, buf: &mut BytesMut, cmd: u16) {
        buf.put_u16(ffi::ZEBRA_HEADER_SIZE);
        buf.put_u8(ffi::ZEBRA_HEADER_MARKER);
        buf.put_u8(ffi::ZSERV_VERSION);
        buf.put_u32(self.vrf_id);
        buf.put_u16(cmd);
    }

    // Decodes a ZAPI message.
    fn decode_message(&self, data: &mut Vec<u8>) -> DecodeResult<ZapiRxMsg> {
        let mut buf = Bytes::copy_from_slice(data);

        // Decode message header.
        if buf.len() < ffi::ZEBRA_HEADER_SIZE as usize {
            return Err(DecodeError::PartialMessage);
        }
        let size = buf.get_u16() as usize;
        let marker = buf.get_u8();
        let version = buf.get_u8();
        let vrf_id = buf.get_u32();
        let cmd = buf.get_u16();

        // Sanity checks.
        if version != ffi::ZSERV_VERSION || marker != ffi::ZEBRA_HEADER_MARKER {
            data.drain(0..size);
            return Err(DecodeError::VersionMismatch(version, marker));
        }
        if buf.len() < (size - ffi::ZEBRA_HEADER_SIZE as usize) {
            return Err(DecodeError::PartialMessage);
        }
        data.drain(0..size);

        // Decode message body.
        ZapiRxMsg::decode(buf, cmd, vrf_id)
    }

    pub(crate) async fn write_loop(
        &self,
        mut stream: OwnedWriteHalf,
        mut sb_txc: UnboundedReceiver<ZapiTxMsg>,
    ) {
        while let Some(msg) = sb_txc.recv().await {
            let buf = msg.encode(self);
            stream.write_all(&buf).await.unwrap();
        }
    }

    pub(crate) async fn read_loop(
        &self,
        mut stream: OwnedReadHalf,
        sb_rxp: Sender<ZapiRxMsg>,
    ) {
        let mut buf: [u8; 4096] = [0; 4096];
        let mut data: Vec<u8> = vec![];

        'network_loop: loop {
            // Read data from zebra.
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(error) => {
                    Error::ZebraReadError(error).log();
                    continue;
                }
            };
            if n == 0 {
                Error::ZebraDisconnected.log();
                return;
            }
            data.extend_from_slice(&buf[0..n]);

            // Parse received data.
            loop {
                match self.decode_message(&mut data) {
                    Ok(msg) => {
                        let _ = sb_rxp.send(msg).await;
                    }
                    // Try again later once more data arrives.
                    Err(DecodeError::PartialMessage) => continue 'network_loop,
                    // Log but otherwise ignore the error.
                    Err(error) => {
                        Error::DecodeError(error).log();
                    }
                }
            }
        }
    }
}

// ===== impl Debug =====

impl Debug {
    pub fn log(&self) {
        match self {
            Debug::Connected => {
                debug_span!("southbound").in_scope(|| {
                    debug!("{}", self);
                });
            }
        }
    }
}

impl std::fmt::Display for Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::Connected => {
                write!(f, "connected to zebra")
            }
        }
    }
}
