//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

// Real Linux sockets.
#[cfg(network_backend = "linux")]
mod linux;
// Sockets that go nowhere, for test builds and platforms without a backend.
#[cfg(network_backend = "null")]
mod null;

#[cfg(network_backend = "linux")]
pub use crate::socket::linux::*;
#[cfg(network_backend = "null")]
pub use crate::socket::null::*;

// Maximum TTL for IPv4 or Hop Limit for IPv6.
pub const TTL_MAX: u8 = 255;

// TCP connection information.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct TcpConnInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug)]
pub enum TransportStream {
    TcpStream(TcpStream),
    TlsStream(TlsStream<TcpStream>),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::TcpStream(s) => Pin::new(s).poll_read(cx, buf),
            Self::TlsStream(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::TcpStream(s) => Pin::new(s).poll_write(cx, buf),
            Self::TlsStream(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::TcpStream(s) => Pin::new(s).poll_flush(cx),
            Self::TlsStream(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::TcpStream(s) => Pin::new(s).poll_shutdown(cx),
            Self::TlsStream(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl TransportStream {
    pub fn into_split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        tokio::io::split(self)
    }
}
