//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

// Sockets that go nowhere, for test builds and platforms without a backend.

use std::marker::PhantomData;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Default)]
pub struct AsyncFd<T>(T);

#[derive(Debug, Default)]
pub struct Socket();

#[derive(Debug, Default)]
pub struct UdpSocket();

#[derive(Debug, Default)]
pub struct TcpSocket();

#[derive(Debug, Default)]
pub struct TcpListener();

#[derive(Debug, Default)]
pub struct TcpStream();

#[derive(Debug, Default)]
pub struct TlsStream<T>(PhantomData<T>);

#[derive(Debug, Default)]
pub struct OwnedReadHalf();

#[derive(Debug, Default)]
pub struct OwnedWriteHalf();

impl<T> AsyncFd<T> {
    pub fn new(inner: T) -> std::io::Result<Self> {
        Ok(Self(inner))
    }

    pub fn get_ref(&self) -> &T {
        &self.0
    }
}

impl TcpStream {
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (OwnedReadHalf(), OwnedWriteHalf())
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl<T> TlsStream<T> {
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (OwnedReadHalf(), OwnedWriteHalf())
    }
}

impl<T> AsyncRead for TlsStream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl<T> AsyncWrite for TlsStream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

pub trait SocketExt {}
pub trait UdpSocketExt {}
pub trait TcpSocketExt {}
pub trait TcpStreamExt {}
pub trait RawSocketExt {}
pub trait LinkAddrExt {}
