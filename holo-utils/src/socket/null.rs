//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

// Sockets that go nowhere, for test builds and platforms without a backend.

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

pub trait SocketExt {}
pub trait UdpSocketExt {}
pub trait TcpSocketExt {}
pub trait TcpStreamExt {}
pub trait RawSocketExt {}
pub trait LinkAddrExt {}
