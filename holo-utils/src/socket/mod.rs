//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

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
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct TcpConnInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}
