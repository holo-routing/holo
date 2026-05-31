//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use const_addrs::{ip4, sock4};
use holo_utils::capabilities;
use holo_utils::socket::{SocketExt, UdpSocket, UdpSocketExt};

use crate::network::NetworkVersion;
use crate::version::Ripv2;

// RIPv2 multicast address.
static RIPV2_MCAST_ADDR: Ipv4Addr = ip4!("224.0.0.9");
static RIPV2_MCAST_SOCKADDR: SocketAddrV4 = sock4!("224.0.0.9:520");

// ===== impl Ripv2 =====

impl NetworkVersion<Self> for Ripv2 {
    const UDP_PORT: u16 = 520;

    fn socket(ifname: &str) -> Result<UdpSocket, std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            let sockaddr =
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, Self::UDP_PORT));
            let socket =
                capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr))?;
            capabilities::raise(|| {
                socket.bind_device(Some(ifname.as_bytes()))
            })?;
            socket.set_multicast_loop_v4(false)?;
            socket.set_multicast_ttl_v4(1)?;
            socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
            Ok(socket)
        }
        #[cfg(feature = "testing")]
        {
            Ok(UdpSocket {})
        }
    }

    fn join_multicast(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            socket.join_multicast_ifindex_v4(&RIPV2_MCAST_ADDR, ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn leave_multicast(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            socket.leave_multicast_ifindex_v4(&RIPV2_MCAST_ADDR, ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn multicast_sockaddr() -> &'static SocketAddrV4 {
        &RIPV2_MCAST_SOCKADDR
    }
}
