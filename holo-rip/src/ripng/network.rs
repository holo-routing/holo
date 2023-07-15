//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use holo_utils::capabilities;
use holo_utils::socket::{UdpSocket, UdpSocketExt};

use crate::network::NetworkVersion;
use crate::version::Ripng;

// RIPng multicast address.
static RIPNG_MCAST_ADDR: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("FF02::9").unwrap());
static RIPNG_MCAST_SOCKADDR: Lazy<SocketAddr> = Lazy::new(|| {
    SocketAddr::new(IpAddr::V6(*RIPNG_MCAST_ADDR), Ripng::UDP_PORT)
});

// ===== impl Ripng =====

#[async_trait]
impl NetworkVersion for Ripng {
    const UDP_PORT: u16 = 521;

    fn socket(ifname: &str) -> Result<UdpSocket, std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            let sockaddr =
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, Self::UDP_PORT));
            let socket =
                capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr))?;
            capabilities::raise(|| {
                socket.bind_device(Some(ifname.as_bytes()))
            })?;
            socket.set_multicast_loop_v6(false)?;
            socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;

            // "As an additional check, periodic advertisements must have their
            // hop counts set to 255, and inbound, multicast packets
            // sent from the RIPng port (i.e. periodic advertisement
            // or triggered update packets) must be examined to
            // ensure that the hop count is 255".
            socket.set_multicast_hopcount_v6(255)?;
            socket.set_min_hopcount_v6(255)?;

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
            socket.join_multicast_v6(&RIPNG_MCAST_ADDR, ifindex)
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
            socket.leave_multicast_v6(&RIPNG_MCAST_ADDR, ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn set_multicast_if(
        socket: &UdpSocket,
        ifindex: u32,
    ) -> std::io::Result<()> {
        #[cfg(not(feature = "testing"))]
        {
            socket.set_multicast_if_v6(ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn multicast_sockaddr() -> &'static SocketAddr {
        &RIPNG_MCAST_SOCKADDR
    }
}
