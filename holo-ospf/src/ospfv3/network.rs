//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use bytes::Bytes;
use holo_utils::capabilities;
use holo_utils::socket::{Socket, SocketExt};
use ipnetwork::Ipv6Network;
use nix::sys::socket::{self, SockaddrIn6};

use crate::network::{MulticastAddr, NetworkVersion, OSPF_IP_PROTO};
use crate::ospfv3;
use crate::packet::error::DecodeResult;
use crate::version::Ospfv3;

// OSPFv3 multicast addresses.
static ALL_SPF_RTRS: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("FF02::5").unwrap());
static ALL_DR_RTRS: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("FF02::6").unwrap());

// ===== impl Ospfv3 =====

impl NetworkVersion<Self> for Ospfv3 {
    type NetIpAddr = Ipv6Addr;
    type NetIpNetwork = Ipv6Network;
    type SocketAddr = SockaddrIn6;
    type Pktinfo = libc::in6_pktinfo;

    fn socket(ifname: &str) -> Result<Socket, std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            use socket2::{Domain, Protocol, Type};

            let socket = capabilities::raise(|| {
                Socket::new(
                    Domain::IPV6,
                    Type::RAW,
                    Some(Protocol::from(OSPF_IP_PROTO)),
                )
            })?;

            socket.set_nonblocking(true)?;
            socket.bind_device(Some(ifname.as_bytes()))?;
            socket.set_multicast_loop_v6(false)?;
            // NOTE: IPV6_MULTICAST_HOPS is 1 by default.
            socket.set_ipv6_pktinfo(true)?;
            socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;

            Ok(socket)
        }
        #[cfg(feature = "testing")]
        {
            Ok(Socket {})
        }
    }

    fn set_cksum_offloading(
        socket: &Socket,
        enable: bool,
    ) -> Result<(), std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            let offset = if enable {
                ospfv3::packet::PacketHdr::CHECKSUM_OFFSET
            } else {
                -1
            };
            socket.set_ipv6_checksum(offset)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn multicast_addr(addr: MulticastAddr) -> &'static Ipv6Addr {
        match addr {
            MulticastAddr::AllSpfRtrs => &ALL_SPF_RTRS,
            MulticastAddr::AllDrRtrs => &ALL_DR_RTRS,
        }
    }

    fn join_multicast(
        socket: &Socket,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            let addr = Self::multicast_addr(addr);
            let socket = socket2::SockRef::from(socket);
            socket.join_multicast_v6(addr, ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn leave_multicast(
        socket: &Socket,
        addr: MulticastAddr,
        ifindex: u32,
    ) -> Result<(), std::io::Error> {
        #[cfg(not(feature = "testing"))]
        {
            let addr = Self::multicast_addr(addr);
            let socket = socket2::SockRef::from(socket);
            socket.leave_multicast_v6(addr, ifindex)
        }
        #[cfg(feature = "testing")]
        {
            Ok(())
        }
    }

    fn new_pktinfo(src: Option<Ipv6Addr>, ifindex: u32) -> libc::in6_pktinfo {
        libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src.unwrap_or(Ipv6Addr::UNSPECIFIED).octets(),
            },
            ipi6_ifindex: ifindex,
        }
    }

    fn set_cmsg_data(
        pktinfo: &libc::in6_pktinfo,
    ) -> socket::ControlMessage<'_> {
        socket::ControlMessage::Ipv6PacketInfo(pktinfo)
    }

    fn get_cmsg_data(mut cmsgs: socket::CmsgIterator<'_>) -> Option<Ipv6Addr> {
        cmsgs.find_map(|cmsg| {
            if let socket::ControlMessageOwned::Ipv6PacketInfo(pktinfo) = cmsg {
                let dst = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
                Some(dst)
            } else {
                None
            }
        })
    }

    fn dst_to_sockaddr(ifindex: u32, addr: Ipv6Addr) -> SockaddrIn6 {
        std::net::SocketAddrV6::new(addr, 0, 0, ifindex).into()
    }

    fn src_from_sockaddr(sockaddr: &SockaddrIn6) -> Ipv6Addr {
        sockaddr.ip()
    }

    // NOTE: by default, the IPv6 raw socket API does not include the IPv6
    // header in the received packets.
    fn validate_ip_hdr(_buf: &mut Bytes) -> DecodeResult<()> {
        Ok(())
    }
}
