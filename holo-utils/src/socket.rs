//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{Ipv4Addr, SocketAddr};
use std::os::raw::{c_int, c_void};
use std::os::unix::io::AsRawFd;

use libc::ip_mreqn;
// Normal build: re-export standard socket types.
#[cfg(not(feature = "testing"))]
pub use {
    socket2::Socket,
    tokio::io::unix::AsyncFd,
    tokio::net::{
        tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpSocket,
        TcpStream, UdpSocket,
    },
};

// FFI struct used to set the TCP_MD5SIG socket option.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_md5sig {
    pub tcpm_addr: nix::sys::socket::SockaddrStorage,
    pub tcpm_flags: u8,
    pub tcpm_prefixlen: u8,
    pub tcpm_keylen: u16,
    pub __tcpm_pad: u32,
    pub tcpm_key: [u8; 108],
}

use crate::ip::{AddressFamily, IpAddrKind};
// Test build: export mock sockets.
#[cfg(feature = "testing")]
pub use crate::socket::mock::{
    AsyncFd, OwnedReadHalf, OwnedWriteHalf, Socket, TcpListener, TcpSocket,
    TcpStream, UdpSocket,
};

// Useful type definition.
type Result<T> = std::io::Result<T>;

// Extension methods for UdpSocket.
pub trait UdpSocketExt {
    // Creates a UDP socket not bound to any address.
    #[allow(clippy::new_ret_no_self)]
    fn new(af: AddressFamily) -> Result<UdpSocket>;

    // Creates a UDP socket from the given address.
    //
    // This is the same as [`UdpSocket::bind`], except that the `SO_REUSEADDR`
    // option is set before binding.
    fn bind_reuseaddr(addr: SocketAddr) -> Result<UdpSocket>;

    // Executes an operation of the IP_ADD_MEMBERSHIP type.
    fn join_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()>;

    // Executes an operation of the IP_DROP_MEMBERSHIP type.
    fn leave_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()>;

    // Sets the value of the IP_MULTICAST_IF option for this socket.
    fn set_multicast_if_v4(&self, ifindex: u32) -> Result<()>;

    // Sets the value of the IPV6_MULTICAST_IF option for this socket.
    fn set_multicast_if_v6(&self, ifindex: u32) -> Result<()>;

    // Sets the value of the IP_TOS option for this socket.
    fn set_ipv4_tos(&self, tos: u8) -> Result<()>;

    // Sets the value of the IP_MINTTL option for this socket.
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()>;

    // Sets the value of the IPV6_TCLASS option for this socket.
    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()>;

    // Sets the value of the IPV6_UNICAST_HOPS option for this socket.
    fn set_unicast_hops_v6(&self, hops: u32) -> Result<()>;

    // Sets the value of the IPV6_MULTICAST_HOPS option for this socket.
    fn set_multicast_hopcount_v6(&self, hopcount: u8) -> Result<()>;

    // Sets the value of the IPV6_MINHOPCOUNT option for this socket.
    fn set_min_hopcount_v6(&self, hopcount: u8) -> Result<()>;

    // Sets the value of the IP_PKTINFO option for this socket.
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()>;

    // Sets the value of the IPV6_RECVPKTINFO option for this socket.
    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()>;
}

// Extension methods for TcpSocket.
pub trait TcpSocketExt {
    // Sets the value of the IP_MINTTL option for this socket.
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()>;

    // Sets the value of the IP_TTL option for this socket.
    fn set_ipv4_ttl(&self, ttl: u8) -> Result<()>;

    // Sets the value of the IP_TOS option for this socket.
    fn set_ipv4_tos(&self, tos: u8) -> Result<()>;

    // Sets the value of the IPV6_TCLASS option for this socket.
    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()>;

    // Sets the value of the TCP_MD5SIG option for this socket.
    fn set_md5sig(
        &self,
        dst: &SocketAddr,
        password: Option<&str>,
    ) -> Result<()>;
}

// Extension methods for TcpStream.
pub trait TcpStreamExt {
    // Sets the value of the IP_MINTTL option for this socket.
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()>;
}

// Extension methods for TcpListener.
pub trait TcpListenerExt {
    // Sets the value of the IP_TOS option for this socket.
    fn set_ipv4_tos(&self, tos: u8) -> Result<()>;

    // Sets the value of the IPV6_TCLASS option for this socket.
    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()>;

    // Sets the value of the TCP_MD5SIG option for this socket.
    fn set_md5sig(
        &self,
        dst: &SocketAddr,
        password: Option<&str>,
    ) -> Result<()>;
}

// Extension methods for Socket.
pub trait SocketExt {
    // Sets the value of the IP_PKTINFO option for this socket.
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()>;

    // Sets the value of the IPV6_CHECKSUM option for this socket.
    fn set_ipv6_checksum(&self, offset: i32) -> Result<()>;

    // Sets the value of the IPV6_TCLASS option for this socket.
    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()>;

    // Sets the value of the IPV6_RECVPKTINFO option for this socket.
    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()>;
}

// ===== impl UdpSocket =====

#[cfg(not(feature = "testing"))]
impl UdpSocketExt for UdpSocket {
    fn new(af: AddressFamily) -> Result<UdpSocket> {
        use socket2::{Domain, Type};

        let domain = match af {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        UdpSocket::from_std(socket.into())
    }

    fn bind_reuseaddr(addr: SocketAddr) -> Result<UdpSocket> {
        use socket2::{Domain, Type};

        let domain = match addr.ip().address_family() {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into())
    }

    fn join_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()> {
        let multiaddr: u32 = (*multiaddr).into();

        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: multiaddr.to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as c_int,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    fn leave_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()> {
        let multiaddr: u32 = (*multiaddr).into();

        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: multiaddr.to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as c_int,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_DROP_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    fn set_multicast_if_v4(&self, ifindex: u32) -> Result<()> {
        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr { s_addr: 0 },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as i32,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    fn set_multicast_if_v6(&self, ifindex: u32) -> Result<()> {
        let optval = ifindex as i32;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv4_tos(&self, tos: u8) -> Result<()> {
        let optval = tos as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MINTTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()> {
        let optval = dscp as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_unicast_hops_v6(&self, hops: u32) -> Result<()> {
        let optval = hops as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_multicast_hopcount_v6(&self, hopcount: u8) -> Result<()> {
        let optval = hopcount as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_min_hopcount_v6(&self, hopcount: u8) -> Result<()> {
        let optval = hopcount as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MINHOPCOUNT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

// ===== impl TcpSocket =====

#[cfg(not(feature = "testing"))]
impl TcpSocketExt for TcpSocket {
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MINTTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv4_ttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv4_tos(&self, tos: u8) -> Result<()> {
        let optval = tos as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()> {
        let optval = dscp as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_md5sig(
        &self,
        dst: &SocketAddr,
        password: Option<&str>,
    ) -> Result<()> {
        let mut optval = tcp_md5sig {
            tcpm_addr: (*dst).into(),
            tcpm_flags: 0,
            tcpm_prefixlen: 0,
            tcpm_keylen: 0,
            __tcpm_pad: 0,
            tcpm_key: [0; 108],
        };
        if let Some(password) = password {
            optval.tcpm_keylen = password.len() as u16;
            optval.tcpm_key[..password.len()]
                .copy_from_slice(password.as_bytes());
        }

        setsockopt(
            self,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<tcp_md5sig>() as libc::socklen_t,
        )
    }
}

// ===== impl TcpStream =====

#[cfg(not(feature = "testing"))]
impl TcpStreamExt for TcpStream {
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MINTTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

// ===== impl TcpListener =====

#[cfg(not(feature = "testing"))]
impl TcpListenerExt for TcpListener {
    fn set_ipv4_tos(&self, tos: u8) -> Result<()> {
        let optval = tos as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()> {
        let optval = dscp as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_md5sig(
        &self,
        dst: &SocketAddr,
        password: Option<&str>,
    ) -> Result<()> {
        let mut optval = tcp_md5sig {
            tcpm_addr: (*dst).into(),
            tcpm_flags: 0,
            tcpm_prefixlen: 0,
            tcpm_keylen: 0,
            __tcpm_pad: 0,
            tcpm_key: [0; 108],
        };
        if let Some(password) = password {
            optval.tcpm_keylen = password.len() as u16;
            optval.tcpm_key[..password.len()]
                .copy_from_slice(password.as_bytes());
        }

        setsockopt(
            self,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<tcp_md5sig>() as libc::socklen_t,
        )
    }
}

// ===== impl Socket =====

#[cfg(not(feature = "testing"))]
impl SocketExt for Socket {
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_checksum(&self, offset: i32) -> Result<()> {
        let optval = offset as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()> {
        let optval = dscp as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

// ===== Mock sockets for unit testing =====

pub mod mock {
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
}

// ===== global functions =====

fn setsockopt<F: AsRawFd>(
    sock: &F,
    opt: c_int,
    val: c_int,
    optval: *const c_void,
    optlen: libc::socklen_t,
) -> Result<()> {
    let ret;

    unsafe {
        ret = libc::setsockopt(sock.as_raw_fd(), opt, val, optval, optlen);
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
