//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

thread_local!(
    pub static TLS_BUF: RefCell<BytesMut> =
        RefCell::new(BytesMut::with_capacity(4096))
);

// Extension methods for Bytes.
pub trait BytesExt {
    /// Gets an unsigned 24 bit integer from `self` in the big-endian byte
    /// order.
    ///
    /// The current position is advanced by 3.
    fn get_u24(&mut self) -> u32;

    /// Gets an IPv4 addr from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    fn get_ipv4(&mut self) -> Ipv4Addr;

    /// Gets an optional IPv4 addr from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    fn get_opt_ipv4(&mut self) -> Option<Ipv4Addr>;

    /// Gets an IPv6 addr from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    fn get_ipv6(&mut self) -> Ipv6Addr;

    /// Gets an optional IPv6 addr from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    fn get_opt_ipv6(&mut self) -> Option<Ipv6Addr>;
}

// Extension methods for BytesMut.
pub trait BytesMutExt {
    /// Writes an unsigned 24 bit integer to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 3.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_u24(&mut self, n: u32);

    /// Writes an IP addr to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4 or 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ip(&mut self, addr: &IpAddr);

    /// Writes an IPv4 addr to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ipv4(&mut self, addr: &Ipv4Addr);

    /// Writes an IPv6 addr to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ipv6(&mut self, addr: &Ipv6Addr);
}

// ===== impl Bytes =====

impl BytesExt for Bytes {
    fn get_u24(&mut self) -> u32 {
        let mut n = [0; 4];
        self.copy_to_slice(&mut n[1..=3]);
        u32::from_be_bytes(n)
    }

    fn get_ipv4(&mut self) -> Ipv4Addr {
        Ipv4Addr::from(self.get_u32())
    }

    fn get_opt_ipv4(&mut self) -> Option<Ipv4Addr> {
        let addr = Ipv4Addr::from(self.get_u32());
        if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        }
    }

    fn get_ipv6(&mut self) -> Ipv6Addr {
        Ipv6Addr::from(self.get_u128())
    }

    fn get_opt_ipv6(&mut self) -> Option<Ipv6Addr> {
        let addr = Ipv6Addr::from(self.get_u128());
        if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        }
    }
}

// ===== impl BytesMut =====

impl BytesMutExt for BytesMut {
    fn put_u24(&mut self, n: u32) {
        let n = n.to_be_bytes();
        self.put_slice(&n[1..=3]);
    }

    fn put_ip(&mut self, addr: &IpAddr) {
        match addr {
            IpAddr::V4(addr) => self.put_slice(&addr.octets()),
            IpAddr::V6(addr) => self.put_slice(&addr.octets()),
        }
    }

    fn put_ipv4(&mut self, addr: &Ipv4Addr) {
        self.put_u32((*addr).into())
    }

    fn put_ipv6(&mut self, addr: &Ipv6Addr) {
        self.put_slice(&addr.octets())
    }
}
