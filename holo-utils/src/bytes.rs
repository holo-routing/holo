//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};

use crate::mac_addr::MacAddr;

thread_local!(
    pub static TLS_BUF: RefCell<BytesMut> =
        RefCell::new(BytesMut::with_capacity(65536))
);

// Extension methods for Bytes.
pub trait BytesExt {
    /// Generate an arbitrary value of `Bytes` from the given unstructured data.
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Bytes>;

    /// Gets an unsigned 24 bit integer from `self` in the big-endian byte
    /// order.
    ///
    /// The current position is advanced by 3.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_u24(&mut self) -> u32;

    /// Gets an unsigned 24 bit integer from `self` in the big-endian byte
    /// order.
    ///
    /// The current position is advanced by 3.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_u24(&mut self) -> Result<u32, TryGetError>;

    /// Gets an IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_ipv4(&mut self) -> Ipv4Addr;

    /// Gets an IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_ipv4(&mut self) -> Result<Ipv4Addr, TryGetError>;

    /// Gets an optional IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_opt_ipv4(&mut self) -> Option<Ipv4Addr>;

    /// Gets an optional IPv4 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_opt_ipv4(&mut self) -> Result<Option<Ipv4Addr>, TryGetError>;

    /// Gets an IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_ipv6(&mut self) -> Ipv6Addr;

    /// Gets an IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_ipv6(&mut self) -> Result<Ipv6Addr, TryGetError>;

    /// Gets an optional IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_opt_ipv6(&mut self) -> Option<Ipv6Addr>;

    /// Gets an optional IPv6 address from `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_opt_ipv6(&mut self) -> Result<Option<Ipv6Addr>, TryGetError>;

    /// Gets a MAC address from `self`.
    ///
    /// The current position is advanced by 6.
    ///
    /// # Panics
    ///
    /// This function panics if there is no more remaining data in `self`.
    fn get_mac(&mut self) -> MacAddr;

    /// Gets a MAC address from `self`.
    ///
    /// The current position is advanced by 6.
    ///
    /// Returns `Err(TryGetError)` when there are not enough remaining bytes to
    /// read the value.
    fn try_get_mac(&mut self) -> Result<MacAddr, TryGetError>;
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

    /// Writes an IP address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4 or 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ip(&mut self, addr: &IpAddr);

    /// Writes an IPv4 address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 4.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ipv4(&mut self, addr: &Ipv4Addr);

    /// Writes an IPv6 address to `self` in big-endian byte order.
    ///
    /// The current position is advanced by 16.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_ipv6(&mut self, addr: &Ipv6Addr);

    /// Writes a MAC address to `self`.
    ///
    /// The current position is advanced by 6.
    ///
    /// # Panics
    ///
    /// This function panics if there is not enough remaining capacity in
    /// `self`.
    fn put_mac(&mut self, addr: &MacAddr);
}

// ===== impl Bytes =====

impl BytesExt for Bytes {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Bytes> {
        let len = u.len();
        let bytes = u.bytes(len)?;
        Ok(Bytes::copy_from_slice(bytes))
    }

    fn get_u24(&mut self) -> u32 {
        self.try_get_u24().unwrap()
    }

    fn try_get_u24(&mut self) -> Result<u32, TryGetError> {
        let mut n = [0; 4];
        self.try_copy_to_slice(&mut n[1..=3])?;
        Ok(u32::from_be_bytes(n))
    }

    fn get_ipv4(&mut self) -> Ipv4Addr {
        self.try_get_ipv4().unwrap()
    }

    fn try_get_ipv4(&mut self) -> Result<Ipv4Addr, TryGetError> {
        let bytes = self.try_get_u32()?;
        Ok(Ipv4Addr::from(bytes))
    }

    fn get_opt_ipv4(&mut self) -> Option<Ipv4Addr> {
        self.try_get_opt_ipv4().unwrap()
    }

    fn try_get_opt_ipv4(&mut self) -> Result<Option<Ipv4Addr>, TryGetError> {
        let bytes = self.try_get_u32()?;
        let addr = Ipv4Addr::from(bytes);
        Ok((!addr.is_unspecified()).then_some(addr))
    }

    fn get_ipv6(&mut self) -> Ipv6Addr {
        self.try_get_ipv6().unwrap()
    }

    fn try_get_ipv6(&mut self) -> Result<Ipv6Addr, TryGetError> {
        let bytes = self.try_get_u128()?;
        Ok(Ipv6Addr::from(bytes))
    }

    fn get_opt_ipv6(&mut self) -> Option<Ipv6Addr> {
        self.try_get_opt_ipv6().unwrap()
    }

    fn try_get_opt_ipv6(&mut self) -> Result<Option<Ipv6Addr>, TryGetError> {
        let bytes = self.try_get_u128()?;
        let addr = Ipv6Addr::from(bytes);
        Ok((!addr.is_unspecified()).then_some(addr))
    }

    fn get_mac(&mut self) -> MacAddr {
        self.try_get_mac().unwrap()
    }

    fn try_get_mac(&mut self) -> Result<MacAddr, TryGetError> {
        let mut bytes: [u8; MacAddr::LENGTH] = [0; MacAddr::LENGTH];
        self.try_copy_to_slice(&mut bytes)?;
        Ok(MacAddr::from(bytes))
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

    fn put_mac(&mut self, addr: &MacAddr) {
        self.put_slice(&addr.as_bytes())
    }
}
