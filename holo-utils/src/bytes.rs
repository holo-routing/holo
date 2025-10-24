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
#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::mpls::Label;

    #[test]
    fn test_try_get_u24() {
        // Test successful parsing
        let mut bytes = Bytes::from(vec![0x01, 0x02, 0x03]);
        assert_eq!(bytes.try_get_u24().unwrap(), 0x010203);

        // Test insufficient bytes
        let mut bytes = Bytes::from(vec![0x01, 0x02]);
        assert!(bytes.try_get_u24().is_err());
    }

    #[test]
    fn test_try_get_u24_valid_values() {
        // Test valid 24-bit values
        let test_cases = vec![
            (vec![0x00, 0x00, 0x00], 0x000000), // Minimum value
            (vec![0x00, 0x00, 0x01], 0x000001), // Minimum non-zero
            (vec![0x00, 0x01, 0x00], 0x000100), // Single byte in middle position
            (vec![0x01, 0x00, 0x00], 0x010000), // Single byte in high position
            (vec![0xFF, 0xFF, 0xFF], 0xFFFFFF), // Maximum 24-bit value
            (vec![0x12, 0x34, 0x56], 0x123456), // Random value
            (vec![0x0F, 0xFF, 0xFF], 0x0FFFFF), // Maximum valid MPLS label
        ];

        for (input_bytes, expected) in test_cases {
            let mut buf = Bytes::from(input_bytes.clone());
            let result = buf.try_get_u24().unwrap();
            assert_eq!(
                result, expected,
                "Failed for input: {:02X?}",
                input_bytes
            );
            assert_eq!(buf.remaining(), 0, "Buffer should be fully consumed");
        }
    }

    #[test]
    fn test_try_get_u24_insufficient_data() {
        // Test cases with insufficient data
        let test_cases = vec![
            vec![],           // Empty buffer
            vec![0x12],       // 1 byte
            vec![0x12, 0x34], // 2 bytes
        ];

        for input_bytes in test_cases {
            let mut buf = Bytes::from(input_bytes.clone());
            let result = buf.try_get_u24();
            assert!(
                result.is_err(),
                "Should fail for input: {:02X?}",
                input_bytes
            );
            assert!(
                matches!(result, Err(_try_get_error)),
                "Should return TryGetError"
            );
        }
    }

    #[test]
    fn test_try_get_u24_with_extra_data() {
        // Test that try_get_u24 only consumes 3 bytes and leaves the rest
        let input = vec![0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut buf = Bytes::from(input);

        let result = buf.try_get_u24().unwrap();
        assert_eq!(result, 0x123456);
        assert_eq!(buf.remaining(), 2, "Should have 2 bytes remaining");

        // Verify remaining bytes are correct
        assert_eq!(buf.get_u8(), 0x78);
        assert_eq!(buf.get_u8(), 0x9A);
    }

    #[test]
    fn test_try_get_u24_multiple_calls() {
        // Test multiple consecutive calls to try_get_u24
        let input = vec![0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF];
        let mut buf = Bytes::from(input);

        let first = buf.try_get_u24().unwrap();
        assert_eq!(first, 0x123456);

        let second = buf.try_get_u24().unwrap();
        assert_eq!(second, 0xABCDEF);

        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_put_u24_large_values() {
        // Test that put_u24 properly truncates large values to 24 bits
        let test_cases = vec![
            (0x01000000, vec![0x00, 0x00, 0x00]), // Truncated to 0
            (0x01123456, vec![0x12, 0x34, 0x56]), // High byte dropped
            (0xFF123456, vec![0x12, 0x34, 0x56]), // High byte dropped
        ];

        for (input_value, expected_bytes) in test_cases {
            let mut buf = BytesMut::new();
            buf.put_u24(input_value);

            let result_bytes: Vec<u8> = buf.to_vec();
            assert_eq!(
                result_bytes, expected_bytes,
                "put_u24 failed for input: 0x{:08X}",
                input_value
            );
        }
    }
}
