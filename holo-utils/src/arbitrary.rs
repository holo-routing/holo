//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//
//
// Stores the custom global arbitrary implementations.

use std::net::{Ipv4Addr, Ipv6Addr};

use arbitrary::{
    Arbitrary, Error as ArbitraryError, Result as ArbitraryResult, Unstructured,
};
use bytes::{BufMut, Bytes, BytesMut};
use ipnetwork::{Ipv4Network, Ipv6Network};

// ===== struct BytesArbitrary =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct BytesArbitrary(
    // Used when implementing external traits on Bytes e.g Arbitrary.
    pub Bytes,
);

// ===== struct BytesMutArbitrary =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct BytesMutArbitrary(
    // Used when implementing external traits on BytesMut e.g Arbitrary.
    pub BytesMut,
);

// ===== struct Ipv4NetworkArbitrary =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct Ipv4NetworkArbitrary(
    // Used when implementing external traits on BytesMut e.g Arbitrary.
    pub Ipv4Network,
);

// ===== struct Ipv6NetworkArbitrary =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct Ipv6NetworkArbitrary(
    // Used when implementing external traits on BytesMut e.g Arbitrary.
    pub Ipv6Network,
);

// ====== impl BytesWrapper =====

impl Arbitrary<'_> for BytesArbitrary {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let len = u.len();
        let peeked_bytes = u.peek_bytes(len).unwrap();
        let buf = Bytes::copy_from_slice(peeked_bytes);
        Ok(Self(buf))
    }
}

// ====== impl BytesMutArbitrary =====

impl Arbitrary<'_> for BytesMutArbitrary {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let len = u.len();
        let peeked_bytes = u.peek_bytes(len).unwrap();
        let mut buf = BytesMut::new();
        buf.put_slice(peeked_bytes);
        Ok(Self(buf))
    }
}

// ====== impl Ipv4NetworkArbitrary =====

impl Arbitrary<'_> for Ipv4NetworkArbitrary {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let ip_addr = Ipv4Addr::arbitrary(u)?;
        let prefix = u8::arbitrary(u)?;
        match Ipv4Network::new(ip_addr, prefix) {
            Ok(net) => Ok(Self(net)),
            Err(_) => Err(ArbitraryError::IncorrectFormat),
        }
    }
}

// ====== impl Ipv6NetworkArbitrary =====

impl Arbitrary<'_> for Ipv6NetworkArbitrary {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let ip_addr = Ipv6Addr::arbitrary(u)?;
        let prefix = u8::arbitrary(u)?;
        match Ipv6Network::new(ip_addr, prefix) {
            Ok(net) => Ok(Self(net)),
            Err(_) => Err(ArbitraryError::IncorrectFormat),
        }
    }
}
