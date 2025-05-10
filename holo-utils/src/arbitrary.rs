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

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use bytes::{BufMut, Bytes, BytesMut};

// ===== struct BytesArbitrary =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct BytesArbitrary(
    // Used when implementing external traits on Bytes e.g Arbitrary.
    pub Bytes,
);

// ===== struct BytesMutWrapper =====

#[allow(dead_code)]
#[derive(Debug)]
pub struct BytesMutWrapper(
    // Used when implementing external traits on BytesMut e.g Arbitrary.
    pub BytesMut,
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

// ====== impl BytesWrapper =====

impl Arbitrary<'_> for BytesMutWrapper {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let len = u.len();
        let peeked_bytes = u.peek_bytes(len).unwrap();
        let mut buf = BytesMut::new();
        buf.put_slice(peeked_bytes);
        Ok(Self(buf))
    }
}
