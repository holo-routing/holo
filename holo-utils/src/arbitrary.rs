//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use bytes::Bytes;

// Used when implementing external traits on Bytes e.g Arbitrary.
#[allow(dead_code)]
#[derive(Debug)]
pub struct BytesArbitrary(pub Bytes);

// ====== impl BytesArbitrary =====

impl Arbitrary<'_> for BytesArbitrary {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        let len = u.len();
        let peeked_bytes = u.peek_bytes(len).unwrap();
        let buf = Bytes::copy_from_slice(peeked_bytes);
        Ok(Self(buf))
    }
}
