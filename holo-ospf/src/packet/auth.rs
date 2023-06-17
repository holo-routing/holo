//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use derive_new::new;
use holo_utils::crypto::CryptoAlgo;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct AuthCtx {
    // Authentication key.
    pub key: String,
    // Authentication key ID.
    pub key_id: u32,
    // Authentication cryptographic algorithm.
    pub algo: CryptoAlgo,
    // Non-decreasing sequence number (only used for encoding packets).
    pub seqno: Arc<AtomicU32>,
}

// ===== global functions =====

pub(crate) fn md5_digest(data: &[u8], auth_key: &str) -> [u8; 16] {
    // The authentication key needs to be 16-bytes long.
    let mut auth_key = auth_key.as_bytes().to_vec();
    auth_key.resize(16, 0);

    let mut ctx = md5::Context::new();
    ctx.consume(data);
    ctx.consume(&auth_key);
    *ctx.compute()
}
