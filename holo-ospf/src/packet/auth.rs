//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::atomic::AtomicU32;
use std::sync::{Arc, LazyLock as Lazy};

use derive_new::new;
use hmac::digest::block_buffer::Eager;
use hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
};
use hmac::digest::typenum::{IsLess, Le, NonZero, U256};
use hmac::digest::{HashMarker, Mac};
use hmac::Hmac;
use holo_utils::crypto::CryptoAlgo;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

pub static HMAC_APAD: Lazy<Vec<u8>> = Lazy::new(|| {
    [0x87, 0x8F, 0xE1, 0xF3]
        .into_iter()
        .cycle()
        .take(64)
        .collect()
});

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

// ===== helper functions =====

fn md5_digest(data: &[u8], auth_key: &str) -> [u8; 16] {
    // The authentication key needs to be 16-bytes long.
    let mut auth_key = auth_key.as_bytes().to_vec();
    auth_key.resize(16, 0);

    let mut ctx = md5::Context::new();
    ctx.consume(data);
    ctx.consume(&auth_key);
    *ctx.compute()
}

fn hmac_sha_digest<H>(
    data: &[u8],
    auth_key: &str,
    digest_size: usize,
) -> Vec<u8>
where
    H: CoreProxy,
    H::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <H::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<H::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut mac = Hmac::<H>::new_from_slice(auth_key.as_bytes()).unwrap();
    mac.update(data);
    // TODO: infer digest size from the generic H type.
    mac.update(&HMAC_APAD[..digest_size]);
    let digest = mac.finalize();
    digest.into_bytes().to_vec()
}

// ===== global functions =====

pub(crate) fn message_digest(
    data: &[u8],
    algo: CryptoAlgo,
    key: &str,
) -> Vec<u8> {
    let dsize = algo.digest_size() as usize;
    match algo {
        CryptoAlgo::Md5 => md5_digest(data, key).to_vec(),
        CryptoAlgo::HmacSha1 => hmac_sha_digest::<Sha1>(data, key, dsize),
        CryptoAlgo::HmacSha256 => hmac_sha_digest::<Sha256>(data, key, dsize),
        CryptoAlgo::HmacSha384 => hmac_sha_digest::<Sha384>(data, key, dsize),
        CryptoAlgo::HmacSha512 => hmac_sha_digest::<Sha512>(data, key, dsize),
        _ => {
            // Other algorithms can't be configured (e.g. Keyed SHA1).
            unreachable!()
        }
    }
}
