//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use hmac::Hmac;
use hmac::digest::block_buffer::Eager;
use hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
};
use hmac::digest::typenum::{IsLess, Le, NonZero, U256};
use hmac::digest::{HashMarker, Mac};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::keychain::{Key, Keychain};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

#[derive(Clone, Debug)]
pub enum AuthMethod {
    ManualKey(Key),
    Keychain(Arc<Keychain>),
}

// ===== impl AuthMethod =====

impl AuthMethod {
    pub(crate) fn get_key_send(&self) -> Option<&Key> {
        match self {
            AuthMethod::ManualKey(key) => Some(key),
            AuthMethod::Keychain(keychain) => keychain.key_lookup_send(),
        }
    }

    pub(crate) fn get_key_accept_any(&self) -> Option<&Key> {
        match self {
            AuthMethod::ManualKey(key) => Some(key),
            AuthMethod::Keychain(keychain) => keychain.key_lookup_accept_any(),
        }
    }

    pub(crate) fn get_key_accept(&self, key_id: u16) -> Option<&Key> {
        match self {
            AuthMethod::ManualKey(key) => {
                (key.id == key_id as u64).then_some(key)
            }
            AuthMethod::Keychain(keychain) => {
                keychain.key_lookup_accept(key_id as u64)
            }
        }
    }
}

// ===== helper functions =====

fn hmac_digest<H>(data: &[u8], key: &[u8]) -> Vec<u8>
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
    // Compute the message digest.
    let mut mac = Hmac::<H>::new_from_slice(key).unwrap();
    mac.update(data);
    let digest = mac.finalize();
    digest.into_bytes().to_vec()
}

// ===== global functions =====

pub(crate) fn message_digest(
    data: &[u8],
    algo: CryptoAlgo,
    key: &[u8],
) -> Vec<u8> {
    match algo {
        CryptoAlgo::HmacMd5 => hmac_digest::<Md5>(data, key),
        CryptoAlgo::HmacSha1 => hmac_digest::<Sha1>(data, key),
        CryptoAlgo::HmacSha256 => hmac_digest::<Sha256>(data, key),
        CryptoAlgo::HmacSha384 => hmac_digest::<Sha384>(data, key),
        CryptoAlgo::HmacSha512 => hmac_digest::<Sha512>(data, key),
        _ => {
            // Other algorithms can't be configured.
            unreachable!()
        }
    }
}
