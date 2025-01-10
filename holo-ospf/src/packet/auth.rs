//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock as Lazy};

use derive_new::new;
use hmac::Hmac;
use hmac::digest::block_buffer::Eager;
use hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore,
};
use hmac::digest::typenum::{IsLess, Le, NonZero, U256};
use hmac::digest::{HashMarker, Mac, OutputSizeUser};
use holo_utils::crypto::{CryptoAlgo, CryptoProtocolId};
use holo_utils::ip::{Ipv4AddrExt, Ipv6AddrExt};
use holo_utils::keychain::{Key, Keychain};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

// Apad is the hexadecimal value 0x878FE1F3 repeated (L/4) times, where L is the
// length of the hash, measured in bytes.
//
// The read-only Apad defined here is designed to accommodate the largest
// supported hash length, which is 64 bytes for SHA512.
pub static HMAC_APAD: Lazy<Vec<u8>> = Lazy::new(|| {
    [0x87, 0x8F, 0xE1, 0xF3]
        .into_iter()
        .cycle()
        .take(64)
        .collect()
});

#[derive(Clone, Debug)]
pub enum AuthMethod {
    ManualKey(Key),
    Keychain(Arc<Keychain>),
}

#[derive(Clone, Copy, Debug, new)]
pub struct AuthEncodeCtx<'a> {
    // Authentication key.
    pub key: &'a Key,
    // Authentication sequence number.
    pub seqno: &'a Arc<AtomicU64>,
    // Packet source.
    pub src_addr: IpAddr,
}

#[derive(Clone, Debug, new)]
pub struct AuthDecodeCtx<'a> {
    // Authentication method.
    pub method: &'a AuthMethod,
    // Packet source.
    pub src_addr: IpAddr,
}

// ===== helper functions =====

fn keyed_md5_digest(data: &[u8], key: &[u8]) -> [u8; 16] {
    // The authentication key needs to be 16-bytes long.
    let mut key = key.to_vec();
    key.resize(16, 0);

    let mut ctx = md5::Context::new();
    ctx.consume(data);
    ctx.consume(&key);
    *ctx.compute()
}

fn hmac_sha_digest<H>(
    data: &[u8],
    key: &[u8],
    proto_id: Option<CryptoProtocolId>,
    src: Option<&IpAddr>,
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
    let mut key = key;
    let key_proto: Vec<u8>;

    // Append Cryptographic Protocol ID to the authentication key.
    if let Some(proto_id) = proto_id {
        let proto_id = proto_id as u16;
        key_proto = [key, &proto_id.to_be_bytes()].concat();
        key = &key_proto;
    }

    // Compute the message digest.
    let mut mac = Hmac::<H>::new_from_slice(key).unwrap();
    mac.update(data);
    let digest_size = H::Core::output_size();
    match src {
        Some(IpAddr::V4(addr)) => {
            // RFC 7474 Section 5 says:
            // "Initialize the first 4 octets of Apad to the IP source address
            // from the IP header of the incoming OSPFv2 packet. The remainder
            // of Apad will contain the value 0x878FE1F3 repeated (L - 4)/4
            // times".
            mac.update(&addr.octets());
            mac.update(&HMAC_APAD[..digest_size - Ipv4Addr::LENGTH]);
        }
        Some(IpAddr::V6(addr)) => {
            // RFC 7166 Section 4.5 says:
            // "Apad is a value that is the same length as the hash output or
            // message digest. The first 16 octets contain the IPv6 source
            // address followed by the hexadecimal value 0x878FE1F3 repeated
            // (L-16)/4 times".
            mac.update(&addr.octets());
            mac.update(&HMAC_APAD[..digest_size - Ipv6Addr::LENGTH]);
        }
        None => {
            mac.update(&HMAC_APAD[..digest_size]);
        }
    }
    let digest = mac.finalize();
    digest.into_bytes().to_vec()
}

// ===== global functions =====

pub(crate) fn message_digest(
    data: &[u8],
    algo: CryptoAlgo,
    key: &[u8],
    proto_id: Option<CryptoProtocolId>,
    src: Option<&IpAddr>,
) -> Vec<u8> {
    match algo {
        CryptoAlgo::Md5 => keyed_md5_digest(data, key).to_vec(),
        CryptoAlgo::HmacSha1 => {
            hmac_sha_digest::<Sha1>(data, key, proto_id, src)
        }
        CryptoAlgo::HmacSha256 => {
            hmac_sha_digest::<Sha256>(data, key, proto_id, src)
        }
        CryptoAlgo::HmacSha384 => {
            hmac_sha_digest::<Sha384>(data, key, proto_id, src)
        }
        CryptoAlgo::HmacSha512 => {
            hmac_sha_digest::<Sha512>(data, key, proto_id, src)
        }
        _ => {
            // Other algorithms can't be configured (e.g. Keyed SHA1).
            unreachable!()
        }
    }
}
