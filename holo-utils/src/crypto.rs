//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use holo_yang::{ToYang, TryFromYang};
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum CryptoAlgo {
    ClearText,
    Md5,
    Sha1,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

// Cryptographic Protocol ID.
//
// Unique protocol-specific values for cryptographic applications, including but
// not limited to prevention of cross-protocol replay attacks.
//
// IANA registry:
// https://www.iana.org/assignments/authentication-cryptographic-protocol-id/authentication-cryptographic-protocol-id.xhtml
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum CryptoProtocolId {
    Ospfv3 = 0x01,
    Ldp = 0x02,
    Ospfv2 = 0x03,
}

// A precomputed Apad value used in authentication for many routing protocols.
//
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

// ===== impl CryptoAlgo =====

impl CryptoAlgo {
    pub fn digest_size(&self) -> u8 {
        match self {
            CryptoAlgo::ClearText => unreachable!(),
            CryptoAlgo::Md5 => 16,
            CryptoAlgo::Sha1 => 20,
            CryptoAlgo::HmacMd5 => 16,
            CryptoAlgo::HmacSha1 => 20,
            CryptoAlgo::HmacSha256 => 32,
            CryptoAlgo::HmacSha384 => 48,
            CryptoAlgo::HmacSha512 => 64,
        }
    }
}

impl ToYang for CryptoAlgo {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            CryptoAlgo::ClearText => "ietf-key-chain:cleartext".into(),
            CryptoAlgo::Md5 => "ietf-key-chain:md5".into(),
            CryptoAlgo::Sha1 => "ietf-key-chain:sha-1".into(),
            CryptoAlgo::HmacMd5 => "holo-key-chain:hmac-md5".into(),
            CryptoAlgo::HmacSha1 => "ietf-key-chain:hmac-sha-1".into(),
            CryptoAlgo::HmacSha256 => "ietf-key-chain:hmac-sha-256".into(),
            CryptoAlgo::HmacSha384 => "ietf-key-chain:hmac-sha-384".into(),
            CryptoAlgo::HmacSha512 => "ietf-key-chain:hmac-sha-512".into(),
        }
    }
}

impl TryFromYang for CryptoAlgo {
    fn try_from_yang(identity: &str) -> Option<CryptoAlgo> {
        match identity {
            "ietf-key-chain:cleartext" => Some(CryptoAlgo::ClearText),
            "ietf-key-chain:md5" => Some(CryptoAlgo::Md5),
            "ietf-key-chain:sha-1" => Some(CryptoAlgo::Sha1),
            "holo-key-chain:hmac-md5" => Some(CryptoAlgo::HmacMd5),
            "ietf-key-chain:hmac-sha-1" => Some(CryptoAlgo::HmacSha1),
            "ietf-key-chain:hmac-sha-256" => Some(CryptoAlgo::HmacSha256),
            "ietf-key-chain:hmac-sha-384" => Some(CryptoAlgo::HmacSha384),
            "ietf-key-chain:hmac-sha-512" => Some(CryptoAlgo::HmacSha512),
            _ => None,
        }
    }
}
