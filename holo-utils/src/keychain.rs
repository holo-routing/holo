//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Utc};
use derive_new::new;
use serde::{Deserialize, Serialize};

use crate::crypto::CryptoAlgo;

// Type aliases.
pub type Keychains = BTreeMap<String, Arc<Keychain>>;

// Authentication key-chain.
#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct Keychain {
    // Name of the key-chain.
    pub name: String,
    // Timestamp of the most recent update to the key-chain.
    #[new(default)]
    pub last_modified: Option<DateTime<Utc>>,
    // Maximum digest size among all keys.
    #[new(default)]
    pub max_digest_size: u8,
    // List of configured keys.
    #[new(default)]
    pub keys: BTreeMap<u64, KeychainKey>,
}

// Single key in key-chain.
#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct KeychainKey {
    // Key's data.
    pub data: Key,
    // The key's send lifetime.
    #[new(default)]
    pub send_lifetime: KeyLifetime,
    // The key's accept lifetime.
    #[new(default)]
    pub accept_lifetime: KeyLifetime,
}

// Authentication key.
#[derive(Clone, Debug, new)]
#[derive(Deserialize, Serialize)]
pub struct Key {
    // Numeric value uniquely identifying the key.
    pub id: u64,
    // Cryptographic algorithm associated with the key.
    pub algo: CryptoAlgo,
    // The key string.
    pub string: Vec<u8>,
}

// Key lifetime.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct KeyLifetime {
    // Optional start time.
    pub start: Option<DateTime<FixedOffset>>,
    // Optional end time (`None` means infinite).
    pub end: Option<DateTime<FixedOffset>>,
}

// ===== impl Keychain =====

impl Keychain {
    // Looks up the key used to send a packet. The first key with a valid
    // lifetime will be selected.
    pub fn key_lookup_send(&self) -> Option<&Key> {
        self.keys
            .values()
            .find(|key| key.send_lifetime.is_active())
            .map(|key| &key.data)
    }

    // Looks up the key used to accept a packet. The first key of the provided
    // key ID with a valid lifetime will be selected.
    pub fn key_lookup_accept(&self, key_id: u64) -> Option<&Key> {
        self.keys
            .values()
            .find(|key| key.data.id == key_id)
            .filter(|key| key.accept_lifetime.is_active())
            .map(|key| &key.data)
    }

    // Looks up the first key with a valid accept lifetime, regardless of key ID.
    pub fn key_lookup_accept_any(&self) -> Option<&Key> {
        self.keys
            .values()
            .filter(|key| key.accept_lifetime.is_active())
            .map(|key| &key.data)
            .next()
    }
}

// ===== impl KeyLifetime =====

impl KeyLifetime {
    // Checks if the key lifetime is currently active.
    pub fn is_active(&self) -> bool {
        let now = Utc::now();

        if let Some(start) = self.start {
            if now < start {
                return false;
            }
        }
        if let Some(end) = self.end {
            if now > end {
                return false;
            }
        }

        true
    }
}
