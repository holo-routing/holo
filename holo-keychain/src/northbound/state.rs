//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::paths::key_chains;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_utils::keychain::{Keychain, KeychainKey};

use crate::Master;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Keychain(&'a Keychain),
    Key(&'a KeychainKey),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::default()
        .path(key_chains::key_chain::PATH)
        .get_iterate(|master: &Master, _args| {
            let iter = master.keychains.values().map(ListEntry::Keychain);
            Some(Box::new(iter))
        })
        .path(key_chains::key_chain::last_modified_timestamp::PATH)
        .get_element_date_and_time(|_master, args| {
            let keychain = args.list_entry.as_keychain().unwrap();
            keychain.last_modified
        })
        .path(key_chains::key_chain::key::PATH)
        .get_iterate(|_master, args| {
            let keychain = args.parent_list_entry.as_keychain().unwrap();
            let iter = keychain.keys.values().map(ListEntry::Key);
            Some(Box::new(iter))
        })
        .path(key_chains::key_chain::key::send_lifetime_active::PATH)
        .get_element_bool(|_master, args| {
            let key = args.list_entry.as_key().unwrap();
            Some(key.send_lifetime.is_active())
        })
        .path(key_chains::key_chain::key::accept_lifetime_active::PATH)
        .get_element_bool(|_master, args| {
            let key = args.list_entry.as_key().unwrap();
            Some(key.accept_lifetime.is_active())
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-key-chain:key-chains";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::Keychain(keychain) => {
                use key_chains::key_chain::list_keys;
                let keys = list_keys(&keychain.name);
                Some(keys)
            }
            ListEntry::Key(key) => {
                use key_chains::key_chain::key::list_keys;
                let keys = list_keys(key.data.id);
                Some(keys)
            }
        }
    }
}
