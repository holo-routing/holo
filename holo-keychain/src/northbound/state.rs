//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::key_chains;
use holo_utils::keychain::{Keychain, KeychainKey};

use crate::Master;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Keychain(&'a Keychain),
    Key(&'a KeychainKey),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(key_chains::key_chain::PATH)
        .get_iterate(|master, _args| {
            let iter = master.keychains.values().map(ListEntry::Keychain);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use key_chains::key_chain::KeyChain;
            let keychain = args.list_entry.as_keychain().unwrap();
            Box::new(KeyChain {
                name: keychain.name.as_str().into(),
                last_modified_timestamp: keychain
                    .last_modified
                    .as_ref()
                    .map(Cow::Borrowed),
            })
        })
        .path(key_chains::key_chain::key::PATH)
        .get_iterate(|_master, args| {
            let keychain = args.parent_list_entry.as_keychain().unwrap();
            let iter = keychain.keys.values().map(ListEntry::Key);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use key_chains::key_chain::key::Key;
            let key = args.list_entry.as_key().unwrap();
            Box::new(Key {
                key_id: key.data.id,
                send_lifetime_active: Some(key.send_lifetime.is_active()),
                accept_lifetime_active: Some(key.accept_lifetime.is_active()),
            })
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}
