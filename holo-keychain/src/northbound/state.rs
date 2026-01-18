//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangList, YangOps};
use holo_utils::keychain::{Keychain, KeychainKey};

use crate::Master;
use crate::northbound::yang_gen::{self, key_chains};

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Keychain(&'a Keychain),
    Key(&'a KeychainKey),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for key_chains::key_chain::KeyChain<'a> {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.keychains.values().map(ListEntry::Keychain);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let keychain = list_entry.as_keychain().unwrap();
        Self {
            name: keychain.name.as_str().into(),
            last_modified_timestamp: keychain.last_modified.as_ref().map(Cow::Borrowed),
        }
    }
}

impl<'a> YangList<'a, Master> for key_chains::key_chain::key::Key {
    fn iter(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let keychain = list_entry.as_keychain().unwrap();
        let iter = keychain.keys.values().map(ListEntry::Key);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let key = list_entry.as_key().unwrap();
        Self {
            key_id: key.data.id,
            send_lifetime_active: Some(key.send_lifetime.is_active()),
            accept_lifetime_active: Some(key.accept_lifetime.is_active()),
        }
    }
}
