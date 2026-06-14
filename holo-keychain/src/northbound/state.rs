//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::state::{ListIterator, Provider, YangList, YangOps};
use holo_utils::keychain::{Keychain, KeychainKey};

use crate::Master;
use crate::northbound::yang_gen::{self, key_chains};

impl Provider for Master {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        "/ietf-key-chain:key-chains".to_owned()
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for key_chains::key_chain::KeyChain<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Keychain;

    fn iter(master: &'a Master, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.keychains.values();
        Some(iter)
    }

    fn new(_master: &'a Master, keychain: &Self::ListEntry) -> Self {
        Self {
            name: keychain.name.as_str().into(),
            last_modified_timestamp: keychain.last_modified,
        }
    }
}

impl<'a> YangList<'a, Master> for key_chains::key_chain::key::Key {
    type ParentListEntry = &'a Keychain;
    type ListEntry = &'a KeychainKey;

    fn iter(_master: &'a Master, keychain: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = keychain.keys.values();
        Some(iter)
    }

    fn new(_master: &'a Master, key: &Self::ListEntry) -> Self {
        Self {
            key_id: key.data.id,
            send_lifetime_active: Some(key.send_lifetime.is_active()),
            accept_lifetime_active: Some(key.accept_lifetime.is_active()),
        }
    }
}
