//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::{Arc, LazyLock as Lazy};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::yang::key_chains;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::keychain::{Key, Keychain, KeychainKey};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;

use crate::Master;

static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Keychain(String),
    Key(String, u64),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    KeychainChange(String),
    KeychainDelete(String),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(key_chains::key_chain::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("./name").unwrap();
            let keychain = Keychain::new(name.clone());
            master.keychains.insert(name, keychain);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_keychain().unwrap();
            master.keychains.remove(&name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainDelete(name.clone()));
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("./name").unwrap();
            ListEntry::Keychain(name)
        })
        .path(key_chains::key_chain::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::PATH)
        .create_apply(|master, args| {
            let keychain_name = args.list_entry.into_keychain().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();

            let key_id = args.dnode.get_u64_relative("./key-id").unwrap();
            let algo = args.dnode.get_string_relative("./crypto-algorithm").unwrap();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            let key = KeychainKey::new(Key::new(key_id, algo, Default::default()));
            keychain.keys.insert(key_id, key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();

            keychain.keys.remove(&key_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .lookup(|_master, list_entry, dnode| {
            let keychain_name = list_entry.into_keychain().unwrap();

            let key_id = dnode.get_u64_relative("./key-id").unwrap();
            ListEntry::Key(keychain_name, key_id)
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::always::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.send_lifetime.start = None;
            key.send_lifetime.end = None;
            key.accept_lifetime.start = None;
            key.accept_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::start_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.send_lifetime.start = Some(date_time);
            key.accept_lifetime.start = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::no_end_time::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.send_lifetime.end = None;
            key.accept_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::duration::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let seconds  = args.dnode.get_u32();
            let duration = Duration::from_secs(seconds as u64);
            let duration = chrono::Duration::from_std(duration).unwrap();
            if let Some(start) = key.send_lifetime.start {
                key.send_lifetime.end = Some(start + duration);
            }
            if let Some(start) = key.accept_lifetime.start {
                key.accept_lifetime.end = Some(start + duration);
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::end_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.send_lifetime.end = Some(date_time);
            key.accept_lifetime.end = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_lifetime::always::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.send_lifetime.start = None;
            key.send_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_lifetime::start_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.send_lifetime.start = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_lifetime::no_end_time::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.send_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_lifetime::duration::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let seconds  = args.dnode.get_u32();
            let duration = Duration::from_secs(seconds as u64);
            let duration = chrono::Duration::from_std(duration).unwrap();
            if let Some(start) = key.send_lifetime.start {
                key.send_lifetime.end = Some(start + duration);
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::send_lifetime::end_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.send_lifetime.end = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::accept_lifetime::always::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.accept_lifetime.start = None;
            key.accept_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::accept_lifetime::start_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.accept_lifetime.start = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::accept_lifetime::no_end_time::PATH)
        .create_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.accept_lifetime.end = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::accept_lifetime::duration::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let seconds  = args.dnode.get_u32();
            let duration = Duration::from_secs(seconds as u64);
            let duration = chrono::Duration::from_std(duration).unwrap();
            if let Some(start) = key.accept_lifetime.start {
                key.accept_lifetime.end = Some(start + duration);
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::lifetime::accept_lifetime::end_date_time::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let date_time = args.dnode.get_string();
            let date_time = DateTime::<FixedOffset>::parse_from_rfc3339(&date_time).unwrap();
            key.accept_lifetime.end = Some(date_time);

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(key_chains::key_chain::key::crypto_algorithm::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let algo = args.dnode.get_string();
            let algo = CryptoAlgo::try_from_yang(&algo).unwrap();
            key.data.algo = algo;

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .path(key_chains::key_chain::key::key_string::keystring::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let string = args.dnode.get_string();
            key.data.string = string.into_bytes();

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.data.string.clear();

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .path(key_chains::key_chain::key::key_string::hexadecimal_string::PATH)
        .modify_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            let string = args.dnode.get_string();
            key.data.string = string
               .split(':')
               .map(|hex_byte| u8::from_str_radix(hex_byte, 16).unwrap())
               .collect();

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .delete_apply(|master, args| {
            let (keychain_name, key_id) = args.list_entry.into_key().unwrap();
            let keychain = master.keychains.get_mut(&keychain_name).unwrap();
            let key = keychain.keys.get_mut(&key_id).unwrap();

            key.data.string.clear();

            let event_queue = args.event_queue;
            event_queue.insert(Event::KeychainChange(keychain.name.clone()));
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::KeychainChange(name) => {
                let keychain = self.keychains.get_mut(&name).unwrap();

                // Update timestamp of the most recent update.
                keychain.last_modified = Some(Utc::now());

                // Update maximum digest size.
                keychain.max_digest_size = keychain
                    .keys
                    .values()
                    .map(|key| key.data.algo.digest_size())
                    .max()
                    .unwrap_or(0);

                // Create a reference-counted copy of the keychain to be shared among all
                // protocol instances.
                let keychain = Arc::new(keychain.clone());

                // Notify protocols that the keychain has been updated.
                self.ibus_tx.keychain_upd(keychain);
            }
            Event::KeychainDelete(name) => {
                // Notify protocols that the keychain has been deleted.
                self.ibus_tx.keychain_del(name);
            }
        }
    }
}
