//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::LazyLock as Lazy;

use holo_northbound::paths::interfaces;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};

use crate::Master;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
pub enum ListEntry {
    #[default]
    None,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::default()
        .path(interfaces::interface::PATH)
        .get_iterate(|_master, _args| {
            // TODO: implement me!
            None
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-interfaces:interfaces";

    type ListEntry<'a> = ListEntry;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry {
    fn get_keys(&self) -> Option<String> {
        None
    }
}
