//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::interfaces;

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
            // No operational data under this list.
            None
        })
        .path(interfaces::interface::ipv4::address::PATH)
        .get_iterate(|_context, _args| {
            // No operational data under this list.
            None
        })
        .path(interfaces::interface::ipv6::address::PATH)
        .get_iterate(|_context, _args| {
            // No operational data under this list.
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
