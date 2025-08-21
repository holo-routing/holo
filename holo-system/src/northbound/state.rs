//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use chrono::{DateTime, Utc};
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::system_state;
use sysinfo::System;

use crate::Master;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default)]
pub enum ListEntry {
    #[default]
    None,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(system_state::platform::PATH)
        .get_object(|_context, _args| {
            use system_state::platform::Platform;
            Box::new(Platform {
                os_name: System::name().map(Cow::Owned),
                os_release: System::kernel_version().map(Cow::Owned),
                os_version: System::os_version().map(Cow::Owned),
                machine: System::cpu_arch().map(Cow::Owned),
            })
        })
        .path(system_state::clock::PATH)
        .get_object(|_context, _args| {
            use system_state::clock::Clock;
            let time_now = Utc::now();
            let time_boot =
                DateTime::from_timestamp(System::boot_time() as i64, 0);
            Box::new(Clock {
                current_datetime: Some(Cow::Owned(time_now)),
                boot_datetime: time_boot.map(Cow::Owned),
            })
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry<'a> = ListEntry;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry {}
