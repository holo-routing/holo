//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangOps};
use sysinfo::System;

use crate::Master;
use crate::northbound::yang_gen::{self, system_state};

impl Provider for Master {
    type ListEntry<'a> = ListEntry;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
pub enum ListEntry {
    #[default]
    None,
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry> + 'a>;

impl ListEntryKind for ListEntry {}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Master> for system_state::platform::Platform<'a> {
    fn new(_master: &'a Master, _list_entry: &ListEntry) -> Option<Self> {
        Some(Self {
            os_name: System::name().map(Cow::Owned),
            os_release: System::kernel_version().map(Cow::Owned),
            os_version: System::os_version().map(Cow::Owned),
            machine: System::cpu_arch().map(Cow::Owned),
        })
    }
}

impl<'a> YangContainer<'a, Master> for system_state::clock::Clock<'a> {
    fn new(_master: &'a Master, _list_entry: &ListEntry) -> Option<Self> {
        let time_now = Utc::now();
        let time_boot = DateTime::from_timestamp(System::boot_time() as i64, 0);
        Some(Self {
            current_datetime: Some(Cow::Owned(time_now)),
            boot_datetime: time_boot.map(Cow::Owned),
        })
    }
}
