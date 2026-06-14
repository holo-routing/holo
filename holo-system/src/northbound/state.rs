//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use holo_northbound::state::{Provider, YangContainer, YangOps};
use sysinfo::System;

use crate::Master;
use crate::northbound::yang_gen::{self, system_state};

impl Provider for Master {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        "/ietf-system:system".to_owned()
    }
}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Master> for system_state::platform::Platform<'a> {
    type ParentListEntry = ();

    fn new(_master: &'a Master, _: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            os_name: System::name().map(Cow::Owned),
            os_release: System::kernel_version().map(Cow::Owned),
            os_version: System::os_version().map(Cow::Owned),
            machine: Some(Cow::Owned(System::cpu_arch())),
        })
    }
}

impl<'a> YangContainer<'a, Master> for system_state::clock::Clock {
    type ParentListEntry = ();

    fn new(_master: &'a Master, _: &Self::ParentListEntry) -> Option<Self> {
        let time_now = Utc::now();
        let time_boot = DateTime::from_timestamp(System::boot_time() as i64, 0);
        Some(Self {
            current_datetime: Some(time_now),
            boot_datetime: time_boot,
        })
    }
}
