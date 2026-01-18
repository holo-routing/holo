//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangOps};

use crate::Master;
use crate::northbound::yang_gen;

impl Provider for Master {
    type ListEntry<'a> = ListEntry;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry> + 'a>;

impl ListEntryKind for ListEntry {}
