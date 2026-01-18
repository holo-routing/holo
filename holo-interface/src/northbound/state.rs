//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use enum_as_inner::EnumAsInner;
use holo_northbound::NbDaemonSender;
use holo_northbound::state::{ListEntryKind, Provider, YangList, YangOps};

use crate::Master;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, interfaces};

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Interface(&'a Interface),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {
    fn child_task(&self, module_name: &str) -> Option<NbDaemonSender> {
        match self {
            ListEntry::Interface(iface) if module_name == "ietf-vrrp" => iface.vrrp.as_ref().map(|vrrp| vrrp.nb_tx.clone()),
            _ => None,
        }
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for interfaces::interface::Interface<'a> {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.interfaces.iter().map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        Self {
            name: Cow::Borrowed(&iface.name),
        }
    }
}
