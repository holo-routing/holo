//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_northbound::NbDaemonSender;
use holo_northbound::state::{ListIterator, Provider, YangList, YangOps};

use crate::Master;
use crate::interface::Interface;
use crate::northbound::yang_gen::{self, interfaces};

impl Provider for Master {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        "/ietf-interfaces:interfaces".to_owned()
    }
}

// ===== YANG impls =====

impl<'a> YangList<'a, Master> for interfaces::interface::Interface<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Interface;

    fn iter(master: &'a Master, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = master.interfaces.iter();
        Some(iter)
    }

    fn new(_master: &'a Master, iface: &Self::ListEntry) -> Self {
        Self {
            name: Cow::Borrowed(&iface.name),
        }
    }

    fn child_task(iface: &Self::ListEntry, module_name: &str) -> Option<NbDaemonSender> {
        if module_name == "ietf-vrrp" { iface.vrrp.as_ref().map(|vrrp| vrrp.nb_tx.clone()) } else { None }
    }
}
