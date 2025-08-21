//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::interfaces;
use holo_northbound::{CallbackKey, NbDaemonSender};

use crate::Master;
use crate::interface::Interface;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Interface(&'a Interface),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(interfaces::interface::PATH)
        .get_iterate(|master, _args| {
            let iter = master.interfaces.iter().map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(Interface {
                name: Cow::Borrowed(&iface.name),
            })
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "vrrp")]
            holo_vrrp::northbound::state::CALLBACKS.keys(),
        ];

        Some(keys.concat())
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {
    fn child_task(&self, module_name: &str) -> Option<NbDaemonSender> {
        match self {
            ListEntry::Interface(iface) if module_name == "ietf-vrrp" => {
                iface.vrrp.as_ref().map(|vrrp| vrrp.nb_tx.clone())
            }
            _ => None,
        }
    }
}
