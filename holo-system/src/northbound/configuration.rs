//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::yang::system;
use holo_utils::yang::DataNodeRefExt;

use crate::{Master, ibus};

static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default)]
pub enum ListEntry {
    #[default]
    None,
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    HostnameChange,
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct SystemCfg {
    pub contact: Option<String>,
    pub hostname: Option<String>,
    pub location: Option<String>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(system::contact::PATH)
        .modify_apply(|master, args| {
            let contact = args.dnode.get_string();
            master.config.contact = Some(contact);
        })
        .delete_apply(|master, _args| {
            master.config.contact = None;
        })
        .path(system::hostname::PATH)
        .modify_apply(|master, args| {
            let hostname = args.dnode.get_string();
            master.config.hostname = Some(hostname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::HostnameChange);
        })
        .delete_apply(|master, args| {
            master.config.hostname = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::HostnameChange);
        })
        .path(system::location::PATH)
        .modify_apply(|master, args| {
            let location = args.dnode.get_string();
            master.config.location = Some(location);
        })
        .delete_apply(|master, _args| {
            master.config.location = None;
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
            Event::HostnameChange => {
                for ibus_tx in self.hostname_subscriptions.values() {
                    ibus::notify_hostname_update(
                        ibus_tx,
                        self.config.hostname.clone(),
                    );
                }
            }
        }
    }
}
