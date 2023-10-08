//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::paths::interfaces;

use crate::Master;

static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(interfaces::interface::PATH)
        .create_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .lookup(|_instance, _list_entry, _dnode| ListEntry::None)
        .path(interfaces::interface::description::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::r#type::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::enabled::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::PATH)
        .create_apply(|_context, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::enabled::PATH)
        .modify_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv6::PATH)
        .create_apply(|_context, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv6::enabled::PATH)
        .modify_apply(|_context, _args| {
            // TODO: implement me!
        })
        .build()
}

// ===== impl Master =====

#[async_trait]
impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }
}
