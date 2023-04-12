//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::paths::key_chains;

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
        .path(key_chains::key_chain::PATH)
        .create_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .lookup(|_master, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .path(key_chains::key_chain::description::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::PATH)
        .create_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .lookup(|_master, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::always::PATH)
        .create_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::start_date_time::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::no_end_time::PATH)
        .create_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::duration::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::lifetime::send_accept_lifetime::end_date_time::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::crypto_algorithm::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(key_chains::key_chain::key::key_string::keystring::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
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
