//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::derivable_impls)]

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::interfaces;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;

use crate::instance::Instance;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::PATH)
        .create_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .lookup(|_instance, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::version::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::log_state_change::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::preempt::enabled::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::preempt::hold_time::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::priority::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::accept_mode::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::advertise_interval_sec::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::advertise_interval_centi_sec::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::track::interfaces::interface::PATH)
        .create_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .lookup(|_instance, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::track::interfaces::interface::priority_decrement::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::track::networks::network::PATH)
        .create_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .lookup(|_instance, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::track::networks::network::priority_decrement::PATH)
        .modify_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::virtual_ipv4_addresses::virtual_ipv4_address::PATH)
        .create_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_instance, _args| {
            // TODO: implement me!
        })
        .lookup(|_instance, _list_entry, _dnode| {
            // TODO: implement me!
            todo!();
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default().build()
}

// ===== impl Instance =====

#[async_trait]
impl Provider for Instance {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }

    async fn process_event(&mut self, event: Event) {
        // TODO
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        InstanceCfg {}
    }
}
