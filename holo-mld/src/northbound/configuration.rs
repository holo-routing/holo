//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::marker::PhantomData;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};

use crate::{
    instance::Instance,
    version::{Mldv1, Mldv2, Version},
};

#[derive(Debug, EnumAsInner, Default)]
pub enum ListEntry<V: Version> {
    #[default]
    None,
    _Phantom(PhantomData<V>),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {}

pub static VALIDATION_CALLBACKS_MLDV1: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_mldv1);
pub static VALIDATION_CALLBACKS_MLDV2: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_mldv2);
pub static CALLBACKS_MLDV1: Lazy<Callbacks<Instance<Mldv1>>> =
    Lazy::new(load_callbacks_mldv1);
pub static CALLBACKS_MLDV2: Lazy<Callbacks<Instance<Mldv2>>> =
    Lazy::new(load_callbacks_mldv2);

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default().build()
}

fn load_callbacks_mldv1() -> Callbacks<Instance<Mldv1>> {
    let core_cb = load_callbacks();
    CallbacksBuilder::<Instance<Mldv1>>::new(core_cb).build()
}

fn load_callbacks_mldv2() -> Callbacks<Instance<Mldv2>> {
    let core_cb = load_callbacks();
    CallbacksBuilder::<Instance<Mldv2>>::new(core_cb).build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default().build()
}

fn load_validation_callbacks_mldv1() -> ValidationCallbacks {
    let core_cb = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cb).build()
}

fn load_validation_callbacks_mldv2() -> ValidationCallbacks {
    let core_cb = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cb).build()
}

#[derive(Debug)]
pub struct InstanceCfg {}

impl Default for InstanceCfg {
    fn default() -> Self {
        InstanceCfg {}
    }
}

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry = ListEntry<V>;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        V::validation_callbacks()
    }

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::configuration_callbacks()
    }

    fn process_event(&mut self, event: Event) {
        match event {}
    }
}
