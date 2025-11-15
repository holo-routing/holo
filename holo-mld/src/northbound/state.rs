use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};

use crate::{
    instance::Instance,
    version::{Mldv1, Mldv2, Version},
};

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a, V: Version> {
    #[default]
    None,
    Tmp(&'a Instance<V>),
}

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
    CallbacksBuilder::new(core_cb).build()
}

fn load_callbacks_mldv2() -> Callbacks<Instance<Mldv2>> {
    let core_cb = load_callbacks();
    CallbacksBuilder::new(core_cb).build()
}

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = ListEntry<'a, V>;

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::state_callbacks()
    }
}

impl<V> ListEntryKind for ListEntry<'_, V> where V: Version {}
