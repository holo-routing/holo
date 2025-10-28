use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};

use crate::{
    instance::Instance,
    version::{Mldv1, Mldv2, Version},
};

pub static CALLBACKS_MLDV1: Lazy<Callbacks<Instance<Mldv1>>> =
    Lazy::new(load_callbacks);

pub static CALLBACKS_MLDV2: Lazy<Callbacks<Instance<Mldv2>>> =
    Lazy::new(load_callbacks);

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::default().build()
}

impl<V> Provider for Instance<V>
where
    V: Version,
{
    fn callbacks() -> &'static holo_northbound::rpc::Callbacks<Self> {
        V::rpc_callbacks()
    }
}
