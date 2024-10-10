//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang;

use crate::instance::Instance;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(yang::clear_adjacency::PATH)
        .rpc(|_instance, _args| {
            Box::pin(async move {
                // TODO: implement me!
                Ok(())
            })
        })
        .path(yang::isis_clear_database::PATH)
        .rpc(|_instance, _args| {
            Box::pin(async move {
                // TODO: implement me!
                Ok(())
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}
