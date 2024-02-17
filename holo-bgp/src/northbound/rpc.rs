//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};

//use holo_utils::yang::DataNodeRefExt;
//use yang2::data::Data;
use crate::instance::Instance;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    // TODO: YANG actions are not supported yet.
    CallbacksBuilder::<Instance>::default().build()
}

// ===== impl Instance =====

impl Provider for Instance {
    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}
