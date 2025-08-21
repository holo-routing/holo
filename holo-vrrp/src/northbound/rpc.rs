//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};

use crate::interface::Interface;

pub static CALLBACKS: Lazy<Callbacks<Interface>> = Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Interface> {
    CallbacksBuilder::<Interface>::default().build()
}

// ===== impl Interface =====

impl Provider for Interface {
    fn callbacks() -> &'static Callbacks<Interface> {
        &CALLBACKS
    }
}
