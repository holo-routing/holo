//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang;

use crate::ibus;
use crate::instance::{Instance, InstanceUpView};
use crate::route::RouteType;
use crate::version::{Ripng, Ripv2, Version};

pub static CALLBACKS_RIPV2: Lazy<Callbacks<Instance<Ripv2>>> =
    Lazy::new(load_callbacks);
pub static CALLBACKS_RIPNG: Lazy<Callbacks<Instance<Ripng>>> =
    Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(yang::clear_rip_route::PATH)
        .rpc(|instance, _args| {
            // Clear routes.
            if let Some((mut instance, _)) = instance.as_up() {
                clear_routes(&mut instance);
            }
            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::rpc_callbacks()
    }
}

// ===== helper functions =====

fn clear_routes<V>(instance: &mut InstanceUpView<'_, V>)
where
    V: Version,
{
    // Remove all received RIP routes.
    instance.state.routes.retain(|_, route| {
        if route.route_type != RouteType::Rip {
            return true;
        }

        // Uninstall and remove route.
        ibus::tx::route_uninstall(&instance.tx.ibus, route);
        false
    });
}
