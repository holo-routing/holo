//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang;

use crate::instance::{Instance, InstanceUp};
use crate::route::RouteType;
use crate::southbound;
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
            Box::pin(async move {
                // Clear routes.
                if let Instance::Up(instance) = instance {
                    clear_routes(instance);
                }
                Ok(())
            })
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    fn callbacks() -> Option<&'static Callbacks<Instance<V>>> {
        V::rpc_callbacks()
    }
}

// ===== helper functions =====

fn clear_routes<V>(instance: &mut InstanceUp<V>)
where
    V: Version,
{
    // Remove all received RIP routes.
    instance.state.routes.retain(|_, route| {
        if route.route_type != RouteType::Rip {
            return true;
        }

        // Uninstall and remove route.
        southbound::tx::route_uninstall(&instance.tx.ibus, route);
        false
    });
}
