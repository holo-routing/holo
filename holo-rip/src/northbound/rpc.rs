//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};
use yang4::data::DataTree;

use crate::ibus;
use crate::instance::Instance;
use crate::northbound::yang_gen as yang;
use crate::route::RouteType;
use crate::version::Version;

impl<V> Provider for Instance<V>
where
    V: Version,
{
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_RPC;
}

// ===== YANG impls =====

impl<V: Version> YangRpc<Instance<V>> for yang::clear_rip_route::ClearRipRoute {
    fn invoke(instance: &mut Instance<V>, _data: &mut DataTree<'static>, _rpc_path: &str) -> Result<(), String> {
        let Some((instance, _)) = instance.as_up() else {
            return Ok(());
        };

        // Remove all received RIP routes.
        instance.state.routes.retain(|_, route| {
            if route.route_type != RouteType::Rip {
                return true;
            }

            // Uninstall and remove route.
            ibus::tx::route_uninstall(&instance.tx.ibus, route);
            false
        });

        Ok(())
    }
}
