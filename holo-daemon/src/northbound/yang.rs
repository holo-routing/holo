//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_northbound::ProviderBase;
use holo_utils::yang::ContextExt;
use holo_yang as yang;
use holo_yang::YANG_CTX;

fn modules_add<P: ProviderBase>(modules: &mut Vec<&'static str>) {
    modules.extend(P::yang_modules().iter());
}

pub(crate) fn create_context() {
    let mut modules = Vec::new();

    // Add data type modules.
    for module_name in ["iana-if-type", "ietf-routing-types", "ietf-bfd-types"]
    {
        modules.push(module_name);
    }

    // Add core modules.
    #[cfg(feature = "interface")]
    modules_add::<holo_interface::Master>(&mut modules);

    #[cfg(feature = "routing")]
    modules_add::<holo_routing::Master>(&mut modules);

    #[cfg(feature = "keychain")]
    modules_add::<holo_keychain::Master>(&mut modules);

    #[cfg(feature = "policy")]
    modules_add::<holo_policy::Master>(&mut modules);

    #[cfg(feature = "system")]
    modules_add::<holo_system::Master>(&mut modules);

    // Add protocol modules based on enabled features.
    #[cfg(feature = "bfd")]
    {
        use holo_bfd::master::Master;
        modules_add::<Master>(&mut modules);
    }
    #[cfg(feature = "bgp")]
    {
        use holo_bgp::instance::Instance;
        modules_add::<Instance>(&mut modules);
    }
    #[cfg(feature = "isis")]
    {
        use holo_isis::instance::Instance;
        modules_add::<Instance>(&mut modules);
    }
    #[cfg(feature = "ldp")]
    {
        use holo_ldp::instance::Instance;
        modules_add::<Instance>(&mut modules);
    }
    #[cfg(feature = "ospf")]
    {
        use holo_ospf::instance::Instance;
        use holo_ospf::version::{Ospfv2, Ospfv3};
        modules_add::<Instance<Ospfv2>>(&mut modules);
        modules_add::<Instance<Ospfv3>>(&mut modules);
    }
    #[cfg(feature = "rip")]
    {
        use holo_rip::instance::Instance;
        use holo_rip::version::{Ripng, Ripv2};
        modules_add::<Instance<Ripv2>>(&mut modules);
        modules_add::<Instance<Ripng>>(&mut modules);
    }
    #[cfg(feature = "vrrp")]
    {
        use holo_vrrp::interface::Interface;
        modules_add::<Interface>(&mut modules);
    }

    // Create YANG context and load all required modules and their deviations.
    let mut yang_ctx = yang::new_context();
    for module_name in modules.iter() {
        yang::load_module(&mut yang_ctx, module_name);
    }
    for module_name in modules.iter().rev() {
        yang::load_deviations(&mut yang_ctx, module_name);
    }
    yang_ctx.cache_data_paths();
    YANG_CTX.set(Arc::new(yang_ctx)).unwrap();
}
