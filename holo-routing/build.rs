//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_yang as yang;

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::ROUTING;
    yang::load_modules(&mut yang_ctx, modules);
    // NOTE: IS-IS and OSPF are implemented in holo-isis and holo-ospf, but
    // their base YANG models must be loaded here because they augment the
    // global RIB.
    yang::load_modules(&mut yang_ctx, &["ietf-isis", "ietf-ospf"]);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
}
