//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_yang as yang;

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::RIP;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(
        &yang_ctx,
        modules,
        Some("ipv6"),
        "yang_ops_ripv2.rs",
    );
    yang_codegen::build_yang_ops(
        &yang_ctx,
        modules,
        Some("ipv4"),
        "yang_ops_ripng.rs",
    );
}
