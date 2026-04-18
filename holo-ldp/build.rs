//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// LDP-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "advertised-received",
        TypeSpec {
            rust_type: "AdvertisementType",
            copy_semantics: true,
        },
    ),
    (
        "label-adv-mode",
        TypeSpec {
            rust_type: "LabelAdvMode",
            copy_semantics: true,
        },
    ),
];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::LDP;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
}
