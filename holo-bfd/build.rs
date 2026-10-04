//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// BFD-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "diagnostic",
        TypeSpec {
            rust_type: "DiagnosticCode",
            copy_semantics: true,
        },
    ),
    (
        "state",
        TypeSpec {
            rust_type: "State",
            copy_semantics: true,
        },
    ),
];

// BFD-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[(
    "path-type",
    TypeSpec {
        rust_type: "PathType",
        copy_semantics: true,
    },
)];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::BFD;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(
        &yang_ctx,
        modules,
        Some("control-plane-protocol"),
        "yang_config.rs",
    );
}
