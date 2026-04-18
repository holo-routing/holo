//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// IS-IS-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "adj-state-type",
        TypeSpec {
            rust_type: "AdjacencyState",
            copy_semantics: true,
        },
    ),
    (
        "area-address",
        TypeSpec {
            rust_type: "AreaAddr",
            copy_semantics: false,
        },
    ),
    (
        "extended-system-id",
        TypeSpec {
            rust_type: "LanId",
            copy_semantics: true,
        },
    ),
    (
        "level",
        TypeSpec {
            rust_type: "LevelType",
            copy_semantics: true,
        },
    ),
    (
        "lsp-id",
        TypeSpec {
            rust_type: "LspId",
            copy_semantics: true,
        },
    ),
    (
        "system-id",
        TypeSpec {
            rust_type: "SystemId",
            copy_semantics: true,
        },
    ),
];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::ISIS;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
}
