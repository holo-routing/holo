//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// VRRP-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[(
    "new-master-reason-type",
    TypeSpec {
        rust_type: "MasterReason",
        copy_semantics: true,
    },
)];

// VRRP-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "vrrp-event-type",
        TypeSpec {
            rust_type: "fsm::Event",
            copy_semantics: true,
        },
    ),
    (
        "vrrp-state-type",
        TypeSpec {
            rust_type: "fsm::State",
            copy_semantics: true,
        },
    ),
];

// VRRP-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[(
    "/ietf-interfaces:interfaces/interface/holo-vrrp:vrrp/trace-options/flag/name",
    TypeSpec {
        rust_type: "TraceOption",
        copy_semantics: true,
    },
)];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::VRRP;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(&yang_ctx, modules, None, "yang_config.rs");
}
