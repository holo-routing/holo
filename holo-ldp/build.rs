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
    (
        "mpls-label",
        TypeSpec {
            rust_type: "Label",
            copy_semantics: true,
        },
    ),
];

// LDP-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-mpls-ldp:mpls-ldp/global/address-families/ipv4/label-distribution-control-mode",
        TypeSpec {
            rust_type: "LabelDistMode",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-mpls-ldp:mpls-ldp/peers/peer/session-state",
        TypeSpec {
            rust_type: "neighbor::fsm::State",
            copy_semantics: true,
        },
    ),
];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::LDP;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(
        &yang_ctx,
        modules,
        Some("control-plane-protocol"),
        "yang_config.rs",
    );
}
