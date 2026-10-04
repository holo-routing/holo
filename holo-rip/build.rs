//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// RIP-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[(
    "crypto-algorithm",
    TypeSpec {
        rust_type: "CryptoAlgo",
        copy_semantics: true,
    },
)];

// RIP-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/interfaces/interface/split-horizon",
        TypeSpec {
            rust_type: "SplitHorizon",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/holo-rip:trace-options/flag/name",
        TypeSpec {
            rust_type: "TraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv4/routes/route/route-type",
        TypeSpec {
            rust_type: "RouteType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-rip:rip/ipv6/routes/route/route-type",
        TypeSpec {
            rust_type: "RouteType",
            copy_semantics: true,
        },
    ),
];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::RIP;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
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
    yang_codegen::build_yang_config(
        &yang_ctx,
        modules,
        Some("control-plane-protocol"),
        "yang_config.rs",
    );
}
