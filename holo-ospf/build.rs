//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// OSPF-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "fletcher-checksum16-type",
        TypeSpec {
            rust_type: "FletcherChecksum16",
            copy_semantics: true,
        },
    ),
    (
        "graceful-restart-reason-type",
        TypeSpec {
            rust_type: "GrReason",
            copy_semantics: true,
        },
    ),
    (
        "if-state-type",
        TypeSpec {
            rust_type: "ism::State",
            copy_semantics: true,
        },
    ),
    (
        "nbr-state-type",
        TypeSpec {
            rust_type: "nsm::State",
            copy_semantics: true,
        },
    ),
    (
        "packet-type",
        TypeSpec {
            rust_type: "PacketType",
            copy_semantics: true,
        },
    ),
    (
        "restart-exit-reason-type",
        TypeSpec {
            rust_type: "GrExitReason",
            copy_semantics: true,
        },
    ),
    (
        "route-type",
        TypeSpec {
            rust_type: "OspfRouteType",
            copy_semantics: true,
        },
    ),
];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::OSPF;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(
        &yang_ctx,
        modules,
        Some("ospfv3"),
        "yang_ops_ospfv2.rs",
    );
    yang_codegen::build_yang_ops(
        &yang_ctx,
        modules,
        Some("ospfv2"),
        "yang_ops_ospfv3.rs",
    );
}
