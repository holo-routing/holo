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
    (
        "address-family",
        TypeSpec {
            rust_type: "AddressFamily",
            copy_semantics: true,
        },
    ),
    (
        "extended-sequence-number-mode",
        TypeSpec {
            rust_type: "ExtendedSeqNumMode",
            copy_semantics: true,
        },
    ),
    (
        "interface-type",
        TypeSpec {
            rust_type: "InterfaceType",
            copy_semantics: true,
        },
    ),
    (
        "algo-type",
        TypeSpec {
            rust_type: "holo_utils::sr::IgpAlgo",
            copy_semantics: true,
        },
    ),
    (
        "metric-type",
        TypeSpec {
            rust_type: "IgpMetricType",
            copy_semantics: true,
        },
    ),
];

// IS-IS-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "control-plane-protocol",
        TypeSpec {
            rust_type: "Protocol",
            copy_semantics: true,
        },
    ),
    (
        "crypto-algorithm",
        TypeSpec {
            rust_type: "CryptoAlgo",
            copy_semantics: true,
        },
    ),
    (
        "flooding-algorithm",
        TypeSpec {
            rust_type: "FloodingAlgo",
            copy_semantics: true,
        },
    ),
    (
        "lsp-log-reason",
        TypeSpec {
            rust_type: "LspLogReason",
            copy_semantics: true,
        },
    ),
    (
        "mt-topology",
        TypeSpec {
            rust_type: "MtId",
            copy_semantics: true,
        },
    ),
    (
        "prefix-sid-algorithm",
        TypeSpec {
            rust_type: "holo_utils::sr::PrefixSidAlgo",
            copy_semantics: true,
        },
    ),
];

// IS-IS-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/interfaces/interface/ietf-isis-link-attr:isis-asla/interface-asla/link-attr-app",
        TypeSpec {
            rust_type: "StandardApp",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/address-families/address-family-list/holo-isis:redistribution/level",
        TypeSpec {
            rust_type: "LevelNumber",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/metric-type/value",
        TypeSpec {
            rust_type: "MetricType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/metric-type/level-1/value",
        TypeSpec {
            rust_type: "MetricType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/metric-type/level-2/value",
        TypeSpec {
            rust_type: "MetricType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/holo-isis:trace-options/flag/name",
        TypeSpec {
            rust_type: "InstanceTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/interfaces/interface/holo-isis:trace-options/flag/name",
        TypeSpec {
            rust_type: "InterfaceTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/spf-control/ietf-spf-delay/holo-isis:level/current-state",
        TypeSpec {
            rust_type: "spf::fsm::State",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-isis:isis/spf-log/event/spf-type",
        TypeSpec {
            rust_type: "SpfType",
            copy_semantics: true,
        },
    ),
];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::ISIS;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
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
