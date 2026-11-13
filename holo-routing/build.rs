//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// Routing-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "address-family",
        TypeSpec {
            rust_type: "AddressFamily",
            copy_semantics: true,
        },
    ),
    (
        "bsl",
        TypeSpec {
            rust_type: "Bsl",
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
    (
        "route-type",
        TypeSpec {
            rust_type: "OspfRouteType",
            copy_semantics: true,
        },
    ),
    (
        "underlay-protocol-type",
        TypeSpec {
            rust_type: "UnderlayProtocolType",
            copy_semantics: true,
        },
    ),
];

// Routing-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "bier-encapsulation",
        TypeSpec {
            rust_type: "BierEncapsulationType",
            copy_semantics: true,
        },
    ),
    (
        "control-plane-protocol",
        TypeSpec {
            rust_type: "Protocol",
            copy_semantics: true,
        },
    ),
    (
        "prefix-sid-algorithm",
        TypeSpec {
            rust_type: "PrefixSidAlgo",
            copy_semantics: true,
        },
    ),
    (
        "routing-protocol",
        TypeSpec {
            rust_type: "Protocol",
            copy_semantics: true,
        },
    ),
];

// Routing-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/static-routes/ietf-ipv4-unicast-routing:ipv4/route/next-hop/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/static-routes/ietf-ipv6-unicast-routing:ipv6/route/next-hop/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/holo-routing:next-hop-tracking/next-hop/resolution/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/ietf-segment-routing:segment-routing/ietf-segment-routing-mpls:sr-mpls/bindings/connected-prefix-sid-map/connected-prefix-sid/last-hop-behavior",
        TypeSpec {
            rust_type: "SidLastHopBehavior",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/ribs/rib/routes/route/ietf-isis:route-type",
        TypeSpec {
            rust_type: "IsisRouteType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/ribs/rib/routes/route/next-hop/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/ribs/rib/routes/route/next-hop/holo-routing:resolved-next-hop/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/ribs/rib/routes/route/next-hop/next-hop-list/next-hop/holo-routing:resolved-next-hop/special-next-hop",
        TypeSpec {
            rust_type: "NexthopSpecial",
            copy_semantics: true,
        },
    ),
];

fn main() {
    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::ROUTING;
    yang::load_modules(&mut yang_ctx, modules);
    // NOTE: IS-IS and OSPF are implemented in holo-isis and holo-ospf, but
    // their base YANG models must be loaded here because they augment the
    // global RIB.
    yang::load_modules(&mut yang_ctx, &["ietf-isis", "ietf-ospf"]);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
    yang_codegen::build_yang_objects(&yang_ctx, modules, "yang_objects.rs");
    yang_codegen::build_yang_ops(&yang_ctx, modules, None, "yang_ops.rs");
    yang_codegen::build_yang_config(&yang_ctx, modules, None, "yang_config.rs");
}
