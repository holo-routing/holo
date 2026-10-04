//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::yang_codegen;
use holo_northbound::yang_codegen::types::TypeSpec;
use holo_yang as yang;

// BGP-specific YANG types.
static TYPEDEFS: &[(&str, TypeSpec)] = &[
    (
        "bgp-origin-attr-type",
        TypeSpec {
            rust_type: "Origin",
            copy_semantics: true,
        },
    ),
    (
        "peer-type",
        TypeSpec {
            rust_type: "PeerType",
            copy_semantics: true,
        },
    ),
    (
        "address-family",
        TypeSpec {
            rust_type: "Afi",
            copy_semantics: true,
        },
    ),
    (
        "bgp-ext-community-type",
        TypeSpec {
            rust_type: "ExtComm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-ipv6-ext-community-type",
        TypeSpec {
            rust_type: "Extv6Comm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-large-community-type",
        TypeSpec {
            rust_type: "LargeComm",
            copy_semantics: true,
        },
    ),
    (
        "bgp-safi",
        TypeSpec {
            rust_type: "Safi",
            copy_semantics: true,
        },
    ),
    (
        "default-policy-type",
        TypeSpec {
            rust_type: "DefaultPolicyType",
            copy_semantics: true,
        },
    ),
    (
        "remove-private-as-option",
        TypeSpec {
            rust_type: "PrivateAsRemove",
            copy_semantics: true,
        },
    ),
];

// BGP-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "afi-safi-type",
        TypeSpec {
            rust_type: "holo_utils::bgp::AfiSafi",
            copy_semantics: true,
        },
    ),
    (
        "as-path-segment-type",
        TypeSpec {
            rust_type: "AsPathSegmentType",
            copy_semantics: true,
        },
    ),
    (
        "bgp-capability",
        TypeSpec {
            rust_type: "CapabilityCode",
            copy_semantics: true,
        },
    ),
    (
        "bgp-notification",
        TypeSpec {
            rust_type: "NotificationMsg",
            copy_semantics: false,
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
        "ineligible-route-reason",
        TypeSpec {
            rust_type: "RouteIneligibleReason",
            copy_semantics: true,
        },
    ),
];

// BGP-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/prefix-limit/idle-time",
        TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/prefix-limit/idle-time",
        TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/global/holo-bgp:trace-options/flag/name",
        TypeSpec {
            rust_type: "InstanceTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/prefix-limit/idle-time",
        TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/transport/local-address",
        TypeSpec {
            rust_type: "IpAddr",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/idle-time",
        TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/idle-time",
        TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/holo-bgp:trace-options/flag/name",
        TypeSpec {
            rust_type: "NeighborTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/session-state",
        TypeSpec {
            rust_type: "fsm::State",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/capabilities/advertised-capabilities/value/add-paths/afi-safis/mode",
        TypeSpec {
            rust_type: "AddPathMode",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/neighbors/neighbor/capabilities/received-capabilities/value/add-paths/afi-safis/mode",
        TypeSpec {
            rust_type: "AddPathMode",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/rib/communities/community/community",
        TypeSpec {
            rust_type: "Comm",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/rib/afi-safis/afi-safi/ipv4-unicast/loc-rib/routes/route/origin",
        TypeSpec {
            rust_type: "RouteOrigin",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/rib/afi-safis/afi-safi/ipv6-unicast/loc-rib/routes/route/origin",
        TypeSpec {
            rust_type: "RouteOrigin",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/rib/afi-safis/afi-safi/ipv4-unicast/neighbors/neighbor/adj-rib-in-post/routes/route/reject-reason",
        TypeSpec {
            rust_type: "RouteRejectReason",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-bgp:bgp/rib/afi-safis/afi-safi/ipv6-unicast/neighbors/neighbor/adj-rib-in-post/routes/route/reject-reason",
        TypeSpec {
            rust_type: "RouteRejectReason",
            copy_semantics: true,
        },
    ),
];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::BGP;
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
