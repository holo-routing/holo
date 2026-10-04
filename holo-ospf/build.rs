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
    (
        "address-family",
        TypeSpec {
            rust_type: "AddressFamily",
            copy_semantics: true,
        },
    ),
];

// OSPF-specific YANG identity types.
static IDENTITY_TYPES: &[(&str, TypeSpec)] = &[
    (
        "area-type",
        TypeSpec {
            rust_type: "AreaType",
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
        "lsa-log-reason",
        TypeSpec {
            rust_type: "LsaLogReason",
            copy_semantics: true,
        },
    ),
    (
        "ospfv3-lsa-type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaType",
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
];

// OSPF-specific YANG leaf types.
static LEAF_TYPES: &[(&str, TypeSpec)] = &[
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/interface-type",
        TypeSpec {
            rust_type: "InterfaceType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/holo-ospf:trace-options/flag/name",
        TypeSpec {
            rust_type: "InstanceTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/holo-ospf:trace-options/flag/name",
        TypeSpec {
            rust_type: "InterfaceTraceOption",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/spf-control/ietf-spf-delay/current-state",
        TypeSpec {
            rust_type: "spf::fsm::State",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/spf-log/event/spf-type",
        TypeSpec {
            rust_type: "SpfLogType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/header/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/external/topologies/topology/flags",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa::LsaAsExternalFlags",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa_opaque::ExtPrefixRouteType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv3/header/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/database/as-scope-lsa-type/as-scope-lsas/as-scope-lsa/ospfv3/body/as-external/flags",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaAsExternalFlags",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/header/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/router/links/link/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::iana::LsaRouterLinkType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-prefix-opaque/extended-prefix-tlv/route-type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa_opaque::ExtPrefixRouteType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv2/body/opaque/extended-link-opaque/extended-link-tlv/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::iana::LsaRouterLinkType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv3/header/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv3/body/router/links/link/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::iana::LsaRouterLinkType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/database/area-scope-lsa-type/area-scope-lsas/area-scope-lsa/ospfv3/body/ietf-ospfv3-extended-lsa:e-router/e-router-tlvs/link-tlv/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::iana::LsaRouterLinkType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/virtual-links/virtual-link/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/virtual-links/virtual-link/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv3/header/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv2/header/type",
        TypeSpec {
            rust_type: "crate::ospfv2::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
    (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/database/link-scope-lsa-type/link-scope-lsas/link-scope-lsa/ospfv3/header/type",
        TypeSpec {
            rust_type: "crate::ospfv3::packet::lsa::LsaType",
            copy_semantics: true,
        },
    ),
];

fn main() {
    holo_platform::network_backend();

    let mut yang_ctx = yang::new_context();
    let modules = yang::implemented_modules::OSPF;
    yang::load_modules(&mut yang_ctx, modules);
    yang_codegen::types::register_typedefs(TYPEDEFS);
    yang_codegen::types::register_identity_types(&yang_ctx, IDENTITY_TYPES);
    yang_codegen::types::register_leaf_types(&yang_ctx, LEAF_TYPES);
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
    yang_codegen::build_yang_config(
        &yang_ctx,
        modules,
        Some("control-plane-protocol"),
        "yang_config.rs",
    );
}
