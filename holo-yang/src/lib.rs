//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod serde;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock as Lazy, OnceLock};

use maplit::hashmap;
use yang3::context::{
    Context, ContextFlags, EmbeddedModuleKey, EmbeddedModules,
};
use yang3::data::DataNodeRef;

// Global YANG context.
pub static YANG_CTX: OnceLock<Arc<Context>> = OnceLock::new();

// List of embedded YANG modules.
//
// All implemented or imported modules need to be specified here. Holo by
// default doesn't support loading YANG modules from the filesystem.
pub static YANG_EMBEDDED_MODULES: Lazy<EmbeddedModules> = Lazy::new(|| {
    hashmap! {
        // IEEE modules
        EmbeddedModuleKey::new("ieee802-dot1q-types", Some("2022-01-19"), None, None) =>
            include_str!("../modules/ieee/ieee802-dot1q-types@2022-01-19.yang"),
        // IETF modules
        EmbeddedModuleKey::new("iana-bfd-types", Some("2021-10-21"), None, None) =>
            include_str!("../modules/ietf/iana-bfd-types@2021-10-21.yang"),
        EmbeddedModuleKey::new("iana-bgp-community-types", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/iana-bgp-community-types@2023-07-05.yang"),
        EmbeddedModuleKey::new("iana-bgp-notification", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/iana-bgp-notification@2023-07-05.yang"),
        EmbeddedModuleKey::new("iana-bgp-rib-types", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/iana-bgp-rib-types@2023-07-05.yang"),
        EmbeddedModuleKey::new("iana-bgp-types", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/iana-bgp-types@2023-07-05.yang"),
        EmbeddedModuleKey::new("iana-crypt-hash", Some("2014-08-06"), None, None) =>
            include_str!("../modules/ietf/iana-crypt-hash@2014-08-06.yang"),
        EmbeddedModuleKey::new("iana-if-type", Some("2017-01-19"), None, None) =>
            include_str!("../modules/ietf/iana-if-type@2017-01-19.yang"),
        EmbeddedModuleKey::new("iana-msd-types", Some("2025-01-10"), None, None) =>
            include_str!("../modules/ietf/iana-msd-types@2025-01-10.yang"),
        EmbeddedModuleKey::new("iana-routing-types", Some("2018-10-29"), None, None) =>
            include_str!("../modules/ietf/iana-routing-types@2018-10-29.yang"),
        EmbeddedModuleKey::new("ietf-bfd-ip-mh", Some("2022-09-22"), None, None) =>
            include_str!("../modules/ietf/ietf-bfd-ip-mh@2022-09-22.yang"),
        EmbeddedModuleKey::new("ietf-bfd-ip-sh", Some("2022-09-22"), None, None) =>
            include_str!("../modules/ietf/ietf-bfd-ip-sh@2022-09-22.yang"),
        EmbeddedModuleKey::new("ietf-bfd-types", Some("2022-09-22"), None, None) =>
            include_str!("../modules/ietf/ietf-bfd-types@2022-09-22.yang"),
        EmbeddedModuleKey::new("ietf-bfd", Some("2022-09-22"), None, None) =>
            include_str!("../modules/ietf/ietf-bfd@2022-09-22.yang"),
        EmbeddedModuleKey::new("ietf-bier", Some("2023-09-16"), None, None) =>
            include_str!("../modules/ietf/ietf-bier@2023-09-16.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/ietf-bgp@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-capabilities"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-capabilities@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-common"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-common@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-common-multiprotocol"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-common-multiprotocol@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-common-structure"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-common-structure@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-neighbor"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-neighbor@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-rib"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-rib@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-rib-attributes"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-rib-attributes@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp", Some("2023-07-05"), Some("ietf-bgp-rib-tables"), Some("2023-07-05")) =>
            include_str!("../modules/ietf/ietf-bgp-rib-tables@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-bgp-policy", Some("2023-07-05"), None, None) =>
            include_str!("../modules/ietf/ietf-bgp-policy@2023-07-05.yang"),
        EmbeddedModuleKey::new("ietf-if-extensions", Some("2023-01-26"), None, None) =>
            include_str!("../modules/ietf/ietf-if-extensions@2023-01-26.yang"),
        EmbeddedModuleKey::new("ietf-if-vlan-encapsulation", Some("2023-01-26"), None, None) =>
            include_str!("../modules/ietf/ietf-if-vlan-encapsulation@2023-01-26.yang"),
        EmbeddedModuleKey::new("ietf-interfaces", Some("2018-02-20"), None, None) =>
            include_str!("../modules/ietf/ietf-interfaces@2018-02-20.yang"),
        EmbeddedModuleKey::new("ietf-ip", Some("2018-02-22"), None, None) =>
            include_str!("../modules/ietf/ietf-ip@2018-02-22.yang"),
        EmbeddedModuleKey::new("ietf-ipv4-unicast-routing", Some("2018-03-13"), None, None) =>
            include_str!("../modules/ietf/ietf-ipv4-unicast-routing@2018-03-13.yang"),
        EmbeddedModuleKey::new("ietf-ipv6-unicast-routing", Some("2018-03-13"), None, None) =>
            include_str!("../modules/ietf/ietf-ipv6-unicast-routing@2018-03-13.yang"),
        EmbeddedModuleKey::new("ietf-ipv6-unicast-routing", Some("2018-03-13"), Some("ietf-ipv6-router-advertisements"), Some("2018-03-13")) =>
            include_str!("../modules/ietf/ietf-ipv6-router-advertisements@2018-03-13.yang"),
        EmbeddedModuleKey::new("ietf-isis", Some("2022-10-19"), None, None) =>
            include_str!("../modules/ietf/ietf-isis@2022-10-19.yang"),
        EmbeddedModuleKey::new("ietf-isis-msd", Some("2024-09-02"), None, None) =>
            include_str!("../modules/ietf/ietf-isis-msd@2024-09-02.yang"),
        EmbeddedModuleKey::new("ietf-isis-sr-mpls", Some("2025-05-05"), None, None) =>
            include_str!("../modules/ietf/ietf-isis-sr-mpls@2025-05-05.yang"),
        EmbeddedModuleKey::new("ietf-key-chain", Some("2017-06-15"), None, None) =>
            include_str!("../modules/ietf/ietf-key-chain@2017-06-15.yang"),
        EmbeddedModuleKey::new("ietf-mpls", Some("2020-12-18"), None, None) =>
            include_str!("../modules/ietf/ietf-mpls@2020-12-18.yang"),
        EmbeddedModuleKey::new("ietf-mpls-msd", Some("2025-01-10"), None, None) =>
            include_str!("../modules/ietf/ietf-mpls-msd@2025-01-10.yang"),
        EmbeddedModuleKey::new("ietf-mpls-ldp", Some("2022-03-14"), None, None) =>
            include_str!("../modules/ietf/ietf-mpls-ldp@2022-03-14.yang"),
        EmbeddedModuleKey::new("ietf-netconf-acm", Some("2018-02-14"), None, None) =>
            include_str!("../modules/ietf/ietf-netconf-acm@2018-02-14.yang"),
        EmbeddedModuleKey::new("ietf-ospf", Some("2022-10-19"), None, None) =>
            include_str!("../modules/ietf/ietf-ospf@2022-10-19.yang"),
        EmbeddedModuleKey::new("ietf-ospf-sr-mpls", Some("2025-05-05"), None, None) =>
            include_str!("../modules/ietf/ietf-ospf-sr-mpls@2025-05-05.yang"),
        EmbeddedModuleKey::new("ietf-ospfv3-extended-lsa", Some("2024-06-07"), None, None) =>
            include_str!("../modules/ietf/ietf-ospfv3-extended-lsa@2024-06-07.yang"),
        EmbeddedModuleKey::new("ietf-rip", Some("2020-02-20"), None, None) =>
            include_str!("../modules/ietf/ietf-rip@2020-02-20.yang"),
        EmbeddedModuleKey::new("ietf-system", Some("2014-08-06"), None, None) =>
            include_str!("../modules/ietf/ietf-system@2014-08-06.yang"),
        EmbeddedModuleKey::new("ietf-routing", Some("2018-03-13"), None, None) =>
            include_str!("../modules/ietf/ietf-routing@2018-03-13.yang"),
        EmbeddedModuleKey::new("ietf-routing-policy", Some("2021-10-11"), None, None) =>
            include_str!("../modules/ietf/ietf-routing-policy@2021-10-11.yang"),
        EmbeddedModuleKey::new("ietf-routing-types", Some("2017-12-04"), None, None) =>
            include_str!("../modules/ietf/ietf-routing-types@2017-12-04.yang"),
        EmbeddedModuleKey::new("ietf-segment-routing-common", Some("2021-05-26"), None, None) =>
            include_str!("../modules/ietf/ietf-segment-routing-common@2021-05-26.yang"),
        EmbeddedModuleKey::new("ietf-segment-routing-mpls", Some("2021-05-26"), None, None) =>
            include_str!("../modules/ietf/ietf-segment-routing-mpls@2021-05-26.yang"),
        EmbeddedModuleKey::new("ietf-segment-routing", Some("2021-05-26"), None, None) =>
            include_str!("../modules/ietf/ietf-segment-routing@2021-05-26.yang"),
        EmbeddedModuleKey::new("ietf-tcp", Some("2022-09-11"), None, None) =>
            include_str!("../modules/ietf/ietf-tcp@2022-09-11.yang"),
        EmbeddedModuleKey::new("ietf-tcp-common", Some("2023-04-17"), None, None) =>
            include_str!("../modules/ietf/ietf-tcp-common@2023-04-17.yang"),
        EmbeddedModuleKey::new("ietf-vrrp", Some("2018-03-13"), None, None) =>
            include_str!("../modules/ietf/ietf-vrrp@2018-03-13.yang"),
        // IETF Holo augmentations
        EmbeddedModuleKey::new("holo-bgp", None, None, None) =>
            include_str!("../modules/augmentations/holo-bgp.yang"),
        EmbeddedModuleKey::new("holo-isis", None, None, None) =>
            include_str!("../modules/augmentations/holo-isis.yang"),
        EmbeddedModuleKey::new("holo-isis-dev", None, None, None) =>
            include_str!("../modules/augmentations/holo-isis-dev.yang"),
        EmbeddedModuleKey::new("holo-key-chain", None, None, None) =>
            include_str!("../modules/augmentations/holo-key-chain.yang"),
        EmbeddedModuleKey::new("holo-ospf", None, None, None) =>
            include_str!("../modules/augmentations/holo-ospf.yang"),
        EmbeddedModuleKey::new("holo-ospf-dev", None, None, None) =>
            include_str!("../modules/augmentations/holo-ospf-dev.yang"),
        EmbeddedModuleKey::new("holo-rip", None, None, None) =>
            include_str!("../modules/augmentations/holo-rip.yang"),
        EmbeddedModuleKey::new("holo-routing", None, None, None) =>
            include_str!("../modules/augmentations/holo-routing.yang"),
        EmbeddedModuleKey::new("holo-vrrp", None, None, None) =>
            include_str!("../modules/augmentations/holo-vrrp.yang"),
        // IETF Holo deviations
        EmbeddedModuleKey::new("holo-ietf-bgp-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-bgp-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-bier-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-bier-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-mpls-ldp-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-mpls-ldp-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-if-extensions-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-if-extensions-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-if-vlan-encapsulation-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-if-vlan-encapsulation-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-interfaces-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-interfaces-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-ip-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-ip-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-isis-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-isis-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-isis-msd-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-isis-msd-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-isis-sr-mpls-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-isis-sr-mpls-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-mpls-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-mpls-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-ospf-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-ospf-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-ospf-sr-mpls-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-ospf-sr-mpls-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-ospfv3-extended-lsa-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-ospfv3-extended-lsa-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-rip-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-rip-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-system-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-system-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-routing-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-routing-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-ipv6-unicast-routing-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-ipv6-unicast-routing-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-routing-policy-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-routing-policy-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-segment-routing-mpls-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-segment-routing-mpls-deviations.yang"),
        EmbeddedModuleKey::new("holo-ietf-vrrp-deviations", None, None, None) =>
            include_str!("../modules/deviations/holo-ietf-vrrp-deviations.yang"),
    }
});

// All modules currently implemented.
//
// The list includes modules that define YANG identities that can be
// instantiated.
pub static YANG_IMPLEMENTED_MODULES: Lazy<Vec<&'static str>> =
    Lazy::new(|| {
        vec![
            // IEEE modules
            "ieee802-dot1q-types",
            // IETF modules
            "iana-if-type",
            "iana-bgp-notification",
            "iana-bgp-rib-types",
            "iana-bgp-types",
            "iana-msd-types",
            "ietf-bfd-ip-mh",
            "ietf-bfd-ip-sh",
            "ietf-bfd-types",
            "ietf-bfd",
            "ietf-bgp",
            "ietf-bgp-policy",
            "ietf-bier",
            "ietf-routing-types",
            "ietf-if-extensions",
            "ietf-if-vlan-encapsulation",
            "ietf-interfaces",
            "ietf-ip",
            "ietf-isis",
            "ietf-isis-msd",
            "ietf-isis-sr-mpls",
            "ietf-key-chain",
            "ietf-routing",
            "ietf-routing-policy",
            "ietf-ipv4-unicast-routing",
            "ietf-ipv6-unicast-routing",
            "ietf-segment-routing",
            "ietf-segment-routing-common",
            "ietf-segment-routing-mpls",
            "ietf-mpls",
            "ietf-mpls-msd",
            "ietf-mpls-ldp",
            "ietf-ospf",
            "ietf-ospf-sr-mpls",
            "ietf-ospfv3-extended-lsa",
            "ietf-rip",
            "ietf-system",
            "ietf-tcp",
            "ietf-vrrp",
            // IETF Holo augmentations
            "holo-bgp",
            "holo-isis",
            "holo-isis-dev",
            "holo-key-chain",
            "holo-ospf",
            "holo-ospf-dev",
            "holo-rip",
            "holo-routing",
            "holo-vrrp",
        ]
    });

// All features currently supported.
pub static YANG_FEATURES: Lazy<HashMap<&'static str, Vec<&'static str>>> =
    Lazy::new(|| {
        hashmap! {
            "iana-bgp-types" => vec![
                "clear-neighbors",
                "route-refresh",
                "ttl-security",
            ],
            "ietf-bfd-types" => vec![
                "client-base-cfg-parms",
                "single-minimum-interval",
            ],
            "ietf-key-chain" => vec![
                "cleartext",
                "hex-key-string",
                "independent-send-accept-lifetime",
            ],
            "ietf-if-extensions" => vec![
                "sub-interfaces",
            ],
            "ietf-isis" => vec![
                "admin-control",
                "bfd",
                "ietf-spf-delay",
                "key-chain",
                "lsp-refresh",
                "max-ecmp",
                "multi-topology",
                "node-flag",
                "node-tag",
                "nlpid-control",
                "poi-tlv",
                "te-rid",
            ],
            "ietf-ospf" => vec![
                "bfd",
                "explicit-router-id",
                "graceful-restart",
                "ietf-spf-delay",
                "key-chain",
                "lls",
                "max-ecmp",
                "mtu-ignore",
                "node-tag",
                "ospfv3-authentication-trailer",
                "stub-router",
            ],
            "ietf-rip" => vec![
                "explicit-neighbors",
                "global-statistics",
                "interface-statistics",
            ],
            "ietf-segment-routing-common" => vec![
                "sid-last-hop-behavior",
            ],
            "ietf-vrrp" => vec![
                "validate-interval-errors",
            ],
        }
    });

//
// YANG conversion traits.
//

pub trait ToYang {
    // Return YANG textual representation of the value.
    fn to_yang(&self) -> Cow<'static, str>;
}

pub trait ToYangBits {
    // Return vector representing YANG bit set.
    fn to_yang_bits(&self) -> Vec<&'static str>;
}

pub trait TryFromYang: Sized {
    // Construct value from YANG identity or enum value.
    fn try_from_yang(identity: &str) -> Option<Self>;
}

// A trait representing YANG objects (containers or lists).
//
// This trait is automatically implemented for all structs generated from
// YANG definitions at build-time.
pub trait YangObject {
    // Initialize a given YANG data node with attributes from the current
    // object.
    fn into_data_node(self: Box<Self>, dnode: &mut DataNodeRef<'_>);

    // Return the keys of the list, or an empty string for containers or keyless
    // lists.
    fn list_keys(&self) -> String {
        String::new()
    }
}

//
// YANG path type.
//
// Instances of this structure are created automatically at build-time, and
// their use should be preferred over regular strings for extra type safety.
//
#[derive(Clone, Copy, Debug)]
pub struct YangPath(&'static str);

// ===== impl YangPath =====

impl YangPath {
    pub const fn new(path: &'static str) -> YangPath {
        YangPath(path)
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for YangPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for YangPath {
    fn as_ref(&self) -> &str {
        self.0
    }
}

// ===== global functions =====

// Creates empty YANG context.
pub fn new_context() -> Context {
    let mut ctx = Context::new(
        ContextFlags::NO_YANGLIBRARY | ContextFlags::DISABLE_SEARCHDIRS,
    )
    .expect("Failed to create YANG context");
    ctx.set_embedded_modules(&YANG_EMBEDDED_MODULES);
    ctx
}

// Loads a YANG module.
pub fn load_module(ctx: &mut Context, name: &str) {
    let features = YANG_FEATURES
        .get(name)
        .map(|features| features.as_slice())
        .unwrap_or_else(|| &[]);
    if let Err(error) = ctx.load_module(name, None, features) {
        panic!("failed to load YANG module: {error}");
    }
}

// Loads a YANG deviations module.
pub fn load_deviations(ctx: &mut Context, name: &str) {
    let name = format!("holo-{name}-deviations");
    // Ignore errors since the deviation module might not exist.
    let _ = ctx.load_module(&name, None, &[]);
}
