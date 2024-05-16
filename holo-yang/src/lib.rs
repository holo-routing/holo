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
use tracing::error;
use yang2::context::{
    Context, ContextFlags, EmbeddedModuleKey, EmbeddedModules,
};
use yang2::data::DataNodeRef;

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
        EmbeddedModuleKey::new("iana-if-type", Some("2017-01-19"), None, None) =>
            include_str!("../modules/ietf/iana-if-type@2017-01-19.yang"),
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
        EmbeddedModuleKey::new("ietf-key-chain", Some("2017-06-15"), None, None) =>
            include_str!("../modules/ietf/ietf-key-chain@2017-06-15.yang"),
        EmbeddedModuleKey::new("ietf-mpls", Some("2020-12-18"), None, None) =>
            include_str!("../modules/ietf/ietf-mpls@2020-12-18.yang"),
        EmbeddedModuleKey::new("ietf-mpls-ldp", Some("2022-03-14"), None, None) =>
            include_str!("../modules/ietf/ietf-mpls-ldp@2022-03-14.yang"),
        EmbeddedModuleKey::new("ietf-netconf-acm", Some("2018-02-14"), None, None) =>
            include_str!("../modules/ietf/ietf-netconf-acm@2018-02-14.yang"),
        EmbeddedModuleKey::new("ietf-ospf", Some("2022-10-19"), None, None) =>
            include_str!("../modules/ietf/ietf-ospf@2022-10-19.yang"),
        EmbeddedModuleKey::new("ietf-ospf-sr-mpls", Some("2024-01-18"), None, None) =>
            include_str!("../modules/ietf/ietf-ospf-sr-mpls@2024-01-18.yang"),
        EmbeddedModuleKey::new("ietf-ospfv3-extended-lsa", Some("2024-01-16"), None, None) =>
            include_str!("../modules/ietf/ietf-ospfv3-extended-lsa@2024-01-16.yang"),
        EmbeddedModuleKey::new("ietf-rip", Some("2020-02-20"), None, None) =>
            include_str!("../modules/ietf/ietf-rip@2020-02-20.yang"),
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
        // IETF Holo augmentations
        EmbeddedModuleKey::new("holo-bgp", None, None, None) =>
            include_str!("../modules/augmentations/holo-bgp.yang"),
        EmbeddedModuleKey::new("holo-ospf", None, None, None) =>
            include_str!("../modules/augmentations/holo-ospf.yang"),
        EmbeddedModuleKey::new("holo-ospf-dev", None, None, None) =>
            include_str!("../modules/augmentations/holo-ospf-dev.yang"),
        // IETF Holo deviations
        EmbeddedModuleKey::new("ietf-bgp-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-bgp-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-mpls-ldp-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-mpls-ldp-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-if-extensions-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-if-extensions-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-if-vlan-encapsulation-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-if-vlan-encapsulation-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-interfaces-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-interfaces-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-ip-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-ip-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-mpls-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-mpls-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-key-chain-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-key-chain-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-ospf-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-ospf-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-ospf-sr-mpls-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-ospf-sr-mpls-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-ospfv3-extended-lsa-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-ospfv3-extended-lsa-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-rip-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-rip-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-routing-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-routing-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-ipv6-unicast-routing-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-ipv6-unicast-routing-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-routing-policy-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-routing-policy-holo-deviations.yang"),
        EmbeddedModuleKey::new("ietf-segment-routing-mpls-holo-deviations", None, None, None) =>
            include_str!("../modules/deviations/ietf-segment-routing-mpls-holo-deviations.yang"),
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
            "ietf-bfd-ip-mh",
            "ietf-bfd-ip-sh",
            "ietf-bfd-types",
            "ietf-bfd",
            "ietf-bgp",
            "ietf-bgp-policy",
            "ietf-routing-types",
            "ietf-if-extensions",
            "ietf-if-vlan-encapsulation",
            "ietf-interfaces",
            "ietf-ip",
            "ietf-key-chain",
            "ietf-routing",
            "ietf-routing-policy",
            "ietf-ipv4-unicast-routing",
            "ietf-ipv6-unicast-routing",
            "ietf-segment-routing",
            "ietf-segment-routing-common",
            "ietf-segment-routing-mpls",
            "ietf-mpls",
            "ietf-mpls-ldp",
            "ietf-ospf",
            "ietf-ospf-sr-mpls",
            "ietf-ospfv3-extended-lsa",
            "ietf-rip",
            "ietf-tcp",
            // IETF Holo augmentations
            "holo-bgp",
            "holo-ospf",
            "holo-ospf-dev",
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
                "hex-key-string",
                "independent-send-accept-lifetime",
            ],
            "ietf-if-extensions" => vec![
                "sub-interfaces",
            ],
            "ietf-ospf" => vec![
                "bfd",
                "explicit-router-id",
                "graceful-restart",
                "ietf-spf-delay",
                "key-chain",
                "max-ecmp",
                "mtu-ignore",
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
    fn into_data_node(self, dnode: &mut DataNodeRef<'_>);

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
        error!(%error, "failed to load YANG module");
        std::process::exit(1);
    }
}

// Loads a YANG deviations module.
pub fn load_deviations(ctx: &mut Context, name: &str) {
    let name = format!("{}-holo-deviations", name);
    // Ignore errors since the deviation module might not exist.
    let _ = ctx.load_module(&name, None, &[]);
}
