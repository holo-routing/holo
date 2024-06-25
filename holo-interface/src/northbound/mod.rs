//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod state;

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::Provider;
use holo_northbound::yang::interfaces;
use holo_northbound::ProviderBase;
use regex::Regex;
use tracing::{debug_span, Span};

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &[
            "ietf-if-extensions",
            "ietf-if-vlan-encapsulation",
            "ietf-interfaces",
            "ietf-ip",
        ]
    }

    fn top_level_node(&self) -> String {
        "/ietf-interfaces:interfaces".to_owned()
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("interface")
    }
}

// No RPC/Actions to implement.
impl Provider for Master {}

// ===== regular expressions =====

// Matches on the protocol type and instance name of a YANG path.
static REGEX_VRRP_STR: Lazy<String> = Lazy::new(|| {
    format!(
        r"{}\[name='(.+?)'\]/ietf-ip:ipv4/ietf-vrrp:vrrp/*",
        interfaces::interface::PATH
    )
});
pub static REGEX_VRRP: Lazy<Regex> =
    Lazy::new(|| Regex::new(&REGEX_VRRP_STR).unwrap());
