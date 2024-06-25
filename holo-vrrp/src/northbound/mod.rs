//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

pub mod configuration;
pub mod notification;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use tracing::{debug_span, Span};

use crate::interface::Interface;

// ===== impl Interface =====

impl ProviderBase for Interface {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-vrrp", "holo-vrrp"]
    }

    fn top_level_node(&self) -> String {
        "/ietf-interfaces:interfaces".to_owned()
    }

    fn debug_span(interface: &str) -> Span {
        debug_span!("vrrp", %interface)
    }
}

// No RPC/Actions to implement.
impl holo_northbound::rpc::Provider for Interface {}
