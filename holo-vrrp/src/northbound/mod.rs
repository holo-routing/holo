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
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use tracing::{Span, debug_span};

use crate::interface::Interface;

// ===== impl Interface =====

impl ProviderBase for Interface {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-vrrp", "holo-vrrp"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-interfaces:interfaces/interface[name='{}']",
            self.name
        )
    }

    fn debug_span(interface: &str) -> Span {
        debug_span!("vrrp", %interface)
    }
}
