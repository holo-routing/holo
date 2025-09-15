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
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;
use tracing::{Span, debug_span};

use crate::instance::Instance;

// ===== impl Instance =====

impl ProviderBase for Instance {
    fn yang_modules() -> &'static [&'static str] {
        &[
            "ietf-isis",
            "ietf-isis-msd",
            "ietf-isis-sr-mpls",
            "holo-isis",
            "holo-isis-dev",
        ]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-isis:isis",
            Protocol::ISIS.to_yang(),
            self.name
        )
    }

    fn debug_span(name: &str) -> Span {
        debug_span!("isis-instance", %name)
    }
}
