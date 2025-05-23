//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
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
        &["ietf-igmp-mld"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-igmp-mld:igmp",
            Protocol::IGMP.to_yang(),
            self.name
        )
    }

    fn debug_span(name: &str) -> Span {
        debug_span!("igmp-instance", %name)
    }
}
