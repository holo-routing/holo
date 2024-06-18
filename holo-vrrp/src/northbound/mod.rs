//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod notification;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use holo_yang::ToYang;
use tracing::{debug_span, Span};

use crate::instance::Instance;

// ===== impl Instance =====

impl ProviderBase for Instance {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-vrrp", "holo-vrrp"]
    }

    fn top_level_node(&self) -> String {
        // TODO
        String::new()
    }

    fn debug_span(name: &str) -> Span {
        debug_span!("vrrp-instance", %name)
    }
}

// No RPC/Actions to implement.
impl holo_northbound::rpc::Provider for Instance {}
