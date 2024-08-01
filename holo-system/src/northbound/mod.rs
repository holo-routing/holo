//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod state;

use holo_northbound::{rpc, ProviderBase};
use tracing::{debug_span, Span};

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-system"]
    }

    fn top_level_node(&self) -> String {
        "/ietf-system:system".to_owned()
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("system")
    }
}

// No RPC/Actions to implement.
impl rpc::Provider for Master {}
