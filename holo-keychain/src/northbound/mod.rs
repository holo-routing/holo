//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod state;

use holo_northbound::ProviderBase;
use holo_northbound::rpc::Provider;
use tracing::{Span, debug_span};

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-key-chain"]
    }

    fn top_level_node(&self) -> String {
        "/ietf-key-chain:key-chains".to_owned()
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("key-chain")
    }
}

// No RPC/Actions to implement.
impl Provider for Master {}
