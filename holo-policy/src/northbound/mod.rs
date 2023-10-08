//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod state;

use holo_northbound::rpc::Provider;
use holo_northbound::ProviderBase;
use tracing::{debug_span, Span};

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-routing-policy"]
    }

    fn top_level_node(&self) -> String {
        "/ietf-routing-policy:routing-policy".to_owned()
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("policy")
    }
}

// No RPC/Actions to implement.
impl Provider for Master {}
