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
        &["ietf-interfaces", "ietf-ip"]
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("interface")
    }
}

// No RPC/Actions to implement.
impl Provider for Master {}
