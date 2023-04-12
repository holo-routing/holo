//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod notification;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use tracing::{debug_span, Span};

use crate::instance::Instance;

impl ProviderBase for Instance {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-mpls-ldp"]
    }

    fn debug_span(name: &str) -> Span {
        debug_span!("ldp-instance", %name)
    }
}
