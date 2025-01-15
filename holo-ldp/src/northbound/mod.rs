//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
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

impl ProviderBase for Instance {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-mpls-ldp"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-mpls-ldp:mpls-ldp",
            Protocol::LDP.to_yang(),
            self.name
        )
    }

    fn debug_span(name: &str) -> Span {
        debug_span!("ldp-instance", %name)
    }
}
