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

use crate::master::Master;

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-bfd-ip-mh", "ietf-bfd-ip-sh", "ietf-bfd"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='main']/ietf-bfd:bfd",
            Protocol::BFD.to_yang(),
        )
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("bfd")
    }
}
