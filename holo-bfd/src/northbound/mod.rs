//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod notification;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use tracing::{debug_span, Span};

use crate::master::Master;

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-bfd-ip-mh", "ietf-bfd-ip-sh", "ietf-bfd"]
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("bfd")
    }
}

// No RPC/Actions to implement.
impl holo_northbound::rpc::Provider for Master {}
