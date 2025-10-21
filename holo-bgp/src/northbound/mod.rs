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

use crate::instance::Instance;

// ===== impl Instance =====

impl ProviderBase for Instance {
    fn yang_modules() -> &'static [&'static str] {
        &[
            "iana-bgp-notification",
            "iana-bgp-rib-types",
            "iana-bgp-types",
            "ietf-bgp",
            "holo-bgp",
        ]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-bgp:bgp",
            Protocol::BGP.to_yang(),
            self.name
        )
    }
}
