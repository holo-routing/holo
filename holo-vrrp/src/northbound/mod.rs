//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

pub mod configuration;
pub mod notification;
pub mod rpc;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;

use crate::interface::Interface;

// ===== impl Interface =====

impl ProviderBase for Interface {
    fn top_level_node(&self) -> String {
        format!(
            "/ietf-interfaces:interfaces/interface[name='{}']",
            self.name
        )
    }
}
