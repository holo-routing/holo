//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod rpc;
pub mod state;

use holo_northbound::ProviderBase;

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn top_level_node(&self) -> String {
        "/ietf-system:system".to_owned()
    }
}
