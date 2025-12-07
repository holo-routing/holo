//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod configuration;
pub mod rpc;
pub mod state;
pub mod yang;

use std::sync::LazyLock as Lazy;

use holo_northbound::ProviderBase;
use holo_northbound::yang::control_plane_protocol;
use regex::Regex;

use crate::Master;

// ===== impl Master =====

impl ProviderBase for Master {
    fn top_level_node(&self) -> String {
        "/ietf-routing:routing".to_owned()
    }
}

// ===== regular expressions =====

// Matches on the protocol type and instance name of a YANG path.
static REGEX_PROTOCOLS_STR: Lazy<String> = Lazy::new(|| {
    format!(
        r"{}\[type='(.+?)'\]\[name='(.+?)'\]*",
        control_plane_protocol::PATH
    )
});
pub static REGEX_PROTOCOLS: Lazy<Regex> =
    Lazy::new(|| Regex::new(&REGEX_PROTOCOLS_STR).unwrap());
