//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::{ToYang, TryFromYang};

use crate::northbound::configuration::NexthopSpecial;

// ===== impl NexthopSpecial =====

impl ToYang for NexthopSpecial {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            NexthopSpecial::Blackhole => "blackhole".into(),
            NexthopSpecial::Unreachable => "unreachable".into(),
            NexthopSpecial::Prohibit => "prohibit".into(),
        }
    }
}

impl TryFromYang for NexthopSpecial {
    fn try_from_yang(value: &str) -> Option<NexthopSpecial> {
        match value {
            "blackhole" => Some(NexthopSpecial::Blackhole),
            "unreachable" => Some(NexthopSpecial::Unreachable),
            "prohibit" => Some(NexthopSpecial::Prohibit),
            _ => None,
        }
    }
}
