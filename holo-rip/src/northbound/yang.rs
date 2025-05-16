//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::{ToYang, TryFromYang};

use crate::interface::SplitHorizon;
use crate::northbound::configuration::TraceOption;
use crate::route::RouteType;

// ===== ToYang implementations =====

impl ToYang for RouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            RouteType::Connected => "connected".into(),
            RouteType::Rip => "rip".into(),
        }
    }
}

// ===== TryFromYang implementations =====

impl TryFromYang for SplitHorizon {
    fn try_from_yang(value: &str) -> Option<SplitHorizon> {
        match value {
            "disabled" => Some(SplitHorizon::Disabled),
            "simple" => Some(SplitHorizon::Simple),
            "poison-reverse" => Some(SplitHorizon::PoisonReverse),
            _ => None,
        }
    }
}

impl TryFromYang for TraceOption {
    fn try_from_yang(value: &str) -> Option<TraceOption> {
        match value {
            "events" => Some(TraceOption::Events),
            "internal-bus" => Some(TraceOption::InternalBus),
            "packets" => Some(TraceOption::Packets),
            "route" => Some(TraceOption::Route),
            _ => None,
        }
    }
}
