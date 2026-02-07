//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;

use holo_yang::ToYang;

use crate::neighbor::{self, LabelAdvMode, LabelDistMode};
use crate::northbound::state::AdvertisementType;

// ===== ToYang implementations =====

impl ToYang for AdvertisementType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AdvertisementType::Advertised => "advertised".into(),
            AdvertisementType::Received => "received".into(),
        }
    }
}

impl ToYang for neighbor::fsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            neighbor::fsm::State::NonExistent => "non-existent".into(),
            neighbor::fsm::State::Initialized => "initialized".into(),
            neighbor::fsm::State::OpenRec => "openrec".into(),
            neighbor::fsm::State::OpenSent => "opensent".into(),
            neighbor::fsm::State::Operational => "operational".into(),
        }
    }
}

impl ToYang for LabelDistMode {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LabelDistMode::Independent => "independent".into(),
            LabelDistMode::Ordered => "ordered".into(),
        }
    }
}

impl ToYang for LabelAdvMode {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LabelAdvMode::DownstreamUnsolicited => "downstream-unsolicited".into(),
            LabelAdvMode::DownstreamOnDemand => "downstream-on-demand".into(),
        }
    }
}
