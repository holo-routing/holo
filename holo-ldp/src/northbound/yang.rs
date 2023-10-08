//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_yang::ToYang;

use crate::neighbor::{self, LabelAdvMode, LabelDistMode};
use crate::northbound::state::AdvertisementType;

// ===== ToYang implementations =====

impl ToYang for AdvertisementType {
    fn to_yang(&self) -> String {
        match self {
            AdvertisementType::Advertised => "advertised".to_owned(),
            AdvertisementType::Received => "received".to_owned(),
        }
    }
}

impl ToYang for neighbor::fsm::State {
    fn to_yang(&self) -> String {
        match self {
            neighbor::fsm::State::NonExistent => "non-existent".to_owned(),
            neighbor::fsm::State::Initialized => "initialized".to_owned(),
            neighbor::fsm::State::OpenRec => "openrec".to_owned(),
            neighbor::fsm::State::OpenSent => "opensent".to_owned(),
            neighbor::fsm::State::Operational => "operational".to_owned(),
        }
    }
}

impl ToYang for LabelDistMode {
    fn to_yang(&self) -> String {
        match self {
            LabelDistMode::Independent => "independent".to_owned(),
            LabelDistMode::Ordered => "ordered".to_owned(),
        }
    }
}

impl ToYang for LabelAdvMode {
    fn to_yang(&self) -> String {
        match self {
            LabelAdvMode::DownstreamUnsolicited => {
                "downstream-unsolicited".to_owned()
            }
            LabelAdvMode::DownstreamOnDemand => {
                "downstream-on-demand".to_owned()
            }
        }
    }
}
