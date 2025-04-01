//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::borrow::Cow;

use holo_yang::{ToYang, ToYangBits, TryFromYang};
use regex::Regex;

use crate::adjacency::{AdjacencyEvent, AdjacencyState};
use crate::error::AdjacencyRejectError;
use crate::interface::InterfaceType;
use crate::lsdb::LspLogReason;
use crate::northbound::configuration::MetricType;
use crate::packet::consts::LspFlags;
use crate::packet::{AreaAddr, LanId, LevelNumber, LevelType, LspId, SystemId};
use crate::spf;
use crate::spf::SpfType;

// ===== ToYang implementations =====

impl ToYang for LevelType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LevelType::L1 => "level-1".into(),
            LevelType::L2 => "level-2".into(),
            LevelType::All => "level-all".into(),
        }
    }
}

impl ToYang for SystemId {
    fn to_yang(&self) -> Cow<'static, str> {
        let bytes = self.as_ref();
        Cow::Owned(format!(
            "{:02X}{:02X}.{:02X}{:02X}.{:02X}{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    }
}

impl ToYang for LanId {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(format!(
            "{}.{:02}",
            self.system_id.to_yang(),
            self.pseudonode,
        ))
    }
}

impl ToYang for LspId {
    fn to_yang(&self) -> Cow<'static, str> {
        Cow::Owned(format!(
            "{}.{:02}-{:02}",
            self.system_id.to_yang(),
            self.pseudonode,
            self.fragment,
        ))
    }
}

impl ToYang for AreaAddr {
    fn to_yang(&self) -> Cow<'static, str> {
        // Convert the bytes to a hex string.
        let hex_string: String = self
            .as_ref()
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect();

        // Split the hex string into groups of 4, starting with the first two
        // characters.
        let mut groups = vec![hex_string[0..2].to_string()];
        groups.extend(
            hex_string[2..]
                .chars()
                .collect::<Vec<char>>()
                .chunks(4)
                .map(|chunk| chunk.iter().collect::<String>()),
        );

        // Join the groups with periods.
        groups.join(".").into()
    }
}

impl ToYangBits for LspFlags {
    fn to_yang_bits(&self) -> Vec<&'static str> {
        let mut flags = vec![];

        if self.contains(LspFlags::P) {
            flags.push("ietf-isis:lsp-partitioned-flag");
        }
        if self.contains(LspFlags::ATT) {
            flags.push("ietf-isis:lsp-attached-default-metric-flag");
        }
        if self.contains(LspFlags::OL) {
            flags.push("ietf-isis:lsp-overload-flag");
        }
        if self.contains(LspFlags::IS_TYPE2) {
            flags.push("ietf-isis:lsp-l2-system-flag");
        }
        if self.contains(LspFlags::IS_TYPE1) {
            flags.push("ietf-isis:lsp-l1-system-flag");
        }

        flags
    }
}

impl ToYang for AdjacencyState {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AdjacencyState::Down => "down".into(),
            AdjacencyState::Initializing => "init".into(),
            AdjacencyState::Up => "up".into(),
        }
    }
}

impl ToYang for AdjacencyEvent {
    // The "reason" leaf in the "adjacency-state-change" notification uses a
    // primitive "string" type, allowing us to define error reasons freely.
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AdjacencyEvent::HelloOneWayRcvd => "hello-one-way".into(),
            AdjacencyEvent::HelloTwoWayRcvd => "hello-two-way".into(),
            AdjacencyEvent::HoldtimeExpired => "hold-time-expired".into(),
            AdjacencyEvent::LinkDown => "link-down".into(),
            AdjacencyEvent::Kill => "kill".into(),
        }
    }
}

impl ToYang for AdjacencyRejectError {
    // The "reason" leaf in the "rejected-adjacency" notification uses a
    // primitive "string" type, allowing us to define error reasons freely.
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AdjacencyRejectError::InvalidHelloType => {
                "invalid-hello-type".into()
            }
            AdjacencyRejectError::CircuitTypeMismatch => {
                "circuit-type-mismatch".into()
            }
            AdjacencyRejectError::MaxAreaAddrsMismatch(..) => {
                "max-area-addresses-mismatch".into()
            }
            AdjacencyRejectError::AreaMismatch => "area-mismatch".into(),
            AdjacencyRejectError::WrongSystem => "wrong-system".into(),
            AdjacencyRejectError::DuplicateSystemId => {
                "duplicate-system-id".into()
            }
        }
    }
}

impl ToYang for LspLogReason {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            LspLogReason::Refresh => "refresh".into(),
            LspLogReason::ContentChange => "content-change".into(),
        }
    }
}

impl ToYang for spf::fsm::State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            spf::fsm::State::Quiet => "quiet".into(),
            spf::fsm::State::ShortWait => "short-wait".into(),
            spf::fsm::State::LongWait => "long-wait".into(),
        }
    }
}

impl ToYang for SpfType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            SpfType::Full => "full".into(),
            SpfType::RouteOnly => "route-only".into(),
        }
    }
}

// ===== TryFromYang implementations =====

impl TryFromYang for LevelNumber {
    fn try_from_yang(value: &str) -> Option<LevelNumber> {
        match value {
            "1" => Some(LevelNumber::L1),
            "2" => Some(LevelNumber::L2),
            _ => None,
        }
    }
}

impl TryFromYang for LevelType {
    fn try_from_yang(value: &str) -> Option<LevelType> {
        match value {
            "level-1" => Some(LevelType::L1),
            "level-2" => Some(LevelType::L2),
            "level-all" => Some(LevelType::All),
            _ => None,
        }
    }
}

impl TryFromYang for AreaAddr {
    fn try_from_yang(value: &str) -> Option<AreaAddr> {
        // Define the regex pattern to match an area address.
        let re = regex::Regex::new(r"^[0-9A-Fa-f]{2}(\.[0-9A-Fa-f]{4}){0,6}$")
            .ok()?;
        if !re.is_match(value) {
            return None;
        }

        // Remove the dots and convert the hex string into a vector of bytes.
        let area_addr = value.replace('.', "");
        let bytes = (0..area_addr.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&area_addr[i..i + 2], 16).unwrap())
            .collect();

        Some(AreaAddr::new(bytes))
    }
}

impl TryFromYang for SystemId {
    fn try_from_yang(value: &str) -> Option<SystemId> {
        // Initialize an array to hold the parsed bytes.
        let mut bytes = [0u8; 6];

        // Define the regex pattern to match a System ID.
        let re = Regex::new(
            r"^([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})$",
        )
        .ok()?;

        // Apply the regex to the input string.
        let caps = re.captures(value)?;

        // Convert each 4-character group to 2 bytes and populate the byte array.
        for i in 0..3 {
            let group_str = caps.get(i + 1).unwrap().as_str();
            bytes[i * 2] = u8::from_str_radix(&group_str[0..2], 16).ok()?;
            bytes[i * 2 + 1] = u8::from_str_radix(&group_str[2..4], 16).ok()?;
        }

        Some(SystemId::from(bytes))
    }
}

impl TryFromYang for InterfaceType {
    fn try_from_yang(value: &str) -> Option<InterfaceType> {
        match value {
            "broadcast" => Some(InterfaceType::Broadcast),
            "point-to-point" => Some(InterfaceType::PointToPoint),
            _ => None,
        }
    }
}

impl TryFromYang for MetricType {
    fn try_from_yang(value: &str) -> Option<MetricType> {
        match value {
            "wide-only" => Some(MetricType::Wide),
            "old-only" => Some(MetricType::Standard),
            "both" => Some(MetricType::Both),
            _ => None,
        }
    }
}
