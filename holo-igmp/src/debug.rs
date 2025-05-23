//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::IbusMsg;
use tracing::{debug, debug_span};

// IGMP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    IbusRx(&'a IbusMsg),
}

// Reason why IGMP is inactive on an interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceInactiveReason {
    AdminDown,
    OperationalDown,
    MissingIfindex,
}

// ===== impl Debug =====

impl Debug<'_> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::IbusRx(msg) => {
                // Parent span(s): igmp-instance
                debug_span!("internal-bus").in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(%data, "{}", self);
                    })
                })
            }
        }
    }
}

impl std::fmt::Display for Debug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::IbusRx(..) => {
                write!(f, "message")
            }
        }
    }
}

// ===== impl InterfaceInactiveReason =====

impl std::fmt::Display for InterfaceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InterfaceInactiveReason::OperationalDown => {
                write!(f, "operational status down")
            }
            InterfaceInactiveReason::MissingIfindex => {
                write!(f, "missing ifindex")
            }
        }
    }
}
