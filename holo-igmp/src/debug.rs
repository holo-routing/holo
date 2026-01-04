//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ibus::IbusMsg;
use tracing::{debug, debug_span};

use crate::group::{Event, State};

// IGMP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    IbusRx(&'a IbusMsg),
    GroupCreate(Ipv4Addr),
    GroupEvent(Ipv4Addr, &'a State, &'a Event),
    GroupStateChange(Ipv4Addr, &'a State, &'a State),
    GroupTimerStart(Ipv4Addr, u32),
    GroupTimerCancel(Ipv4Addr),
    GroupLastMemberQuery(Ipv4Addr, u32, u32),
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
            Debug::GroupCreate(group_addr) => {
                debug_span!("group").in_scope(|| {
                    debug!(%group_addr, "{}", self);
                })
            }
            Debug::GroupEvent(group_addr, state, event) => debug_span!("group")
                .in_scope(|| {
                    debug!(%group_addr, ?state, ?event, "{}", self);
                }),
            Debug::GroupStateChange(group_addr, old_state, new_state) => {
                debug_span!("group").in_scope(|| {
                    debug!(%group_addr, ?old_state, ?new_state, "{}", self);
                })
            }
            Debug::GroupTimerStart(group_addr, timeout) => debug_span!("group")
                .in_scope(|| {
                    debug!(%group_addr, timeout, "{}", self);
                }),
            Debug::GroupTimerCancel(group_addr) => debug_span!("group")
                .in_scope(|| {
                    debug!(%group_addr, "{}", self);
                }),
            Debug::GroupLastMemberQuery(group_addr, count, interval) => {
                debug_span!("group").in_scope(|| {
                    debug!(%group_addr, count, interval, "{}", self);
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
            Debug::GroupCreate(..) => {
                write!(f, "group created")
            }
            Debug::GroupEvent(..) => {
                write!(f, "group event")
            }
            Debug::GroupStateChange(..) => {
                write!(f, "group state changed")
            }
            Debug::GroupTimerStart(..) => {
                write!(f, "group timer started")
            }
            Debug::GroupTimerCancel(..) => {
                write!(f, "group timer cancelled")
            }
            Debug::GroupLastMemberQuery(..) => {
                write!(f, "sending last member queries")
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
