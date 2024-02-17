//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use tracing::{debug, debug_span};

use crate::neighbor::fsm;
use crate::packet::consts::AttrType;
use crate::packet::error::AttrError;
use crate::packet::message::Message;
use crate::rib::Route;

// BGP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    InstanceCreate,
    InstanceDelete,
    InstanceStart,
    InstanceStop(InstanceInactiveReason),
    InstanceStatusCheck(&'a str),
    NbrFsmEvent(&'a IpAddr, &'a fsm::Event),
    NbrFsmTransition(&'a IpAddr, &'a fsm::State, &'a fsm::State),
    NbrMsgRx(&'a IpAddr, &'a Message),
    NbrMsgTx(&'a IpAddr, &'a Message),
    NbrAttrError(AttrType, AttrError),
    BestPathFound(IpNetwork, &'a Route),
    BestPathNotFound(IpNetwork),
}

// Reason why an BGP instance is inactive.
#[derive(Debug)]
pub enum InstanceInactiveReason {
    AdminDown,
    MissingRouterId,
}

// ===== impl Debug =====

impl<'a> Debug<'a> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate
            | Debug::InstanceDelete
            | Debug::InstanceStart => {
                // Parent span(s): bgp-instance
                debug!("{}", self);
            }
            Debug::InstanceStop(reason) => {
                // Parent span(s): bgp-instance
                debug!(%reason, "{}", self);
            }
            Debug::InstanceStatusCheck(status) => {
                // Parent span(s): bgp-instance
                debug!(%status, "{}", self);
            }
            Debug::NbrFsmEvent(nbr_addr, event) => {
                // Parent span(s): bgp-instance
                debug_span!("neighbor", %nbr_addr).in_scope(|| {
                    debug_span!("fsm").in_scope(|| {
                        debug!(?event, "{}", self);
                    })
                });
            }
            Debug::NbrFsmTransition(nbr_addr, old_state, new_state) => {
                // Parent span(s): bgp-instance
                debug_span!("neighbor", %nbr_addr).in_scope(|| {
                    debug_span!("fsm").in_scope(|| {
                        debug!(?old_state, ?new_state, "{}", self);
                    })
                });
            }
            Debug::NbrMsgRx(nbr_addr, msg) => {
                // Parent span(s): bgp-instance
                debug_span!("neighbor", %nbr_addr).in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(%data, "{}", self);
                    })
                });
            }
            Debug::NbrMsgTx(nbr_addr, msg) => {
                // Parent span(s): bgp-instance
                debug_span!("neighbor", %nbr_addr).in_scope(|| {
                    debug_span!("output").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(%data, "{}", self);
                    })
                });
            }
            Debug::NbrAttrError(attr_type, action) => {
                // Parent span(s): bgp-instance
                debug!(?attr_type, ?action, "{}", self);
            }
            Debug::BestPathFound(prefix, route) => {
                // Parent span(s): bgp-instance
                debug!(%prefix, origin = ?route.origin, "{}", self);
            }
            Debug::BestPathNotFound(prefix) => {
                // Parent span(s): bgp-instance
                debug!(%prefix, "{}", self);
            }
        }
    }
}

impl<'a> std::fmt::Display for Debug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::InstanceCreate => {
                write!(f, "instance created")
            }
            Debug::InstanceDelete => {
                write!(f, "instance deleted")
            }
            Debug::InstanceStart => {
                write!(f, "starting instance")
            }
            Debug::InstanceStop(..) => {
                write!(f, "stopping instance")
            }
            Debug::InstanceStatusCheck(..) => {
                write!(f, "checking instance status")
            }
            Debug::NbrFsmEvent(..) => {
                write!(f, "event")
            }
            Debug::NbrFsmTransition(..) => {
                write!(f, "state transition")
            }
            Debug::NbrMsgRx(..) | Debug::NbrMsgTx(..) => {
                write!(f, "message")
            }
            Debug::NbrAttrError(..) => {
                write!(f, "malformed attribute")
            }
            Debug::BestPathFound(..) => {
                write!(f, "best path found")
            }
            Debug::BestPathNotFound(..) => {
                write!(f, "best path not found")
            }
        }
    }
}

// ===== impl InstanceInactiveReason =====

impl std::fmt::Display for InstanceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InstanceInactiveReason::MissingRouterId => {
                write!(f, "missing router-id")
            }
        }
    }
}
