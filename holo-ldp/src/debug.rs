//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, Ipv4Addr};

use holo_utils::mpls::Label;
use tracing::{debug, debug_span, Span};

use crate::discovery::AdjacencySource;
use crate::fec::{Fec, Nexthop};
use crate::neighbor;
use crate::packet::messages::hello::HelloMsg;
use crate::packet::Message;

// LDP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    InstanceCreate,
    InstanceDelete,
    InstanceStart,
    InstanceStop(InstanceInactiveReason),
    InstanceStatusCheck(&'a str),
    InterfaceCreate(&'a str),
    InterfaceDelete(&'a str),
    InterfaceStart(&'a str),
    InterfaceStop(&'a str, InterfaceInactiveReason),
    TargetedNbrCreate(&'a IpAddr),
    TargetedNbrDelete(&'a IpAddr),
    TargetedNbrStart(&'a IpAddr),
    TargetedNbrStop(&'a IpAddr),
    AdjacencyCreate(&'a AdjacencySource, &'a Ipv4Addr),
    AdjacencyDelete(&'a AdjacencySource, &'a Ipv4Addr),
    AdjacencyTimeout(&'a AdjacencySource, &'a Ipv4Addr),
    AdjacencyHelloRx(&'a Span, &'a AdjacencySource, &'a Ipv4Addr, &'a HelloMsg),
    AdjacencyHelloTx(&'a HelloMsg),
    NoMatchingHelloAdjacency(&'a IpAddr),
    NbrCreate(&'a Ipv4Addr),
    NbrDelete(&'a Ipv4Addr),
    NbrFsmTransition(
        &'a Ipv4Addr,
        &'a neighbor::fsm::Event,
        &'a neighbor::fsm::State,
        &'a neighbor::fsm::State,
    ),
    NbrMsgRx(&'a Ipv4Addr, &'a Message),
    NbrMsgTx(&'a Ipv4Addr, &'a Message),
    NbrInitBackoffTimeout(&'a Ipv4Addr),
    FecCreate(&'a Fec),
    FecDelete(&'a Fec),
    FecLabelUpdate(&'a Fec, &'a Option<Label>),
    NexthopCreate(&'a Nexthop),
    NexthopDelete(&'a Nexthop),
    NexthopLabelUpdate(&'a Nexthop, &'a Option<Label>),
}

// Reason why an LDP instance is inactive.
#[derive(Debug)]
pub enum InstanceInactiveReason {
    AdminDown,
    MissingRouterId,
}

// Reason why LDP is inactive on an interface.
#[derive(Debug)]
pub enum InterfaceInactiveReason {
    InstanceDown,
    AdminDown,
    OperationalDown,
    MissingIfindex,
    MissingIpAddress,
}

// ===== impl Debug =====

impl<'a> Debug<'a> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate
            | Debug::InstanceDelete
            | Debug::InstanceStart => {
                // Parent span(s): ldp-instance
                debug!("{}", self);
            }
            Debug::InstanceStop(reason) => {
                // Parent span(s): ldp-instance
                debug!(%reason, "{}", self);
            }
            Debug::InstanceStatusCheck(status) => {
                // Parent span(s): ldp-instance
                debug!(%status, "{}", self);
            }
            Debug::InterfaceCreate(name)
            | Debug::InterfaceDelete(name)
            | Debug::InterfaceStart(name) => {
                // Parent span(s): ldp-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::InterfaceStop(name, reason) => {
                // Parent span(s): ldp-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%reason, "{}", self);
                });
            }
            Debug::TargetedNbrCreate(addr)
            | Debug::TargetedNbrDelete(addr)
            | Debug::TargetedNbrStart(addr)
            | Debug::TargetedNbrStop(addr) => {
                // Parent span(s): ldp-instance
                debug_span!("targeted-nbr", address = %addr).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::AdjacencyCreate(source, lsr_id)
            | Debug::AdjacencyDelete(source, lsr_id)
            | Debug::AdjacencyTimeout(source, lsr_id) => {
                // Parent span(s): ldp-instance
                debug!(%source, %lsr_id, "{}", self);
            }
            Debug::AdjacencyHelloRx(span, source, lsr_id, msg) => {
                // Parent span(s): ldp-instance:{interface, targeted-nbr}
                // (dynamic)
                span.in_scope(|| {
                    debug_span!("discovery").in_scope(|| {
                        debug_span!("input").in_scope(|| {
                            let data = serde_json::to_string(&msg).unwrap();
                            debug!(%source, %lsr_id, %data, "{}", self);
                        })
                    })
                });
            }
            Debug::AdjacencyHelloTx(msg) => {
                // Parent span(s):
                // ldp-instance:{interface,targeted-nbr}:discovery:output
                // (dynamic)
                let data = serde_json::to_string(&msg).unwrap();
                debug!(%data, "{}", self);
            }
            Debug::NoMatchingHelloAdjacency(source) => {
                debug!(%source, "{}", self);
            }
            Debug::NbrCreate(lsr_id) | Debug::NbrDelete(lsr_id) => {
                // Parent span(s): ldp-instance
                debug_span!("neighbor", %lsr_id).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::NbrFsmTransition(lsr_id, event, old_state, new_state) => {
                // Parent span(s): ldp-instance
                debug_span!("neighbor", %lsr_id).in_scope(|| {
                    debug_span!("fsm").in_scope(|| {
                        debug!(?event, ?old_state, ?new_state, "{}", self);
                    })
                });
            }
            Debug::NbrMsgRx(lsr_id, msg) => {
                // Parent span(s): ldp-instance
                debug_span!("neighbor", %lsr_id).in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(r#type = %msg.msg_type(), %data, "{}", self);
                    })
                });
            }
            Debug::NbrMsgTx(lsr_id, msg) => {
                // Parent span(s): ldp-instance
                debug_span!("neighbor", %lsr_id).in_scope(|| {
                    debug_span!("output").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(r#type = %msg.msg_type(), %data, "{}", self);
                    })
                });
            }
            Debug::NbrInitBackoffTimeout(lsr_id) => {
                // Parent span(s): ldp-instance
                debug_span!("neighbor", %lsr_id).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::FecCreate(fec) | Debug::FecDelete(fec) => {
                // Parent span(s): ldp-instance
                debug_span!("lib", prefix = %fec.inner.prefix).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::FecLabelUpdate(fec, new_label) => {
                // Parent span(s): ldp-instance
                let old_label = fec
                    .inner
                    .local_label
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let new_label = new_label
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "none".to_string());

                debug_span!("lib", prefix = %fec.inner.prefix).in_scope(|| {
                    debug!(%old_label, %new_label, "{}", self);
                });
            }
            Debug::NexthopCreate(nexthop) | Debug::NexthopDelete(nexthop) => {
                // Parent span(s): ldp-instance
                debug_span!("lib", prefix = %nexthop.prefix).in_scope(|| {
                    debug!(address = %nexthop.addr, "{}", self);
                });
            }
            Debug::NexthopLabelUpdate(nexthop, new_label) => {
                // Parent span(s): ldp-instance
                let old_label = nexthop
                    .get_label()
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let new_label = new_label
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "none".to_string());

                debug_span!("lib", prefix = %nexthop.prefix).in_scope(|| {
                    debug!(
                        address = %nexthop.addr,
                        %old_label,
                        %new_label,
                        "{}", self
                    );
                });
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
            Debug::InterfaceCreate(..) => {
                write!(f, "interface created")
            }
            Debug::InterfaceDelete(..) => {
                write!(f, "interface deleted")
            }
            Debug::InterfaceStart(..) => {
                write!(f, "starting interface")
            }
            Debug::InterfaceStop(..) => {
                write!(f, "stopping interface")
            }
            Debug::TargetedNbrCreate(..) => {
                write!(f, "targeted neighbor created")
            }
            Debug::TargetedNbrDelete(..) => {
                write!(f, "targeted neighbor deleted")
            }
            Debug::TargetedNbrStart(..) => {
                write!(f, "starting targeted neighbor")
            }
            Debug::TargetedNbrStop(..) => {
                write!(f, "stopping targeted neighbor")
            }
            Debug::AdjacencyCreate(..) => {
                write!(f, "adjacency created")
            }
            Debug::AdjacencyDelete(..) => {
                write!(f, "adjacency deleted")
            }
            Debug::AdjacencyTimeout(..) => {
                write!(f, "adjacency timed out")
            }
            Debug::AdjacencyHelloRx(..) => {
                write!(f, "hello message")
            }
            Debug::AdjacencyHelloTx(..) => {
                write!(f, "hello message")
            }
            Debug::NoMatchingHelloAdjacency(..) => {
                write!(f, "no matching hello adjacency")
            }
            Debug::NbrCreate(..) => {
                write!(f, "neighbor created")
            }
            Debug::NbrDelete(..) => {
                write!(f, "neighbor deleted")
            }
            Debug::NbrFsmTransition(..) => {
                write!(f, "state transition")
            }
            Debug::NbrMsgRx(..) | Debug::NbrMsgTx(..) => {
                write!(f, "message")
            }
            Debug::NbrInitBackoffTimeout(..) => {
                write!(f, "initialization backoff timer expired")
            }
            Debug::FecCreate(..) => {
                write!(f, "FEC created")
            }
            Debug::FecDelete(..) => {
                write!(f, "FEC deleted")
            }
            Debug::FecLabelUpdate(..) => {
                write!(f, "FEC label updated")
            }
            Debug::NexthopCreate(..) => {
                write!(f, "nexthop created")
            }
            Debug::NexthopDelete(..) => {
                write!(f, "nexthop deleted")
            }
            Debug::NexthopLabelUpdate(..) => {
                write!(f, "nexthop label updated")
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

// ===== impl InterfaceInactiveReason =====

impl std::fmt::Display for InterfaceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceInactiveReason::InstanceDown => {
                write!(f, "LDP instance down")
            }
            InterfaceInactiveReason::AdminDown => {
                write!(f, "administrative status down")
            }
            InterfaceInactiveReason::OperationalDown => {
                write!(f, "operational status down")
            }
            InterfaceInactiveReason::MissingIfindex => {
                write!(f, "missing ifindex")
            }
            InterfaceInactiveReason::MissingIpAddress => {
                write!(f, "missing IP address")
            }
        }
    }
}
