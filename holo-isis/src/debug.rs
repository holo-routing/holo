//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::IpAddr;
use std::time::Duration;

use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use holo_yang::ToYang;
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span};

use crate::adjacency::{Adjacency, AdjacencyEvent, AdjacencyState};
use crate::interface::{DisCandidate, Interface, InterfaceType};
use crate::network::MulticastAddr;
use crate::packet::LevelNumber;
use crate::packet::pdu::{Lsp, Pdu};
use crate::spf;
use crate::spf::{SpfType, Vertex, VertexEdge};

// IS-IS debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    // Instances
    InstanceCreate,
    InstanceDelete,
    InstanceStart,
    InstanceStop(InstanceInactiveReason),
    // Interfaces
    InterfaceCreate(&'a str),
    InterfaceDelete(&'a str),
    InterfaceStart(&'a str),
    InterfaceStop(&'a str, InterfaceInactiveReason),
    InterfaceDisChange(&'a str, LevelNumber, &'a Option<DisCandidate>),
    // Adjacencies
    AdjacencyCreate(&'a Adjacency),
    AdjacencyDelete(&'a Adjacency),
    AdjacencyStateChange(&'a Adjacency, AdjacencyState, AdjacencyEvent),
    AdjacencyBfdReg(&'a Adjacency, &'a IpAddr),
    AdjacencyBfdUnreg(&'a Adjacency, &'a IpAddr),
    // Network
    PduRx(&'a Interface, &'a MacAddr, &'a Pdu),
    PduTx(&'a str, MulticastAddr, &'a Pdu),
    // Flooding
    LspDiscard(LevelNumber, &'a Lsp),
    LspTooLarge(&'a Interface, LevelNumber, &'a Lsp),
    // LSDB maintenance
    LspInstall(LevelNumber, &'a Lsp),
    LspOriginate(LevelNumber, &'a Lsp),
    LspPurge(LevelNumber, &'a Lsp, LspPurgeReason),
    LspDelete(LevelNumber, &'a Lsp),
    LspRefresh(LevelNumber, &'a Lsp),
    // SPF
    SpfDelayFsmEvent(spf::fsm::State, spf::fsm::Event),
    SpfDelayFsmTransition(spf::fsm::State, spf::fsm::State),
    SpfStart(SpfType),
    SpfFinish(Duration),
    SpfMaxPathMetric(&'a Vertex, &'a VertexEdge, u32),
    SpfMissingProtocolsTlv(&'a Vertex),
    SpfUnsupportedProtocol(&'a Vertex, AddressFamily),
    // Internal bus
    IbusRx(&'a IbusMsg),
}

// Reason why an IS-IS instance is inactive.
#[derive(Debug)]
pub enum InstanceInactiveReason {
    AdminDown,
    Resetting,
}

// Reason why IS-IS is inactive on an interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceInactiveReason {
    InstanceDown,
    AdminDown,
    OperationalDown,
    MissingIfindex,
    MissingMtu,
    MissingMacAddr,
    BroadcastUnsupported,
    Resetting,
}

// Reason why an LSP is being purged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LspPurgeReason {
    Expired,
    Removed,
    Confusion,
}

// ===== impl Debug =====

impl Debug<'_> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate
            | Debug::InstanceDelete
            | Debug::InstanceStart => {
                // Parent span(s): isis-instance
                debug!("{}", self);
            }
            Debug::InstanceStop(reason) => {
                // Parent span(s): isis-instance
                debug!(%reason, "{}", self);
            }
            Debug::InterfaceCreate(name)
            | Debug::InterfaceDelete(name)
            | Debug::InterfaceStart(name) => {
                // Parent span(s): isis-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!("{}", self);
                })
            }
            Debug::InterfaceStop(name, reason) => {
                // Parent span(s): isis-instance
                debug_span!("interface", %name).in_scope(|| {
                    debug!(%reason, "{}", self);
                })
            }
            Debug::InterfaceDisChange(name, level, dis) => {
                // Parent span(s): isis-instance
                debug_span!("interface", %name).in_scope(|| {
                    if let Some(dis) = dis {
                        debug!(%level, system_id = %dis.system_id.to_yang(), "{}", self);
                    } else {
                        debug!(%level, system_id = "none", "{}", self);
                    }
                })
            }
            Debug::AdjacencyCreate(adj) | Debug::AdjacencyDelete(adj) => {
                // Parent span(s): isis-instance
                debug_span!("adjacency", system_id = %adj.system_id.to_yang())
                    .in_scope(|| {
                        debug!("{}", self);
                    })
            }
            Debug::AdjacencyStateChange(adj, new_state, event) => {
                // Parent span(s): isis-instance
                debug_span!("adjacency", system_id = %adj.system_id.to_yang(), new_state = %new_state.to_yang(), event = %event.to_yang())
                    .in_scope(|| {
                        debug!("{}", self);
                    })
            }
            Debug::AdjacencyBfdReg(adj, addr)
            | Debug::AdjacencyBfdUnreg(adj, addr) => {
                // Parent span(s): isis-instance
                debug_span!("adjacency", system_id = %adj.system_id.to_yang(), %addr)
                    .in_scope(|| {
                        debug!("{}", self);
                    })
            }
            Debug::PduRx(iface, source, pdu) => {
                // Parent span(s): isis-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("input")
                        .in_scope(|| {
                            let data = serde_json::to_string(&pdu).unwrap();
                            if iface.config.interface_type == InterfaceType::Broadcast {
                                debug!(interface = %iface.name, %source, %data, "{}", self);
                            } else {
                                debug!(interface = %iface.name, %data, "{}", self);
                            }
                        })
                })
            }
            Debug::PduTx(ifname, addr, pdu) => {
                // Parent span(s): isis-instance:network:output
                let data = serde_json::to_string(&pdu).unwrap();
                debug!(interface = ifname, ?addr, %data, "{}", self);
            }
            Debug::LspDiscard(level, lsp)
            | Debug::LspInstall(level, lsp)
            | Debug::LspOriginate(level, lsp)
            | Debug::LspDelete(level, lsp)
            | Debug::LspRefresh(level, lsp) => {
                // Parent span(s): isis-instance
                debug!(%level, lsp_id = %lsp.lsp_id.to_yang(), seqno = %lsp.seqno, len = %lsp.raw.len(), "{}", self);
            }
            Debug::LspTooLarge(iface, level, lsp) => {
                // Parent span(s): isis-instance
                debug!(interface = %iface.name, %level, lsp_id = %lsp.lsp_id.to_yang(), len = %lsp.raw.len(), "{}", self);
            }
            Debug::LspPurge(level, lsp, reason) => {
                // Parent span(s): isis-instance
                debug!(%level, lsp_id = %lsp.lsp_id.to_yang(), seqno = %lsp.seqno, len = %lsp.raw.len(), %reason, "{}", self);
            }
            Debug::SpfDelayFsmEvent(state, event) => {
                // Parent span(s): isis-instance:spf
                debug!(state = %state.to_yang(), ?event, "{}", self);
            }
            Debug::SpfDelayFsmTransition(old_state, new_state) => {
                // Parent span(s): isis-instance:spf
                debug!(old_state = %old_state.to_yang(), new_state = %new_state.to_yang(), "{}", self);
            }
            Debug::SpfStart(spf_type) => {
                // Parent span(s): isis-instance:spf
                debug!(spf_type = %spf_type.to_yang(), "{}", self);
            }
            Debug::SpfFinish(run_duration) => {
                // Parent span(s): isis-instance:spf
                debug!(run_duration_ns = %run_duration.as_nanos(), "{}", self);
            }
            Debug::SpfMaxPathMetric(vertex, link, distance) => {
                // Parent span(s): isis-instance:spf
                debug!(vertex = %vertex.id.lan_id.to_yang(), link = %link.id.lan_id.to_yang(), %distance, "{}", self);
            }
            Debug::SpfMissingProtocolsTlv(vertex) => {
                // Parent span(s): isis-instance:spf
                debug!(vertex = %vertex.id.lan_id.to_yang(), "{}", self);
            }
            Debug::SpfUnsupportedProtocol(vertex, protocol) => {
                // Parent span(s): isis-instance:spf
                debug!(vertex = %vertex.id.lan_id.to_yang(), %protocol, "{}", self);
            }
            Debug::IbusRx(msg) => {
                // Parent span(s): isis-instance
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
            Debug::InterfaceDisChange(..) => {
                write!(f, "interface DIS change")
            }
            Debug::AdjacencyCreate(..) => {
                write!(f, "adjacency created")
            }
            Debug::AdjacencyDelete(..) => {
                write!(f, "adjacency deleted")
            }
            Debug::AdjacencyStateChange(..) => {
                write!(f, "adjacency state change")
            }
            Debug::AdjacencyBfdReg(..) => {
                write!(f, "BFD peer registered")
            }
            Debug::AdjacencyBfdUnreg(..) => {
                write!(f, "BFD peer unregistered")
            }
            Debug::PduRx(..) | Debug::PduTx(..) => {
                write!(f, "PDU")
            }
            Debug::LspDiscard(..) => {
                write!(f, "discarding LSP")
            }
            Debug::LspTooLarge(..) => {
                write!(f, "LSP larger than interface MTU")
            }
            Debug::LspInstall(..) => {
                write!(f, "installing LSP")
            }
            Debug::LspOriginate(..) => {
                write!(f, "originating LSP")
            }
            Debug::LspPurge(..) => {
                write!(f, "purging LSP")
            }
            Debug::LspDelete(..) => {
                write!(f, "deleting LSP")
            }
            Debug::LspRefresh(..) => {
                write!(f, "refreshing LSP")
            }
            Debug::SpfDelayFsmEvent(..) => {
                write!(f, "delay FSM event")
            }
            Debug::SpfDelayFsmTransition(..) => {
                write!(f, "delay FSM state transition")
            }
            Debug::SpfStart(..) => {
                write!(f, "starting SPF calculation")
            }
            Debug::SpfFinish(..) => {
                write!(f, "finished SPF calculation")
            }
            Debug::SpfMaxPathMetric(..) => {
                write!(f, "maximum path metric exceeded")
            }
            Debug::SpfMissingProtocolsTlv(..) => {
                write!(f, "missing protocols TLV")
            }
            Debug::SpfUnsupportedProtocol(..) => {
                write!(f, "unsupported protocol")
            }
            Debug::IbusRx(..) => {
                write!(f, "message")
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
            InstanceInactiveReason::Resetting => {
                write!(f, "resetting")
            }
        }
    }
}

// ===== impl InterfaceInactiveReason =====

impl std::fmt::Display for InterfaceInactiveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceInactiveReason::InstanceDown => {
                write!(f, "IS-IS instance down")
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
            InterfaceInactiveReason::MissingMtu => {
                write!(f, "missing MTU")
            }
            InterfaceInactiveReason::MissingMacAddr => {
                write!(f, "missing MAC address")
            }
            InterfaceInactiveReason::BroadcastUnsupported => {
                write!(f, "broadcast mode not supported by interface")
            }
            InterfaceInactiveReason::Resetting => {
                write!(f, "resetting")
            }
        }
    }
}

// ===== impl LspPurgeReason =====

impl std::fmt::Display for LspPurgeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LspPurgeReason::Expired => {
                write!(f, "LSP has expired")
            }
            LspPurgeReason::Removed => {
                write!(f, "LSP no longer exists")
            }
            LspPurgeReason::Confusion => {
                write!(f, "LSP confusion")
            }
        }
    }
}
