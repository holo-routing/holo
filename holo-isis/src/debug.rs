//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_yang::ToYang;
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span};

use crate::adjacency::{Adjacency, AdjacencyEvent, AdjacencyState};
use crate::interface::{DisCandidate, Interface};
use crate::network::MulticastAddr;
use crate::packet::pdu::{Lsp, Pdu};
use crate::packet::LevelNumber;

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
    // Network
    PduRx(&'a Interface, &'a [u8; 6], &'a Pdu),
    PduTx(u32, MulticastAddr, &'a Pdu),
    // Flooding
    LspDiscard(LevelNumber, &'a Lsp),
    // LSDB maintenance
    LspInstall(LevelNumber, &'a Lsp),
    LspOriginate(LevelNumber, &'a Lsp),
    LspPurge(LevelNumber, &'a Lsp, LspPurgeReason),
    LspDelete(LevelNumber, &'a Lsp),
    LspRefresh(LevelNumber, &'a Lsp),
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
                        debug!(?level, lan_id = ?dis.lan_id, "{}", self);
                    } else {
                        debug!(?level, lan_id = "none", "{}", self);
                    }
                })
            }
            Debug::AdjacencyCreate(adj) | Debug::AdjacencyDelete(adj) => {
                // Parent span(s): isis-instance
                debug_span!("adjacency", system_id = ?adj.system_id).in_scope(
                    || {
                        debug!("{}", self);
                    },
                )
            }
            Debug::AdjacencyStateChange(adj, new_state, event) => {
                // Parent span(s): isis-instance
                debug_span!("adjacency", system_id = ?adj.system_id, ?new_state, ?event)
                    .in_scope(|| {
                        debug!("{}", self);
                    })
            }
            Debug::PduRx(iface, src, pdu) => {
                // Parent span(s): isis-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("input")
                        .in_scope(|| {
                            let data = serde_json::to_string(&pdu).unwrap();
                            debug!(interface = %iface.name, ?src, %data, "{}", self);
                        })
                })
            }
            Debug::PduTx(ifindex, addr, pdu) => {
                // Parent span(s): isis-instance:network:output
                let data = serde_json::to_string(&pdu).unwrap();
                debug!(%ifindex, ?addr, %data, "{}", self);
            }
            Debug::LspDiscard(level, lsp)
            | Debug::LspInstall(level, lsp)
            | Debug::LspOriginate(level, lsp)
            | Debug::LspDelete(level, lsp)
            | Debug::LspRefresh(level, lsp) => {
                // Parent span(s): isis-instance
                debug!(?level, lsp_id = %lsp.lsp_id.to_yang(), seqno = %lsp.seqno, len = %lsp.raw.len(), "{}", self);
            }
            Debug::LspPurge(level, lsp, reason) => {
                // Parent span(s): isis-instance
                debug!(?level, lsp_id = %lsp.lsp_id.to_yang(), seqno = %lsp.seqno, len = %lsp.raw.len(), ?reason, "{}", self);
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
            Debug::PduRx(..) | Debug::PduTx(..) => {
                write!(f, "PDU")
            }
            Debug::LspDiscard(..) => {
                write!(f, "discarding LSP")
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