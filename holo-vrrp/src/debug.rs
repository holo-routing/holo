//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_utils::ibus::IbusMsg;
use tracing::{debug, debug_span};

use crate::instance::fsm;
use crate::packet::VrrpHdr;

// VRRP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    // Instances
    InstanceCreate(u8),
    InstanceDelete(u8),
    InstanceStateChange(u8, fsm::Event, fsm::State, fsm::State),
    // Network
    PacketRx(&'a IpAddr, &'a VrrpHdr),
    PacketTx(&'a VrrpHdr),
    ArpTx(u8, &'a Ipv4Addr),
    NeighborAdvertisementTx(u8, &'a Ipv6Addr),
    // Internal bus
    IbusRx(&'a IbusMsg),
}

// ===== impl Debug =====

impl Debug<'_> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate(vrid) | Debug::InstanceDelete(vrid) => {
                // Parent span(s): vrrp
                debug!(%vrid, "{}", self);
            }
            Debug::InstanceStateChange(vrid, event, old_state, new_state) => {
                // Parent span(s): vrrp
                debug!(%vrid, ?event, ?old_state, ?new_state, "{}", self);
            }
            Debug::PacketRx(src, packet) => {
                // Parent span(s): vrrp
                debug_span!("network").in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&packet).unwrap();
                        debug!(%src, %data, "{}", self);
                    })
                })
            }
            Debug::PacketTx(packet) => {
                // Parent span(s): vrrp:network:output
                let data = serde_json::to_string(&packet).unwrap();
                debug!(%data, "{}", self);
            }
            Debug::ArpTx(vrid, addr) => {
                // Parent span(s): vrrp:network:output
                debug!(%vrid, %addr, "{}", self);
            }
            Debug::NeighborAdvertisementTx(vrid, addr) => {
                // Parent span(s): vrrp:network:output
                debug!(%vrid, %addr, "{}", self);
            }
            Debug::IbusRx(msg) => {
                // Parent span(s): vrrp
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
            Debug::InstanceCreate(..) => {
                write!(f, "instance created")
            }
            Debug::InstanceDelete(..) => {
                write!(f, "instance deleted")
            }
            Debug::InstanceStateChange(..) => {
                write!(f, "instance state change")
            }
            Debug::PacketRx(..) | Debug::PacketTx(..) => {
                write!(f, "packet")
            }
            Debug::ArpTx(..) => {
                write!(f, "gratuitous ARP")
            }
            Debug::NeighborAdvertisementTx(..) => {
                write!(f, "neighbor advertisement")
            }
            Debug::IbusRx(..) => {
                write!(f, "message")
            }
        }
    }
}
