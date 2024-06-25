//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use tracing::{debug, debug_span};

use crate::packet::VrrpPacket;

// VRRP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    InstanceCreate,
    InstanceDelete,
    // Network
    PacketRx(&'a IpAddr, &'a VrrpPacket),
    PacketTx(&'a IpAddr, &'a VrrpPacket),
}

// ===== impl Debug =====

impl<'a> Debug<'a> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::InstanceCreate | Debug::InstanceDelete => {
                // Parent span(s): vrrp-instance
                debug!("{}", self);
            }
            Debug::PacketRx(src, packet) => {
                // Parent span(s): vrrp-instance
                debug_span!("network").in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&packet).unwrap();
                        debug!(%src, %data, "{}", self);
                    })
                })
            }
            Debug::PacketTx(addr, packet) => {
                // Parent span(s): vrrp-instance:network:output
                let data = serde_json::to_string(&packet).unwrap();
                debug!(%addr, %data, "{}", self);
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
            Debug::PacketRx(..) | Debug::PacketTx(..) => {
                write!(f, "packet")
            }
        }
    }
}
