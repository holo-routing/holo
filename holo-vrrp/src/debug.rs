//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::IpAddr;

use tracing::{debug, debug_span};

use crate::packet::VrrpHdr;

// VRRP debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    InstanceCreate,
    InstanceDelete,
    // Network
    PacketRx(&'a IpAddr, &'a VrrpHdr),
    PacketTx(&'a IpAddr, &'a VrrpHdr),
}

// ===== impl Debug =====

impl Debug<'_> {
    // Log debug message using the tracing API.
    #[expect(unused)]
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

impl std::fmt::Display for Debug<'_> {
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
