//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ibus::IbusMsg;
use tracing::{debug, debug_span};

#[derive(Debug)]
pub enum Debug<'a> {
    // Instances
    InstanceCreate,
    InstanceDelete,
    // Network
    PacketRx,
    PacketTx,
    // Internal bus
    IbusRx(&'a IbusMsg),
}

impl Debug<'_> {
    pub(crate) fn log(&self) {
        match self {
            Self::InstanceCreate | Self::InstanceDelete => {
                // Parent span(s): mld-instance
                debug!("{}", self);
            }
            Self::IbusRx(msg) => {
                // Parent span(s): mld-instance
                debug_span!("internal-bus").in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(%data, "{}", self);
                    })
                })
            }
            _ => {}
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
            Debug::PacketRx | Debug::PacketTx => {
                write!(f, "packet")
            }
            Debug::IbusRx(..) => {
                write!(f, "message")
            }
        }
    }
}
