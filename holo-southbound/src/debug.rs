//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{debug, debug_span};

use crate::zclient::messages::{ZapiRxMsg, ZapiTxMsg};

// Debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    MsgTx(&'a ZapiTxMsg),
    MsgRx(&'a ZapiRxMsg),
}

// ===== impl Debug =====

impl<'a> Debug<'a> {
    // Log debug message using the tracing API.
    pub fn log(&self) {
        match self {
            Debug::MsgTx(msg) => {
                debug_span!("southbound").in_scope(|| {
                    debug_span!("output").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(r#type = %msg, %data, "{}", self);
                    })
                });
            }
            Debug::MsgRx(msg) => {
                debug_span!("southbound").in_scope(|| {
                    debug_span!("input").in_scope(|| {
                        let data = serde_json::to_string(&msg).unwrap();
                        debug!(r#type = %msg, %data, "{}", self);
                    })
                });
            }
        }
    }
}

impl<'a> std::fmt::Display for Debug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::MsgTx(..) | Debug::MsgRx(..) => {
                write!(f, "message")
            }
        }
    }
}
