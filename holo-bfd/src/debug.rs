//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::bfd::{ClientId, SessionKey, State};
use tracing::{debug, debug_span};

// BFD debug messages.
#[derive(Debug)]
pub enum Debug<'a> {
    SessionCreate(&'a SessionKey),
    SessionDelete(&'a SessionKey),
    SessionClientReg(&'a SessionKey, &'a ClientId),
    SessionClientUnreg(&'a SessionKey, &'a ClientId),
    FsmTransition(&'a SessionKey, State, State),
    DetectionTimeExpiry(&'a SessionKey),
}

// ===== impl Debug =====

impl Debug<'_> {
    // Log debug message using the tracing API.
    pub(crate) fn log(&self) {
        match self {
            Debug::SessionCreate(sess_key) | Debug::SessionDelete(sess_key) => {
                debug_span!("session", key = ?sess_key).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::SessionClientReg(sess_key, client_id)
            | Debug::SessionClientUnreg(sess_key, client_id) => {
                debug_span!("session", key = ?sess_key, client = %client_id.protocol).in_scope(|| {
                    debug!("{}", self);
                });
            }
            Debug::FsmTransition(sess_key, old_state, new_state) => {
                debug_span!("session", key = ?sess_key).in_scope(|| {
                    debug!(?old_state, ?new_state, "{}", self);
                });
            }
            Debug::DetectionTimeExpiry(sess_key) => {
                debug_span!("session", key = ?sess_key).in_scope(|| {
                    debug!("{}", self);
                });
            }
        }
    }
}

impl std::fmt::Display for Debug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::SessionCreate(..) => {
                write!(f, "session created")
            }
            Debug::SessionDelete(..) => {
                write!(f, "session deleted")
            }
            Debug::SessionClientReg(..) => {
                write!(f, "client registered peer")
            }
            Debug::SessionClientUnreg(..) => {
                write!(f, "client unregistered peer")
            }
            Debug::FsmTransition(..) => {
                write!(f, "state transition")
            }
            Debug::DetectionTimeExpiry(..) => {
                write!(f, "detection timer expired")
            }
        }
    }
}
