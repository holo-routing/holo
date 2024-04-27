//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{debug, debug_span, trace, trace_span};

use crate::configuration::CommitPhase;
use crate::{api, CallbackOp};

#[derive(Debug)]
pub enum Debug<'a> {
    RequestRx(&'a api::daemon::Request),
    ValidationCallback(&'a str),
    ConfigurationCallback(CommitPhase, CallbackOp, &'a str),
    RpcCallback(&'a str),
    GetIterateCallback(&'a str),
    GetElementCallback(&'a str, &'a Option<String>),
}

// ===== impl Debug =====

impl<'a> Debug<'a> {
    pub fn log(&self) {
        match self {
            Debug::RequestRx(message) => {
                debug_span!("northbound").in_scope(|| {
                    debug!("{}", self);
                    trace!(?message);
                });
            }
            Debug::ValidationCallback(path) => {
                debug_span!("northbound").in_scope(|| {
                    debug!(%path, "{}", self);
                });
            }
            Debug::ConfigurationCallback(phase, operation, path) => {
                debug_span!("northbound").in_scope(|| {
                    debug!(
                        ?phase, ?operation, %path,
                        "{}", self
                    )
                });
            }
            Debug::RpcCallback(path) => {
                debug_span!("northbound")
                    .in_scope(|| debug!(%path, "{}", self));
            }
            Debug::GetIterateCallback(path) => {
                trace_span!("northbound")
                    .in_scope(|| trace!(%path, "{}", self));
            }
            Debug::GetElementCallback(path, value) => {
                trace_span!("northbound")
                    .in_scope(|| trace!(%path, ?value, "{}", self));
            }
        }
    }
}

impl<'a> std::fmt::Display for Debug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::RequestRx(..) => {
                write!(f, "received request")
            }
            Debug::ValidationCallback(..) => {
                write!(f, "validation callback")
            }
            Debug::ConfigurationCallback(..) => {
                write!(f, "configuration callback")
            }
            Debug::RpcCallback(..) => {
                write!(f, "rpc callback")
            }
            Debug::GetIterateCallback(..) => {
                write!(f, "get iterate callback")
            }
            Debug::GetElementCallback(..) => {
                write!(f, "get element callback")
            }
        }
    }
}
