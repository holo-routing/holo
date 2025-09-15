//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(feature = "testing", allow(dead_code, unused_variables))]

use std::io::Write;

use holo_utils::protocol::Protocol;
use serde::Deserialize;
use tracing::warn;

use crate::{InstanceMsg, ProtocolInstance};

pub struct EventRecorder(std::fs::File);

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub dir: String,
}

// ===== impl EventRecorder =====

impl EventRecorder {
    // Creates new event recorder.
    pub(crate) fn new(
        protocol: Protocol,
        instance: &str,
        config: Config,
    ) -> Option<EventRecorder> {
        // Get full file path.
        let path = format!(
            "{}/holo-events-{}-{}.jsonl",
            config.dir, protocol, instance
        );

        // Create event recorder.
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
        {
            Ok(file) => Some(EventRecorder(file)),
            Err(error) => {
                warn!(%error, "couldn't write to file");
                None
            }
        }
    }

    // Records the protocol instance event.
    pub(crate) fn record<P>(&mut self, msg: &InstanceMsg<P>)
    where
        P: ProtocolInstance,
    {
        let event = serde_json::to_string(msg).unwrap();
        if let Err(error) = writeln!(self.0, "{event}") {
            warn!(%error, "couldn't write to file");
        }
    }
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Config {
        Config {
            enabled: false,
            dir: "/var/opt/holo".to_owned(),
        }
    }
}
