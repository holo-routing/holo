//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::derivable_impls)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub user: String,
    pub group: String,
    pub state_dir: PathBuf,
    pub logging: Logging,
    pub event_recorder: EventRecorder,
    pub rollback_log: RollbackLog,
    pub northbound: Northbound,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logging {
    pub journald: LoggingJournald,
    pub file: LoggingFile,
    pub stdout: LoggingStdout,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingJournald {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingFile {
    pub enabled: bool,
    pub dir: String,
    pub name: String,
    pub rotation: LoggingFileRotation,
    #[serde(flatten)]
    pub fmt: LoggingFmt,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingStdout {
    pub enabled: bool,
    #[serde(flatten)]
    pub fmt: LoggingFmt,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingFmt {
    pub style: LoggingFmtStyle,
    pub colors: bool,
    pub show_thread_id: bool,
    pub show_source: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFileRotation {
    #[default]
    Never,
    Hourly,
    Daily,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFmtStyle {
    Compact,
    Full,
    Json,
    Pretty,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventRecorder {
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RollbackLog {
    pub enabled: bool,
    pub max_entries: u32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Northbound {
    pub grpc: Grpc,
    pub gnmi: Gnmi,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    pub enabled: bool,
    pub address: Vec<SocketAddr>,
    pub insecure: bool,
    pub tls: Tls,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gnmi {
    pub enabled: bool,
    pub address: Vec<SocketAddr>,
    pub insecure: bool,
    pub tls: Tls,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub certificate: String,
    pub key: String,
}

// ===== impl Config =====

impl Config {
    const DFLT_FILEPATH: &'static str = "/etc/holod.toml";

    // Files kept in the state directory.
    pub(crate) const DATABASE_NAME: &'static str = "holo.db";
    pub(crate) const GRPC_SOCKET_NAME: &'static str = "holod.sock";
    pub(crate) const INSTANCE_LOCK_NAME: &'static str = "holod.lock";

    pub(crate) fn load(config_file: Option<&str>) -> Config {
        let config_file = config_file.unwrap_or(Config::DFLT_FILEPATH);

        let config = match std::fs::read_to_string(config_file) {
            Ok(config_str) => {
                toml::from_str(&config_str).unwrap_or_else(|error| {
                    // Prefix the error with its line in the file, when known.
                    let line = error
                        .span()
                        .and_then(|span| config_str.get(..span.start))
                        .map(|before| {
                            format!(":{}", before.matches('\n').count() + 1)
                        })
                        .unwrap_or_default();
                    eprintln!("{config_file}{line}: {}", error.message());
                    std::process::exit(1);
                })
            }
            Err(err) => {
                eprintln!("Failed to load configuration file: {err}");
                eprintln!("Falling back to default configuration...");
                Config::default()
            }
        };

        if !config.state_dir.is_absolute() {
            eprintln!("state_dir must be an absolute path");
            std::process::exit(1);
        }

        config
    }

    // Returns the path of the given file in the state directory.
    pub(crate) fn state_path(&self, name: &str) -> PathBuf {
        self.state_dir.join(name)
    }
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Config {
        Config {
            user: "holo".to_owned(),
            group: "holoadm".to_owned(),
            state_dir: PathBuf::from("/var/opt/holo"),
            logging: Default::default(),
            event_recorder: Default::default(),
            rollback_log: Default::default(),
            northbound: Default::default(),
        }
    }
}

// ===== impl LoggingJournald =====

impl Default for LoggingJournald {
    fn default() -> LoggingJournald {
        LoggingJournald { enabled: false }
    }
}

// ===== impl LoggingFile =====

impl Default for LoggingFile {
    fn default() -> LoggingFile {
        LoggingFile {
            enabled: true,
            dir: "/var/log/holo".to_owned(),
            name: "holod.log".to_owned(),
            rotation: Default::default(),
            fmt: Default::default(),
        }
    }
}

// ===== impl LoggingStdout =====

impl Default for LoggingStdout {
    fn default() -> LoggingStdout {
        LoggingStdout {
            enabled: false,
            fmt: Default::default(),
        }
    }
}

// ===== impl LoggingFmt =====

impl Default for LoggingFmt {
    fn default() -> LoggingFmt {
        LoggingFmt {
            style: LoggingFmtStyle::Full,
            colors: false,
            show_thread_id: false,
            show_source: false,
        }
    }
}

// ===== impl EventRecorder =====

impl Default for EventRecorder {
    fn default() -> EventRecorder {
        EventRecorder { enabled: false }
    }
}

// ===== impl RollbackLog =====

impl Default for RollbackLog {
    fn default() -> RollbackLog {
        RollbackLog {
            enabled: true,
            max_entries: 100,
        }
    }
}

// ===== impl Grpc =====

impl Default for Grpc {
    fn default() -> Grpc {
        Grpc {
            enabled: true,
            address: vec![],
            insecure: false,
            tls: Default::default(),
        }
    }
}

// ===== impl Gnmi =====

impl Default for Gnmi {
    fn default() -> Gnmi {
        Gnmi {
            enabled: false,
            address: vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9339))],
            insecure: false,
            tls: Default::default(),
        }
    }
}

// ===== impl Tls =====

impl Default for Tls {
    fn default() -> Tls {
        Tls {
            certificate: "/etc/holo/holo.pem".to_owned(),
            key: "/etc/holo/holo.key".to_owned(),
        }
    }
}

// ===== unit tests =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_config() {
        let config: Config =
            toml::from_str(include_str!("../holod.toml")).unwrap();
        assert!(config.rollback_log.enabled);
        assert_eq!(config.rollback_log.max_entries, 100);
    }

    #[test]
    fn rollback_log_disabled() {
        let config: Config =
            toml::from_str("rollback_log = { enabled = false }").unwrap();
        assert!(!config.rollback_log.enabled);
        assert_eq!(config.rollback_log.max_entries, 100);
    }
}
