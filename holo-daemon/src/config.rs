//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::derivable_impls)]

use holo_protocol::event_recorder;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub user: String,
    pub group: String,
    pub database_path: String,
    pub logging: Logging,
    pub event_recorder: event_recorder::Config,
    pub plugins: Plugins,
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

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Plugins {
    pub grpc: Grpc,
    pub gnmi: Gnmi,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    pub enabled: bool,
    pub address: String,
    pub tls: Tls,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gnmi {
    pub enabled: bool,
    pub address: String,
    pub tls: Tls,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub enabled: bool,
    pub certificate: String,
    pub key: String,
}

// ===== impl Config =====

impl Config {
    const DFLT_FILEPATH: &'static str = "/etc/holod.toml";

    pub(crate) fn load(config_file: Option<&str>) -> Config {
        let config_file = config_file.unwrap_or(Config::DFLT_FILEPATH);

        match std::fs::read_to_string(config_file) {
            Ok(config_str) => toml::from_str(&config_str)
                .expect("Failed to parse configuration file"),
            Err(err) => {
                eprintln!("Failed to load configuration file: {err}");
                eprintln!("Falling back to default configuration...");
                Config::default()
            }
        }
    }
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Config {
        Config {
            user: "holo".to_owned(),
            group: "holo".to_owned(),
            database_path: "/var/opt/holo/holo.db".to_owned(),
            logging: Default::default(),
            event_recorder: Default::default(),
            plugins: Default::default(),
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
            dir: "/var/log".to_owned(),
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

// ===== impl Grpc =====

impl Default for Grpc {
    fn default() -> Grpc {
        Grpc {
            enabled: true,
            address: "[::]:50051".to_owned(),
            tls: Default::default(),
        }
    }
}

// ===== impl Gnmi =====

impl Default for Gnmi {
    fn default() -> Gnmi {
        Gnmi {
            enabled: true,
            address: "[::]:10161".to_owned(),
            tls: Default::default(),
        }
    }
}

// ===== impl Tls =====

impl Default for Tls {
    fn default() -> Tls {
        Tls {
            enabled: false,
            certificate: "/etc/ssl/private/holo.pem".to_owned(),
            key: "/etc/ssl/certs/holo.key".to_owned(),
        }
    }
}
