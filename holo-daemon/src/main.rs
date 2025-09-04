//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod config;
mod northbound;

use std::path::Path;

use capctl::caps;
use clap::{App, Arg};
use config::{Config, LoggingFileRotation, LoggingFmtStyle};
use nix::unistd::{Uid, User};
use northbound::Northbound;
use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

fn init_tracing(config: &config::Logging) {
    // Enable logging to journald.
    let journald = config.journald.enabled.then(|| {
        tracing_journald::layer().expect("couldn't connect to journald")
    });

    // Enable logging to a file.
    let file = config.file.enabled.then(|| {
        let file_appender = match config.file.rotation {
            LoggingFileRotation::Never => {
                rolling::never(&config.file.dir, &config.file.name)
            }
            LoggingFileRotation::Hourly => {
                rolling::hourly(&config.file.dir, &config.file.name)
            }
            LoggingFileRotation::Daily => {
                rolling::daily(&config.file.dir, &config.file.name)
            }
        };

        let log_level_filter = LevelFilter::from_level(tracing::Level::TRACE);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(file_appender)
            .with_target(false)
            .with_thread_ids(config.file.fmt.show_thread_id)
            .with_file(config.file.fmt.show_source)
            .with_line_number(config.file.fmt.show_source)
            .with_ansi(config.file.fmt.colors);
        let layer = match config.file.fmt.style {
            LoggingFmtStyle::Compact => layer.compact().boxed(),
            LoggingFmtStyle::Full => layer.boxed(),
            LoggingFmtStyle::Json => layer.json().boxed(),
            LoggingFmtStyle::Pretty => layer.pretty().boxed(),
        };
        layer.with_filter(log_level_filter)
    });

    // Enable logging to stdout.
    let stdout = config.stdout.enabled.then(|| {
        let log_level_filter = LevelFilter::from_level(tracing::Level::TRACE);
        let layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(config.stdout.fmt.show_thread_id)
            .with_file(config.stdout.fmt.show_source)
            .with_line_number(config.stdout.fmt.show_source)
            .with_ansi(config.stdout.fmt.colors);
        let layer = match config.stdout.fmt.style {
            LoggingFmtStyle::Compact => layer.compact().boxed(),
            LoggingFmtStyle::Full => layer.boxed(),
            LoggingFmtStyle::Json => layer.json().boxed(),
            LoggingFmtStyle::Pretty => layer.pretty().boxed(),
        };
        layer.with_filter(log_level_filter)
    });

    // Configure the tracing fmt layer.
    #[cfg(feature = "tokio_console")]
    {
        // Enable tokio-console instrumentation.
        let console = console_subscriber::spawn();
        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive("holo=debug".parse().unwrap())
            .from_env_lossy();
        // Enable targets needed by the console.
        let env_filter = env_filter
            .add_directive("tokio=trace".parse().unwrap())
            .add_directive("runtime=trace".parse().unwrap());
        tracing_subscriber::registry()
            .with(env_filter)
            .with(journald)
            .with(file)
            .with(stdout)
            .with(console)
            .init();
    }
    #[cfg(not(feature = "tokio_console"))]
    {
        let env_filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive("holo=debug".parse().unwrap())
            .from_env_lossy();
        tracing_subscriber::registry()
            .with(env_filter)
            .with(journald)
            .with(file)
            .with(stdout)
            .init();
    }
}

fn init_db<P: AsRef<Path>>(
    path: P,
) -> Result<PickleDb, pickledb::error::Error> {
    let dump_policy = PickleDbDumpPolicy::AutoDump;
    let serialization_method = SerializationMethod::Bin;
    match path.as_ref().exists() {
        true => PickleDb::load(path, dump_policy, serialization_method),
        false => Ok(PickleDb::new(path, dump_policy, serialization_method)),
    }
}

fn privdrop(user: &str) -> nix::Result<()> {
    // Preserve set of permitted capabilities upon privdrop.
    capctl::prctl::set_securebits(capctl::prctl::Secbits::KEEP_CAPS).unwrap();

    // Drop to unprivileged user and group.
    if let Some(user) = User::from_name(user)? {
        nix::unistd::setgroups(&[user.gid])?;
        nix::unistd::setresgid(user.gid, user.gid, user.gid)?;
        nix::unistd::setresuid(user.uid, user.uid, user.uid)?;
    } else {
        error!(name = %user, "failed to find user");
        std::process::exit(1);
    }

    // Set permitted capabilities.
    let mut caps = caps::CapState::empty();
    for cap in [
        caps::Cap::NET_ADMIN,
        caps::Cap::NET_BIND_SERVICE,
        caps::Cap::NET_RAW,
    ] {
        caps.permitted.add(cap);
    }
    if let Err(error) = caps.set_current() {
        error!(%error, "failed to set permitted capabilities");
    }

    Ok(())
}

fn signal_listener() -> mpsc::Receiver<()> {
    let (signal_tx, signal_rx) = mpsc::channel(1);

    tokio::task::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigterm = signal(SignalKind::terminate()).unwrap();

        tokio::select! {
            _ = sigint.recv() => {
                info!("received SIGINT");
                let _ = signal_tx.send(()).await;
            },
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                let _ = signal_tx.send(()).await;
            }
        }
    });

    signal_rx
}

fn build_version() -> String {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    match rustc_tools_util::get_version_info!().commit_hash {
        Some(hash) => format!("{VERSION} ({hash})"),
        None => VERSION.to_owned(),
    }
}

// ===== main =====

fn main() {
    // Parse command-line parameters.
    let matches = App::new("Holo routing daemon")
        .version(build_version().as_str())
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("file")
                .help("Specify an alternative configuration file."),
        )
        .get_matches();

    // Read configuration file.
    let config_file = matches.value_of("config");
    let config = Config::load(config_file);

    // Check for root privileges.
    if !Uid::effective().is_root() {
        eprintln!("need privileged user");
        std::process::exit(1);
    }

    // Initialize tracing.
    init_tracing(&config.logging);

    // Initialize non-volatile storage.
    let db = init_db(&config.database_path)
        .expect("failed to initialize non-volatile storage");

    // Drop privileges.
    if let Err(error) = privdrop(&config.user) {
        error!(%error, "failed to drop root privileges");
        std::process::exit(1);
    }

    // We're ready to go!
    info!("starting up");

    // Main loop.
    let main = || async {
        // Spawn signal listener.
        let signal_rx = signal_listener();

        // Serve northbound clients.
        let nb = Northbound::init(&config, db).await;
        nb.run(signal_rx).await;
    };
    #[cfg(not(feature = "io_uring"))]
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create async runtime")
            .block_on(async {
                main().await;
            });
    }
    #[cfg(feature = "io_uring")]
    {
        tokio_uring::start(async {
            main().await;
        });
    }

    info!("exiting");
}
