//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

#![warn(rust_2018_idioms)]

mod config;
mod northbound;

use capctl::caps;
use clap::{App, Arg};
use config::{Config, LoggingFileRotation, LoggingFmtStyle};
use nix::unistd::{Uid, User};
use northbound::Northbound;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

fn init_tracing(config: &config::Logging, tokio_console: bool) {
    // Enable logging to journald.
    let journald = config.journald.enabled.then(|| {
        tracing_journald::layer().expect("couldn't connect to journald")
    });

    // Enable logging to a file.
    let file = config.file.inner.enabled.then(|| {
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
            .with_thread_ids(config.file.inner.show_thread_id)
            .with_file(config.file.inner.show_source)
            .with_line_number(config.file.inner.show_source)
            .with_ansi(config.file.inner.colors);
        let layer = match config.file.inner.style {
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
            .with_thread_ids(config.stdout.show_thread_id)
            .with_file(config.stdout.show_source)
            .with_line_number(config.stdout.show_source)
            .with_ansi(config.stdout.colors);
        let layer = match config.stdout.style {
            LoggingFmtStyle::Compact => layer.compact().boxed(),
            LoggingFmtStyle::Full => layer.boxed(),
            LoggingFmtStyle::Json => layer.json().boxed(),
            LoggingFmtStyle::Pretty => layer.pretty().boxed(),
        };
        layer.with_filter(log_level_filter)
    });

    // Enable tokio-console instrumentation.
    let console = tokio_console.then(console_subscriber::spawn);

    // Configure the tracing fmt layer.
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive("holo=debug".parse().unwrap())
        .from_env_lossy();
    let env_filter = match tokio_console {
        true => {
            // Enable targets needed by the console.
            env_filter
                .add_directive("tokio=trace".parse().unwrap())
                .add_directive("runtime=trace".parse().unwrap())
        }
        false => env_filter,
    };
    tracing_subscriber::registry()
        .with(env_filter)
        .with(journald)
        .with(file)
        .with(stdout)
        .with(console)
        .init();
}

fn privdrop(user: &str) -> nix::Result<()> {
    // Preserve set of permitted capabilities upon privdrop.
    capctl::prctl::set_securebits(capctl::prctl::Secbits::KEEP_CAPS).unwrap();

    // Drop to unprivileged user and group.
    if let Some(user) = User::from_name(user)? {
        //nix::unistd::chroot(&user.dir)?;
        //nix::unistd::chdir("/")?;
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

// ===== main =====

fn main() {
    // Parse command-line parameters.
    let matches = App::new("Holo routing daemon")
        .version(clap::crate_version!())
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
    init_tracing(&config.logging, config.tokio_console.enabled);

    // Drop privileges.
    if let Err(error) = privdrop(&config.user) {
        error!(%error, "failed to drop root privileges");
        std::process::exit(1);
    }

    // Set panic handler to abort the process if any child task panics.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic(info);
        std::process::exit(1);
    }));

    // We're ready to go!
    info!("starting up");

    // Main loop.
    let main = || async {
        // Serve northbound clients.
        let nb = Northbound::init(&config).await;
        nb.run().await;
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
}
