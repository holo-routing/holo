//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod config;
mod northbound;

use std::path::Path;

use capctl::caps;
use config::{Config, LoggingFileRotation, LoggingFmtStyle};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::stat::{Mode, umask};
use nix::unistd::{Group, Uid, User};
use northbound::Northbound;
use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

// jemalloc tends to fragment less than glibc malloc for routing workloads,
// returning freed memory to the OS more aggressively.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, Default)]
struct Args {
    config_file: Option<String>,
}

// Usage summary printed by --help and on command-line errors.
const USAGE: &str = "\
Usage: holod [-c <file>]
       holod -h | -V

Options:
  -c, --config <file>  Specify an alternative configuration file.
  -h, --help           Print this help message and exit.
  -V, --version        Print the version and exit.";

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut args = Args::default();
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Short('c') | lexopt::Arg::Long("config") => {
                args.config_file = Some(parser.value()?.into_string()?);
            }
            lexopt::Arg::Short('h') | lexopt::Arg::Long("help") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            lexopt::Arg::Short('V') | lexopt::Arg::Long("version") => {
                println!("Holo routing daemon {}", build_version());
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(args)
}

fn ensure_single_instance(path: &Path) -> Flock<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|err| {
            eprintln!(
                "failed to open instance lock file {}: {err}",
                path.display()
            );
            std::process::exit(1);
        });

    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => lock,
        Err((_, errno)) => {
            if errno == nix::errno::Errno::EAGAIN {
                eprintln!("another instance of holod is already running");
            } else {
                eprintln!(
                    "failed to acquire instance lock on {}: {errno}",
                    path.display()
                );
            }
            std::process::exit(1);
        }
    }
}

fn init_tracing(config: &config::Logging) {
    // Enable logging to journald.
    let journald = config.journald.enabled.then(|| {
        tracing_journald::layer().expect("couldn't connect to journald")
    });

    // Enable logging to a file.
    let file = config.file.enabled.then(|| {
        let rotation = match config.file.rotation {
            LoggingFileRotation::Never => Rotation::NEVER,
            LoggingFileRotation::Hourly => Rotation::HOURLY,
            LoggingFileRotation::Daily => Rotation::DAILY,
        };
        let file_appender = RollingFileAppender::builder()
            .rotation(rotation)
            .filename_prefix(config.file.name.as_str())
            .build(&config.file.dir);
        let file_appender = match file_appender {
            Ok(file_appender) => file_appender,
            Err(error) => {
                eprintln!(
                    "failed to open the log file in {}: {error}",
                    config.file.dir
                );
                std::process::exit(1);
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
    rollback_log_max: u32,
) -> Result<PickleDb, pickledb::error::Error> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(PickleDb::new(
            path,
            PickleDbDumpPolicy::AutoDump,
            SerializationMethod::Bin,
        ));
    }

    // Trim the rollback log before normal operation. This is done without
    // auto-dumping so that the file is rewritten only once, rather than once
    // per removed transaction.
    //
    // Failing to write the trimmed database isn't fatal: the database is then
    // loaded as it is on disk, and pruning is retried on the next commit.
    let mut db = PickleDb::load(
        path,
        PickleDbDumpPolicy::DumpUponRequest,
        SerializationMethod::Bin,
    )?;
    let pruned = northbound::db::transaction_prune(&mut db, rollback_log_max);
    if pruned > 0 {
        match db.dump() {
            Ok(()) => {
                info!(%pruned, "pruned old transactions from the rollback log");
            }
            Err(error) => {
                error!(%error, "failed to prune the rollback log");
            }
        }
    }
    drop(db);

    PickleDb::load(path, PickleDbDumpPolicy::AutoDump, SerializationMethod::Bin)
}

fn privdrop(user: &str, group: &str) -> nix::Result<()> {
    // Preserve set of permitted capabilities upon privdrop.
    capctl::prctl::set_securebits(capctl::prctl::Secbits::KEEP_CAPS).unwrap();

    // The run-as group is configured independently of the user.
    let Some(group) = Group::from_name(group)? else {
        eprintln!("failed to find group {group}");
        std::process::exit(1);
    };

    // Drop to unprivileged user and group.
    if let Some(user) = User::from_name(user)? {
        nix::unistd::setgroups(&[group.gid])?;
        nix::unistd::setresgid(group.gid, group.gid, group.gid)?;
        nix::unistd::setresuid(user.uid, user.uid, user.uid)?;
    } else {
        eprintln!("failed to find user {user}");
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
        eprintln!("failed to set permitted capabilities: {error}");
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

    // Resolve the commit SHA at compile time.
    //
    // Docker and CI builds do not include the .git directory, so git metadata
    // is unavailable. In those cases, the commit SHA is injected via the
    // GIT_HASH environment variable. For local builds with access to .git,
    // fall back to querying the repository directly.
    let git_hash = option_env!("GIT_HASH")
        .map(String::from)
        .or_else(|| rustc_tools_util::get_version_info!().commit_hash);

    match git_hash {
        Some(hash) => format!("{VERSION} ({hash})"),
        None => VERSION.to_owned(),
    }
}

// ===== main =====

fn main() {
    // Parse command-line parameters.
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}\n\n{USAGE}");
        std::process::exit(1);
    });

    // Read configuration file.
    let config = Config::load(args.config_file.as_deref());

    // Check for root privileges.
    if !Uid::effective().is_root() {
        eprintln!("need privileged user");
        std::process::exit(1);
    }

    // Files created from here on are readable by @user and @group only.
    umask(Mode::from_bits_truncate(0o027));

    // Drop privileges.
    if let Err(error) = privdrop(&config.user, &config.group) {
        eprintln!("failed to drop root privileges: {error}");
        std::process::exit(1);
    }

    // Ensure only one holod instance uses the state directory. This comes
    // after the privilege drop, as @user can write to that directory.
    let _lock =
        ensure_single_instance(&config.state_path(Config::INSTANCE_LOCK_NAME));

    // Initialize tracing.
    init_tracing(&config.logging);

    // Initialize non-volatile storage.
    let db = init_db(
        config.state_path(Config::DATABASE_NAME),
        config.rollback_log.max_entries,
    )
    .expect("failed to initialize non-volatile storage");

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

// ===== unit tests =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_db_prunes_rollback_log() {
        let dir = std::env::temp_dir()
            .join(format!("holod-test-init-db-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("holo.db");

        // Create a database holding five transactions and an unrelated key.
        let mut db = PickleDb::new(
            &path,
            PickleDbDumpPolicy::AutoDump,
            SerializationMethod::Bin,
        );
        for id in 1..=5 {
            db.set(&format!("transaction{id}"), &id).unwrap();
        }
        db.set("unrelated", &0).unwrap();
        drop(db);

        // Only the two newest transactions are kept.
        let mut db = init_db(&path, 2).unwrap();
        let mut keys = db.get_all();
        keys.sort();
        assert_eq!(keys, ["transaction4", "transaction5", "unrelated"]);

        // Later changes are still written to disk automatically.
        db.set("later", &0).unwrap();
        let on_disk =
            PickleDb::load_read_only(&path, SerializationMethod::Bin).unwrap();
        let mut keys = on_disk.get_all();
        keys.sort();
        assert_eq!(
            keys,
            ["later", "transaction4", "transaction5", "unrelated"]
        );

        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
