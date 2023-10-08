//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod client;
mod error;
mod internal_commands;
mod parser;
mod session;
mod terminal;
mod token;
mod token_xml;
mod token_yang;

use std::sync::{Arc, Mutex};

use clap::{App, Arg};
use holo_yang as yang;
use holo_yang::YANG_CTX;
use reedline::Signal;

use crate::client::grpc::GrpcClient;
use crate::client::Client;
use crate::error::Error;
use crate::session::{CommandMode, Session};
use crate::terminal::CliPrompt;
use crate::token::{Action, Commands};

static DEFAULT_HOSTNAME: &str = "holo";

pub struct Cli {
    commands: Commands,
    session: Session,
}

// ===== impl Cli =====

impl Cli {
    fn new(hostname: String, use_pager: bool, client: Box<dyn Client>) -> Cli {
        // Generate commands.
        let mut commands = Commands::new();
        commands.gen_cmds();

        // Create CLI session.
        let mut session = Session::new(hostname, use_pager, client);
        session.update_prompt();

        Cli { commands, session }
    }

    fn enter_command(&mut self, line: &str) -> Result<bool, Error> {
        // Normalize input line.
        let line = match parser::normalize_input_line(line) {
            Some(line) => line,
            None => return Ok(false),
        };

        // Parse command.
        let pcmd =
            parser::parse_command(&mut self.session, &self.commands, &line)
                .map_err(Error::Parser)?;
        let token = self.commands.get_token(pcmd.token_id);
        let negate = pcmd.negate;
        let args = pcmd.args;

        // Process command.
        let mut exit = false;
        if let Some(action) = &token.action {
            match action {
                Action::ConfigEdit(snode) => {
                    // Edit configuration & update CLI node if necessary.
                    self.session
                        .edit_candidate(negate, snode, args)
                        .map_err(Error::EditConfig)?;
                }
                Action::Callback(callback) => {
                    // Execute callback.
                    exit = (callback)(&self.commands, &mut self.session, args)
                        .map_err(Error::Callback)?;
                }
            }
        }

        Ok(exit)
    }
}

// ===== global functions =====

fn read_config_file(mut cli: Cli, path: &str) {
    // Enter configuration mode.
    let mode = CommandMode::Configure { nodes: vec![] };
    cli.session.mode_set(mode);

    // Read file from the filesystem.
    let file = match std::fs::read_to_string(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("% failed to read file path: {}", error);
            return;
        }
    };

    // Read configuration.
    for line in file.lines() {
        if let Err(error) = cli.enter_command(line) {
            eprintln!("% {}", error);
        }
    }

    // Commit configuration.
    let comment = Some(format!("Configuration read from {}", path));
    if let Err(err) = cli.session.candidate_commit(comment) {
        eprintln!("% {}", err);
    }
}

fn main() {
    // Parse command-line parameters.
    let matches = App::new("Holo command-line interface")
        .version(clap::crate_version!())
        .arg(
            Arg::with_name("file")
                .long("file")
                .value_name("path")
                .help("Read configuration file"),
        )
        .arg(
            Arg::with_name("no-colors")
                .long("no-colors")
                .help("Disable ansi coloring"),
        )
        .arg(
            Arg::with_name("no-pager")
                .long("no-pager")
                .help("Disable the pager"),
        )
        .arg(
            Arg::with_name("command")
                .short("c")
                .long("command")
                .value_name("COMMAND")
                .help("Execute argument as command")
                .multiple(true),
        )
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .value_name("ADDRESS")
                .help("Holo daemon IPv4/6 address: http://IP:Port")
                .multiple(false),
        )
        .get_matches();

    let addr = matches
        .value_of("address")
        .unwrap_or("http://[::1]:50051")
        .to_string();
    let grpc_addr: &'static str = Box::leak(addr.into_boxed_str());

    // Initialize YANG context and gRPC client.
    let mut yang_ctx = yang::new_context();
    let mut client = match GrpcClient::connect(grpc_addr) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Connection to holod failed: {}\n", error);
            eprintln!("Please ensure that holod is currently running.");
            std::process::exit(1);
        }
    };
    client.load_modules(&mut yang_ctx);
    YANG_CTX.set(Arc::new(yang_ctx)).unwrap();

    // Initialize CLI master structure.
    let use_pager = matches.values_of("command").is_none()
        && !matches.is_present("no-pager");
    let mut cli =
        Cli::new(DEFAULT_HOSTNAME.to_string(), use_pager, Box::new(client));

    // Read configuration file.
    if let Some(path) = matches.value_of("file") {
        read_config_file(cli, path);
        return;
    }

    // Process commands passed as arguments, if any.
    if let Some(commands) = matches.values_of("command") {
        for command in commands {
            if let Err(error) = cli.enter_command(command) {
                println!("% {}", error)
            }
        }
        return;
    }

    // Initialize reedline.
    let mut prompt = CliPrompt::new(cli.session.prompt());
    let cli = Arc::new(Mutex::new(cli));
    let use_ansi_coloring = !matches.is_present("no-colors");
    let mut le = terminal::reedline_init(cli.clone(), use_ansi_coloring);

    // Main loop.
    while let Signal::Success(line) =
        le.read_line(&prompt).expect("Failed to read line")
    {
        let mut cli = cli.lock().unwrap();
        match cli.enter_command(&line) {
            Ok(exit) => {
                if exit {
                    break;
                }
            }
            Err(error) => {
                println!("% {}", error)
            }
        };

        // Update CLI prompt.
        prompt.update(cli.session.prompt());
    }

    // Update history log.
    le.sync_history().expect("Failed to update history file");
}
