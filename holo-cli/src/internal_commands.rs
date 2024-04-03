//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt::Write;
use std::process::{Command, Stdio};

use holo_yang::YANG_CTX;
use indextree::NodeId;
use prettytable::{format, row, Table};
use similar::TextDiff;
use yang2::data::{Data, DataFormat, DataNodeRef, DataPrinterFlags, DataTree};
use yang2::schema::SchemaNodeKind;

use crate::parser::ParsedArgs;
use crate::session::{CommandMode, ConfigurationType, Session};
use crate::token::{Commands, TokenKind};

// ===== helper functions =====

fn get_arg(args: &mut ParsedArgs, name: &str) -> String {
    get_opt_arg(args, name).expect("Failed to find argument")
}

fn get_opt_arg(args: &mut ParsedArgs, name: &str) -> Option<String> {
    let found = args.iter().position(|(arg_name, _)| arg_name == name);
    if let Some(found) = found {
        return Some(args.remove(found).unwrap().1);
    }

    None
}

fn page_output(session: &Session, data: &str) -> Result<(), std::io::Error> {
    if session.use_pager() {
        use std::io::Write;

        // Spawn the pager process.
        let mut pager = Command::new("less")
            // Exit immediately if the data fits on one screen.
            .arg("-F")
            .stdin(Stdio::piped())
            .spawn()?;

        // Feed the data to the pager.
        pager.stdin.as_mut().unwrap().write_all(data.as_bytes())?;

        // Wait for the pager process to finish.
        pager.wait()?;
    } else {
        // Print the data directly to the console.
        println!("{}", data);
    }

    Ok(())
}

// ===== "configure" =====

pub(crate) fn cmd_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    let mode = CommandMode::Configure { nodes: vec![] };
    session.mode_set(mode);
    Ok(false)
}

// ===== "exit" =====

pub(crate) fn cmd_exit_exec(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    // Do nothing.
    Ok(true)
}

pub(crate) fn cmd_exit_config(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.mode_config_exit();
    Ok(false)
}

// ===== "end" =====

pub(crate) fn cmd_end(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.mode_set(CommandMode::Operational);
    Ok(false)
}

// ===== "list" =====

pub(crate) fn cmd_list(
    commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    match session.mode() {
        CommandMode::Operational => {
            // List EXEC-level commands.
            cmd_list_root(commands, &commands.exec_root);
        }
        CommandMode::Configure { .. } => {
            // List internal configuration commands first.
            cmd_list_root(commands, &commands.config_dflt_internal);
            println!("---");
            cmd_list_root(commands, &commands.config_root_internal);
            println!("---");
            // List YANG configuration commands.
            cmd_list_root(commands, &session.mode().token(commands));
        }
    }

    Ok(false)
}

pub(crate) fn cmd_list_root(commands: &Commands, top_token_id: &NodeId) {
    for token_id in
        top_token_id
            .descendants(&commands.arena)
            .skip(1)
            .filter(|token_id| {
                let token = commands.get_token(*token_id);
                token.action.is_some()
            })
    {
        let mut cmd_string = String::new();

        let ancestor_token_ids = token_id
            .ancestors(&commands.arena)
            .filter(|token_id| *token_id > *top_token_id)
            .collect::<Vec<NodeId>>();
        for ancestor_token_id in ancestor_token_ids.iter().rev() {
            let token = commands.get_token(*ancestor_token_id);
            if token.kind != TokenKind::Word {
                cmd_string.push_str(&token.name.to_uppercase());
            } else {
                cmd_string.push_str(&token.name);
            }
            cmd_string.push(' ');
        }

        println!("{}", cmd_string);
    }
}

// ===== "hostname" =====

pub(crate) fn cmd_hostname(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let hostname = get_arg(&mut args, "hostname");
    session.update_hostname(&hostname);
    Ok(false)
}

// ===== "pwd" =====

pub(crate) fn cmd_pwd(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    println!(
        "{}",
        session.mode().data_path().unwrap_or_else(|| "/".to_owned())
    );
    Ok(false)
}

// ===== "discard" =====

pub(crate) fn cmd_discard(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    session.candidate_discard();
    Ok(false)
}

// ===== "commit" =====

pub(crate) fn cmd_commit(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let comment = get_opt_arg(&mut args, "comment");
    match session.candidate_commit(comment) {
        Ok(_) => {
            println!("% configuration committed successfully");
        }
        Err(error) => {
            println!("% {}", error);
        }
    }

    Ok(false)
}

// ===== "validate" =====

pub(crate) fn cmd_validate(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    match session.candidate_validate() {
        Ok(_) => println!("% candidate configuration validated successfully"),
        Err(error) => {
            println!("% {}", error)
        }
    }

    Ok(false)
}

// ===== "show <candidate|running>" =====

fn cmd_show_config_cmds(config: &DataTree, with_defaults: bool) -> String {
    let mut output = String::new();

    // Iterate over data nodes that represent full commands.
    for dnode in config
        .traverse()
        .filter(|dnode| {
            let snode = dnode.schema();
            match snode.kind() {
                SchemaNodeKind::Container => !snode.is_np_container(),
                SchemaNodeKind::Leaf => !snode.is_list_key(),
                SchemaNodeKind::LeafList => true,
                SchemaNodeKind::List => true,
                _ => false,
            }
        })
        .filter(|dnode| with_defaults || !dnode.is_default())
    {
        let mut tokens = vec![];

        // Indentation.
        let mut indent = String::new();
        for _ in dnode
            .ancestors()
            .filter(|dnode| dnode.schema().kind() == SchemaNodeKind::List)
        {
            write!(indent, " ").unwrap();
        }

        // Build command line.
        for dnode in dnode
            .inclusive_ancestors()
            .take_while(|iter| {
                if *iter == dnode {
                    return true;
                }
                let snode = iter.schema();
                snode.kind() != SchemaNodeKind::List
            })
            .collect::<Vec<DataNodeRef<'_>>>()
            .iter()
            .rev()
        {
            tokens.push(dnode.schema().name().to_owned());
            for dnode in dnode.list_keys() {
                tokens.push(dnode.value_canonical().unwrap());
            }
            if let Some(value) = dnode.value_canonical() {
                tokens.push(value.clone());
            }
        }

        // Print command.
        if dnode.schema().kind() == SchemaNodeKind::List {
            writeln!(output, "{}!", indent).unwrap();
        }
        writeln!(output, "{}{}", indent, tokens.join(" ")).unwrap();
    }

    // Footer.
    writeln!(output, "!").unwrap();

    output
}

fn cmd_show_config_yang(
    config: &DataTree,
    format: DataFormat,
    with_defaults: bool,
) -> Result<String, String> {
    let mut flags = DataPrinterFlags::WITH_SIBLINGS;
    if with_defaults {
        flags |= DataPrinterFlags::WD_ALL;
    }

    let data = config
        .print_string(format, flags)
        .map_err(|error| format!("failed to print configuration: {}", error))?
        .unwrap_or_default();
    Ok(data)
}

pub(crate) fn cmd_show_config(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    // Parse parameters.
    let config_type = get_arg(&mut args, "configuration");
    let config_type = match config_type.as_str() {
        "candidate" => ConfigurationType::Candidate,
        "running" => ConfigurationType::Running,
        _ => panic!("unexpected argument"),
    };
    let with_defaults = get_opt_arg(&mut args, "with-defaults").is_some();
    let format = get_opt_arg(&mut args, "format");

    // Get configuration.
    let config = session.get_configuration(config_type);

    // Display configuration.
    let data = match format.as_deref() {
        Some("json") => {
            cmd_show_config_yang(config, DataFormat::JSON, with_defaults)?
        }
        Some("xml") => {
            cmd_show_config_yang(config, DataFormat::XML, with_defaults)?
        }
        Some(_) => panic!("unknown format"),
        None => cmd_show_config_cmds(config, with_defaults),
    };
    if let Err(error) = page_output(session, &data) {
        println!("% failed to print configuration: {}", error)
    }

    Ok(false)
}

pub(crate) fn cmd_show_config_changes(
    _commands: &Commands,
    session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    let running = session.get_configuration(ConfigurationType::Running);
    let running = cmd_show_config_cmds(running, false);
    let candidate = session.get_configuration(ConfigurationType::Candidate);
    let candidate = cmd_show_config_cmds(candidate, false);

    let diff = TextDiff::from_lines(&running, &candidate);
    print!(
        "{}",
        diff.unified_diff()
            .context_radius(9)
            .header("running configuration", "candidate configuration")
    );

    Ok(false)
}

// ===== "show state" =====

pub(crate) fn cmd_show_state(
    _commands: &Commands,
    session: &mut Session,
    mut args: ParsedArgs,
) -> Result<bool, String> {
    let xpath = get_opt_arg(&mut args, "xpath");
    let format = get_opt_arg(&mut args, "format");
    let format = match format.as_deref() {
        Some("json") => DataFormat::JSON,
        Some("xml") => DataFormat::XML,
        Some(_) => panic!("unknown format"),
        None => DataFormat::JSON,
    };

    match session.get_state(xpath, format) {
        Ok(data) => {
            if let Err(error) = page_output(session, &data) {
                println!("% failed to print state data: {}", error)
            }
        }
        Err(error) => println!("% failed to fetch state data: {}", error),
    }

    Ok(false)
}

// ===== "show yang modules" =====

pub(crate) fn cmd_show_yang_modules(
    _commands: &Commands,
    _session: &mut Session,
    _args: ParsedArgs,
) -> Result<bool, String> {
    // Create the table
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["Module", "Revision", "Flags", "Namespace"]);

    // Add a row per time
    let yang_ctx = YANG_CTX.get().unwrap();
    for module in yang_ctx.modules(false) {
        let mut flags = String::new();

        if module.is_implemented() {
            flags += "I";
        }

        table.add_row(row![
            module.name(),
            module.revision().unwrap_or("-"),
            flags,
            module.namespace()
        ]);
    }

    // Print the table to stdout
    println!(" Flags: I - Implemented");
    println!();
    table.printstd();
    println!();

    Ok(false)
}
