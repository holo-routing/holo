//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::VecDeque;

use derive_new::new;
use indextree::NodeId;

use crate::error::ParserError;
use crate::session::Session;
use crate::token::{Commands, TokenKind};

#[derive(Debug, new)]
pub struct ParsedCommand {
    pub negate: bool,
    pub token_id: NodeId,
    pub args: ParsedArgs,
}

pub type ParsedArgs = VecDeque<(String, String)>;

// ===== global functions =====

pub(crate) fn normalize_input_line(line: &str) -> Option<String> {
    // Ignore "!" comments.
    // TODO: allow "!" within user input like interface descriptions
    let line = match line.split('!').next() {
        Some(line) => line,
        None => return None,
    };

    // Remove redundant whitespaces.
    let line = line.split_whitespace().collect::<Vec<_>>().join(" ");

    // Handle empty input.
    if line.is_empty() {
        return None;
    }

    Some(line)
}

fn get_tokens(
    commands: &Commands,
    start_token_id: NodeId,
    add_internal: bool,
) -> Vec<NodeId> {
    let mut tokens =
        start_token_id.children(&commands.arena).collect::<Vec<_>>();

    // Combine auto-rendered YANG commands and internal commands into
    // a single vector.
    if add_internal {
        // Add top-level internal commands.
        if start_token_id == commands.config_root_yang {
            tokens.extend(
                commands.config_root_internal.children(&commands.arena),
            );
        }

        // Add default internal commands.
        tokens.extend(commands.config_dflt_internal.children(&commands.arena));
    }

    tokens
}

fn find_matching_tokens(
    commands: &Commands,
    tokens: Vec<NodeId>,
    word: &str,
) -> Vec<NodeId> {
    tokens
        .into_iter()
        .filter(|token_id| {
            let token = commands.get_token(*token_id);
            token.matches(word, false)
        })
        .collect::<Vec<_>>()
}

fn find_exact_matching_token<'a>(
    commands: &Commands,
    tokens: &'a [NodeId],
    word: &str,
) -> Option<&'a NodeId> {
    tokens.iter().find(|token_id| {
        let token = commands.get_token(**token_id);
        token.matches(word, true)
    })
}

pub(crate) fn parse_command_try(
    session: &Session,
    commands: &Commands,
    start_token_id: NodeId,
    line: &str,
) -> Result<ParsedCommand, ParserError> {
    let mut curr_token_id = start_token_id;
    let mut args = ParsedArgs::new();
    let mut negate = false;

    for (index, word) in line.split_whitespace().enumerate() {
        let first_word = index == 0;
        let tokens = get_tokens(
            commands,
            curr_token_id,
            first_word && session.mode().is_configure(),
        );

        // Find matching tokens.
        let matching_tokens = find_matching_tokens(commands, tokens, word);

        // Check how many matching tokens were found and return an error if
        // necessary.
        let matching_token_id = match matching_tokens.len() {
            0 => return Err(ParserError::NoMatch),
            1 => matching_tokens[0],
            _ => {
                // Try to find an exact match, otherwise return an ambiguity
                // error.
                if let Some(token_id) =
                    find_exact_matching_token(commands, &matching_tokens, word)
                {
                    *token_id
                } else {
                    return Err(ParserError::Ambiguous(matching_tokens));
                }
            }
        };
        let matching_token = commands.get_token(matching_token_id);

        // Check for negation commands.
        if first_word && matching_token.name == "no" {
            negate = true;
        } else {
            // Check for user-provided arguments.
            if let Some(argument_name) = &matching_token.argument {
                let value = match matching_token.kind {
                    TokenKind::Word => matching_token.name.clone(),
                    TokenKind::String => word.to_owned(),
                };
                args.push_back((argument_name.clone(), value));
            }

            // Update current token ID and proceed to the next word.
            curr_token_id = matching_token_id;
        }
    }

    // Check if the matched token represents a command.
    if curr_token_id != start_token_id {
        let token = commands.get_token(curr_token_id);
        if token.action.is_some() {
            Ok(ParsedCommand::new(negate, curr_token_id, args))
        } else {
            Err(ParserError::Incomplete(curr_token_id))
        }
    } else {
        let tokens =
            get_tokens(commands, start_token_id, session.mode().is_configure());
        Err(ParserError::Ambiguous(tokens))
    }
}

pub(crate) fn parse_command(
    session: &mut Session,
    commands: &Commands,
    line: &str,
) -> Result<ParsedCommand, ParserError> {
    let orig_mode = session.mode().clone();
    let wd_token_id = orig_mode.token(commands);

    let orig_ret = parse_command_try(session, commands, wd_token_id, line);
    if orig_ret.is_ok() {
        return orig_ret;
    }

    // Back-tracking: check if the command is present in upper CLI nodes.
    let mut token_id_child = wd_token_id;
    for token_id in wd_token_id.ancestors(&commands.arena) {
        // Update CLI node when traversing a YANG list.
        if let Some(token) = commands.get_opt_token(token_id) {
            if token.node_update {
                session.mode_config_exit();
            }
        }
        // Ignore list keys that can match on everything.
        match commands.get_opt_token(token_id_child) {
            Some(token_child) => {
                token_id_child = token_id;
                if token_child.kind != TokenKind::Word {
                    continue;
                }
            }
            None => {
                break;
            }
        }

        // Try the same command in this CLI node.
        let ret = parse_command_try(session, commands, token_id, line);
        if ret.is_ok() {
            return ret;
        }
    }

    // Restore original CLI node and return the original error.
    session.mode_set(orig_mode);
    orig_ret
}
