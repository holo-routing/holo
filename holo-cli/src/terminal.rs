//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use indextree::NodeId;
use itertools::Itertools;
use reedline::{
    ColumnarMenu, Completer, FileBackedHistory, KeyCode, KeyModifiers, Prompt,
    PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline,
    ReedlineEvent, ReedlineMenu, Span, Suggestion, Vi,
};

use crate::error::ParserError;
use crate::parser::{self, ParsedCommand};
use crate::token::{Commands, TokenKind};
use crate::Cli;

static DEFAULT_PROMPT_INDICATOR: &str = "# ";
static DEFAULT_MULTILINE_INDICATOR: &str = "::: ";
static DEFAULT_HISTORY_SIZE: usize = 1000;
static DEFAULT_HISTORY_FILENAME: &str = "history.txt";

#[derive(Clone)]
pub struct CliPrompt(String);

#[derive(Clone)]
pub struct CliCompleter(Arc<Mutex<Cli>>);

// ===== impl CliPrompt =====

impl CliPrompt {
    pub(crate) fn new(string: String) -> Self {
        Self(string)
    }

    pub(crate) fn update(&mut self, string: String) {
        self.0 = string;
    }
}

impl Prompt for CliPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned(self.0.clone())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(
        &self,
        _edit_mode: PromptEditMode,
    ) -> Cow<'_, str> {
        DEFAULT_PROMPT_INDICATOR.into()
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        DEFAULT_MULTILINE_INDICATOR.into()
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };
        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

// ===== impl CliCompleter =====

impl Completer for CliCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let cli = self.0.lock().unwrap();

        let last_word = line.split_whitespace().last().unwrap_or(line);
        let partial = line
            .chars()
            .last()
            .map(|c| !c.is_whitespace())
            .unwrap_or(false);

        let wd_token_id = cli.session.mode().token(&cli.commands);
        let completions = match parser::parse_command_try(
            &cli.session,
            &cli.commands,
            wd_token_id,
            line,
        ) {
            Ok(ParsedCommand { token_id, .. })
            | Err(ParserError::Incomplete(token_id)) => {
                if partial {
                    complete_add_token(
                        &cli.commands,
                        token_id,
                        partial,
                        last_word,
                    )
                } else {
                    let token_ids = token_id.children(&cli.commands.arena);
                    complete_add_tokens(&cli.commands, partial, token_ids)
                }
            }
            Err(ParserError::Ambiguous(token_ids)) => {
                complete_add_tokens(&cli.commands, partial, token_ids)
            }
            _ => vec![],
        };

        completions
            .into_iter()
            .map(|(value, description)| Suggestion {
                value,
                description,
                extra: None,
                span: Span {
                    start: if partial { pos - last_word.len() } else { pos },
                    end: pos,
                },
                append_whitespace: true,
            })
            .collect()
    }
}

// ===== global functions =====

pub(crate) fn reedline_init(
    cli: Arc<Mutex<Cli>>,
    use_ansi_coloring: bool,
) -> Reedline {
    let history = Box::new(
        FileBackedHistory::with_file(
            DEFAULT_HISTORY_SIZE,
            DEFAULT_HISTORY_FILENAME.into(),
        )
        .expect("Error configuring history with file"),
    );
    let completer = Box::new(CliCompleter(cli));
    let completion_menu =
        Box::new(ColumnarMenu::default().with_name("completion_menu"));

    let mut insert_keybindings = reedline::default_vi_insert_keybindings();
    let normal_keybindings = reedline::default_vi_normal_keybindings();
    insert_keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    insert_keybindings.add_binding(
        KeyModifiers::CONTROL,
        KeyCode::Char('z'),
        ReedlineEvent::ExecuteHostCommand("end".to_owned()),
    );

    let edit_mode = Box::new(Vi::new(insert_keybindings, normal_keybindings));
    Reedline::create()
        .with_history(history)
        .with_ansi_colors(use_ansi_coloring)
        .with_completer(completer)
        .with_quick_completions(true)
        .with_partial_completions(true)
        .with_edit_mode(edit_mode)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
}

fn complete_add_token(
    commands: &Commands,
    token_id: NodeId,
    partial: bool,
    word: &str,
) -> Vec<(String, Option<String>)> {
    let mut completions = vec![];

    let token = commands.get_token(token_id);
    if token.kind == TokenKind::Word && !token.matches(word, true) {
        completions.push((token.name.clone(), token.help.clone()));
    } else if token.kind == TokenKind::String && !partial {
        completions.push((token.name.to_uppercase(), token.help.clone()));
    }

    completions
}

fn complete_add_tokens(
    commands: &Commands,
    partial: bool,
    token_ids: impl IntoIterator<Item = NodeId>,
) -> Vec<(String, Option<String>)> {
    token_ids
        .into_iter()
        .filter_map(|token_id| {
            let token = commands.get_token(token_id);
            if token.kind == TokenKind::Word {
                Some((token.name.clone(), token.help.clone()))
            } else if token.kind == TokenKind::String && !partial {
                Some((token.name.to_uppercase(), token.help.clone()))
            } else {
                None
            }
        })
        .sorted()
        .collect()
}
