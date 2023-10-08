//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use indextree::{Arena, NodeId};
use yang2::schema::SchemaNode;

use crate::parser::ParsedArgs;
use crate::session::Session;
use crate::{token_xml, token_yang};

pub struct Commands {
    pub arena: Arena<Option<Token>>,
    pub exec_root: NodeId,
    pub config_root_yang: NodeId,
    pub config_root_internal: NodeId,
    pub config_dflt_internal: NodeId,
}

pub struct Token {
    pub name: String,
    pub help: Option<String>,
    pub kind: TokenKind,
    pub argument: Option<String>,
    pub action: Option<Action>,
    pub node_update: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TokenKind {
    Word,
    String,
}

pub enum Action {
    Callback(Callback),
    ConfigEdit(SchemaNode<'static>),
}

type Callback = fn(
    commands: &Commands,
    session: &mut Session,
    args: ParsedArgs,
) -> Result<bool, String>;

// ===== impl Commands =====

impl Commands {
    pub(crate) fn new() -> Commands {
        let mut arena = Arena::new();
        let exec_root = arena.new_node(None);
        let config_dflt_internal = arena.new_node(None);
        let config_root_yang = arena.new_node(None);
        let config_root_internal = arena.new_node(None);

        Commands {
            arena,
            exec_root,
            config_root_yang,
            config_root_internal,
            config_dflt_internal,
        }
    }

    pub(crate) fn gen_cmds(&mut self) {
        token_yang::gen_cmds(self);
        token_xml::gen_cmds(self);
    }

    pub(crate) fn add_token(&mut self, parent: NodeId, token: Token) -> NodeId {
        let token_id = self.arena.new_node(Some(token));
        parent.append(token_id, &mut self.arena);
        token_id
    }

    pub(crate) fn get_token(&self, token_id: NodeId) -> &Token {
        self.get_opt_token(token_id).unwrap()
    }

    pub(crate) fn get_opt_token(&self, token_id: NodeId) -> Option<&Token> {
        self.arena.get(token_id).unwrap().get().as_ref()
    }
}

// ===== impl Token =====

impl Token {
    pub(crate) fn new<S: Into<String>>(
        name: S,
        help: Option<S>,
        kind: TokenKind,
        argument: Option<S>,
        action: Option<Action>,
        node_update: bool,
    ) -> Token {
        Token {
            name: name.into(),
            help: help.map(|s| s.into()),
            kind,
            argument: argument.map(|s| s.into()),
            action,
            node_update,
        }
    }

    pub(crate) fn matches(&self, word: &str, exact: bool) -> bool {
        if self.kind == TokenKind::String {
            // TODO: custom match per token type.
            true
        } else if exact {
            self.name == word
        } else {
            self.name.starts_with(word)
        }
    }
}
