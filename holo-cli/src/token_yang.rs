//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt::Write;
use std::os::raw::c_void;

use holo_yang::YANG_CTX;
use indextree::NodeId;
use itertools::Itertools;
use yang2::schema::{DataValueType, SchemaNode, SchemaNodeKind};

use crate::parser::ParsedArgs;
use crate::token::{Action, Commands, Token, TokenKind};

pub(crate) fn gen_cmds(commands: &mut Commands) {
    // Iterate over top-level YANG nodes.
    let yang_ctx = YANG_CTX.get().unwrap();
    for snode in yang_ctx
        .modules(true)
        .flat_map(|module| module.data())
        .filter(|snode| snode.is_config())
        .filter(|snode| snode.is_status_current())
        .sorted_by(|a, b| Ord::cmp(&a.name(), &b.name()))
    {
        gen_cmds_recursive(commands, snode, commands.config_root_yang);
    }
}

fn gen_cmds_recursive(
    commands: &mut Commands,
    snode: SchemaNode<'static>,
    parent_token_id: NodeId,
) {
    let mut token_id = parent_token_id;

    // Add tokens for this node.
    if !snode.is_schema_only() {
        add_tokens(commands, &snode, &mut token_id);
    }

    // Iterate over child nodes (skipping list keys, schema-only nodes and
    // read-only subtrees).
    for snode in snode
        .children()
        .filter(|snode| snode.is_config())
        .filter(|snode| !snode.is_list_key())
        .filter(|snode| snode.is_status_current())
        .sorted_by(|a, b| Ord::cmp(&a.name(), &b.name()))
    {
        gen_cmds_recursive(commands, snode, token_id);
    }
}

fn add_tokens(
    commands: &mut Commands,
    snode: &SchemaNode<'static>,
    token_id: &mut NodeId,
) {
    // Add base token corresponding to the schema node.
    add_token(commands, token_id, snode, TokenKind::Word, false);

    match snode.kind() {
        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
            if snode.base_type() != Some(DataValueType::Empty) =>
        {
            // Add input token.
            add_token(commands, token_id, snode, TokenKind::String, true);
        }
        SchemaNodeKind::List => {
            // Add list keys.
            for snode in snode.list_keys() {
                add_token(commands, token_id, &snode, TokenKind::String, true);
            }
        }
        _ => (),
    }
}

fn add_token(
    commands: &mut Commands,
    token_id: &mut NodeId,
    snode: &SchemaNode<'static>,
    kind: TokenKind,
    is_argument: bool,
) {
    let name = snode.name();
    let help = snode.description();
    let argument = if is_argument { Some(name) } else { None };
    let action = is_full_command(snode, is_argument)
        .then(|| Action::ConfigEdit(snode.clone()));
    let node_update = snode.kind() == SchemaNodeKind::List;

    let token = Token::new(name, help, kind, argument, action, node_update);
    *token_id = commands.add_token(*token_id, token);
    snode_set_token_id(snode, *token_id);
}

fn is_full_command(snode: &SchemaNode<'_>, is_argument: bool) -> bool {
    match snode.kind() {
        SchemaNodeKind::Container => !snode.is_np_container(),
        SchemaNodeKind::Leaf => {
            if snode.base_type() == Some(DataValueType::Empty) {
                true
            } else if snode.is_list_key() {
                match snode.siblings().next() {
                    Some(next) => !next.is_list_key(),
                    None => true,
                }
            } else {
                is_argument
            }
        }
        SchemaNodeKind::LeafList => is_argument,
        _ => false,
    }
}

pub(crate) fn update_cli_path(
    path: &mut String,
    snode: &SchemaNode<'_>,
    list_keys: &ParsedArgs,
) {
    let snode = snode
        .ancestors()
        .find(|snode| snode.kind() == SchemaNodeKind::List)
        .unwrap();
    let list_keys = list_keys.iter().map(|(_, value)| value).join(" ");
    write!(path, "/{}[{}]", snode.name(), list_keys).unwrap();
}

// Save token ID in the schema node private pointer.
fn snode_set_token_id(snode: &SchemaNode<'_>, token_id: NodeId) {
    let btoken_id = Box::new(token_id);
    let btoken_id_ptr = Box::into_raw(btoken_id) as *mut c_void;
    unsafe { snode.set_private(btoken_id_ptr) };
}

// Retrieve token ID from the schema node private pointer.
pub(crate) fn snode_get_token_id(snode: &SchemaNode<'_>) -> NodeId {
    let btoken_id_ptr = snode.get_private().unwrap() as *mut NodeId;
    let btoken_id = unsafe { Box::from_raw(btoken_id_ptr) };
    let token_id = *btoken_id;
    snode_set_token_id(snode, token_id);
    token_id
}
