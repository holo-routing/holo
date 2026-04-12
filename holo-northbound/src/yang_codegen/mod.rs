//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod code_writer;
pub mod struct_builder;
pub mod types;

use std::env;
use std::iter::once;
use std::path::PathBuf;

use check_keyword::CheckKeyword;
use convert_case::{Boundary, Case, Casing};
use yang5::context::Context;
use yang5::schema::{
    DataValueType, SchemaNode, SchemaNodeKind, SchemaPathFormat,
};

use crate::yang_codegen::code_writer::{CodeWriter, emit};
use crate::yang_codegen::struct_builder::StructBuilder;

const HEADER_YANG_OBJECTS: &str = r#"
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_northbound::rpc::YangRpcObject;
use holo_northbound::{YangObject, YangPath};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::{YANG_CTX, ToYang, TryFromYang};
use holo_yang::types::*;
use yang5::data::{Data, DataNodeRef};
use yang5::schema::SchemaModule;

"#;

const HEADER_YANG_OPS: &str = r#"
use holo_northbound::state::{self, YangList, YangListOps, YangContainer, YangContainerOps};
use holo_northbound::rpc::{self, YangRpc, YangRpcObject, YangRpcOps};
use phf::phf_map;
use super::*;

"#;

pub trait SchemaNodeCodegenExt {
    // Returns the Rust identifier for this node in the given case.
    fn rust_name(&self, case: Case<'_>) -> String;

    // Returns the fully-qualified Rust module path for this node.
    fn rust_module_path(&self) -> String;

    // Returns true if this node is a list that can hold state data.
    fn is_state_list(&self) -> bool;

    // Returns true if this node is a container that can hold state data.
    fn is_state_container(&self) -> bool;

    // Returns true if this node directly carries leaf data: either it is a
    // leaf/leaf-list itself, or it is a choice whose cases contain one.
    fn has_leaf_data(&self) -> bool;

    // Returns true if this node belongs to one of the given YANG modules.
    fn in_modules(&self, modules: &[&str]) -> bool;

    // Returns true if any ancestor of this node has the given name.
    fn has_ancestor_named(&self, name: &str) -> bool;
}

// ===== impl SchemaNode =====

impl SchemaNodeCodegenExt for SchemaNode<'_> {
    fn rust_name(&self, case: Case<'_>) -> String {
        let mut name = self.name().to_owned();

        // If a sibling node shares the same name but belongs to a different
        // module, prepend this node's module prefix to disambiguate.
        if let Some(parent) = self.ancestors().next()
            && parent.children().any(|sibling| {
                sibling.name() == self.name()
                    && sibling.module() != self.module()
            })
        {
            name.insert_str(0, &format!("{}-", self.module().prefix()));
        }

        // Case conversion.
        name = name
            .from_case(Case::Kebab)
            .remove_boundaries(&[Boundary::UpperDigit, Boundary::LowerDigit])
            .to_case(case);

        // Handle Rust reserved keywords.
        name.into_safe()
    }

    fn rust_module_path(&self) -> String {
        let snodes = self.inclusive_ancestors().collect::<Vec<_>>();
        snodes
            .iter()
            .rev()
            .filter(|snode| !snode.is_schema_only())
            .map(|snode| snode.rust_name(Case::Snake))
            .collect::<Vec<_>>()
            .join("::")
    }

    fn is_state_list(&self) -> bool {
        if self.kind() != SchemaNodeKind::List {
            return false;
        }
        if !self.is_config() && !self.is_state() {
            return false;
        }
        self.traverse().any(|snode| snode.is_state())
    }

    fn is_state_container(&self) -> bool {
        if self.kind() != SchemaNodeKind::Container {
            return false;
        }
        if !self.traverse().any(|snode| snode.is_state()) {
            return false;
        }
        self.children()
            .any(|snode| snode.is_state() && snode.has_leaf_data())
    }

    fn has_leaf_data(&self) -> bool {
        match self.kind() {
            SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => true,
            SchemaNodeKind::Choice => self
                .children()
                .flat_map(|snode| snode.children())
                .any(|snode| snode.has_leaf_data()),
            _ => false,
        }
    }

    fn in_modules(&self, modules: &[&str]) -> bool {
        modules.iter().any(|module| *module == self.module().name())
    }

    fn has_ancestor_named(&self, name: &str) -> bool {
        self.ancestors().any(|ancestor| ancestor.name() == name)
    }
}

// ===== helper functions =====

fn generate_module(
    w: &mut CodeWriter,
    modules: &[&str],
    snode: &SchemaNode<'_>,
) -> std::fmt::Result {
    let gen_module = !snode.is_schema_only()
        && snode.traverse().any(|snode| snode.in_modules(modules))
        && (snode.is_config()
            || matches!(
                snode.kind(),
                SchemaNodeKind::Container
                    | SchemaNodeKind::List
                    | SchemaNodeKind::Rpc
                    | SchemaNodeKind::Action
                    | SchemaNodeKind::Input
                    | SchemaNodeKind::Output
                    | SchemaNodeKind::Notification
            ));

    if gen_module {
        let name = snode.rust_name(Case::Snake);

        emit!(w, 0, "pub mod {name} {{")?;
        emit!(w, 1, "use super::*;")?;

        generate_paths(w, snode)?;

        // Generate default value (if any).
        if snode.is_config()
            && let Ok(Some(dflt_value)) = snode.default_value_canonical()
            && let Some(leaf_type) = snode.leaf_type()
        {
            let dflt_type = leaf_type.base_type();
            let dflt_value = dflt_value.to_owned();
            generate_default_value(w, dflt_type, dflt_value)?;
        }

        // Generate object struct.
        match snode.kind() {
            SchemaNodeKind::Container | SchemaNodeKind::Notification => {
                let builder = StructBuilder::new(snode.clone());
                if !builder.fields.is_empty() {
                    builder.generate(w)?;
                }
            }
            SchemaNodeKind::List
            | SchemaNodeKind::Rpc
            | SchemaNodeKind::Action
            | SchemaNodeKind::Input
            | SchemaNodeKind::Output => {
                let builder = StructBuilder::new(snode.clone());
                builder.generate(w)?;
            }
            _ => (),
        }
    }

    // Iterate over child nodes at the next indentation level.
    if gen_module {
        w.level += 1;
    }
    let children = snode
        .actions()
        .chain(snode.notifications())
        .chain(snode.children().filter(|snode| snode.is_status_current()));
    for snode in children {
        generate_module(w, modules, &snode)?;
    }
    if gen_module {
        w.level -= 1;
        emit!(w, 0, "}}")?;
    }

    Ok(())
}

fn generate_paths(
    w: &mut CodeWriter,
    snode: &SchemaNode<'_>,
) -> std::fmt::Result {
    let path = snode.path(SchemaPathFormat::DATA);
    emit!(
        w,
        1,
        "pub const PATH: YangPath = YangPath::new(\"{path}\");"
    )?;

    // For notifications, also generate data path relative to the nearest
    // parent list.
    if snode.kind() == SchemaNodeKind::Notification
        && let Some(snode_parent_list) = snode
            .ancestors()
            .find(|snode| snode.kind() == SchemaNodeKind::List)
    {
        let path_parent_list = snode_parent_list.path(SchemaPathFormat::DATA);
        let relative_path = &path[path_parent_list.len()..];
        emit!(w, 1, "pub const RELATIVE_PATH: &str = \"{relative_path}\";")?;
    }

    Ok(())
}

fn generate_default_value(
    w: &mut CodeWriter,
    dflt_type: DataValueType,
    mut dflt_value: String,
) -> std::fmt::Result {
    let dflt_type = match dflt_type {
        DataValueType::Uint8 => "u8",
        DataValueType::Uint16 => "u16",
        DataValueType::Uint32 => "u32",
        DataValueType::Uint64 => "u64",
        DataValueType::Bool => "bool",
        DataValueType::Int8 => "i8",
        DataValueType::Int16 => "i16",
        DataValueType::Int32 => "i32",
        DataValueType::Int64 => "i64",
        // TODO: handle derived types.
        _ => "&str",
    };
    if dflt_type == "&str" {
        dflt_value = format!("\"{dflt_value}\"");
    }
    emit!(w, 1, "pub const DFLT: {dflt_type} = {dflt_value};")?;
    Ok(())
}

fn write_ops_map_entry(
    w: &mut CodeWriter,
    snode: &SchemaNode<'_>,
    ops_expr: impl Fn(&str) -> String,
) -> std::fmt::Result {
    let path = snode.path(SchemaPathFormat::DATA);
    let type_name = snode.rust_name(Case::Pascal);
    emit!(w, 2, "\"{path}\" => {{")?;
    emit!(w, 3, "use {}::{type_name};", snode.rust_module_path())?;
    emit!(w, 3, "{}", ops_expr(&type_name))?;
    emit!(w, 2, "}},")?;
    Ok(())
}

fn write_ops_map<'a>(
    w: &mut CodeWriter,
    const_name: &str,
    type_str: &str,
    snodes: impl Iterator<Item = SchemaNode<'a>>,
    ops_expr: impl Fn(&str) -> String,
) -> std::fmt::Result {
    emit!(
        w,
        0,
        "const {const_name}: phf::Map<&'static str, {type_str}> = phf_map! {{"
    )?;
    for snode in snodes {
        write_ops_map_entry(w, &snode, &ops_expr)?;
    }
    emit!(w, 0, "}};")?;
    Ok(())
}

fn generate_yang_ops(
    w: &mut CodeWriter,
    modules: &[&str],
    yang_ctx: &Context,
    path_filter: Option<&str>,
) -> std::fmt::Result {
    write_ops_map(
        w,
        "YANG_LIST_OPS",
        "YangListOps<Provider>",
        yang_ctx
            .traverse()
            .filter(|snode| !snode.is_schema_only())
            .filter(|snode| snode.is_status_current())
            .filter(|snode| snode.is_state_list())
            .filter(|snode| snode.in_modules(modules))
            .filter(|snode| {
                !path_filter.is_some_and(|name| snode.has_ancestor_named(name))
            }),
        |name| {
            format!(
                "YangListOps {{ iter: |p, le| {name}::iter(p, le), new: |p, le| Box::new({name}::new(p, le)) }}"
            )
        },
    )?;

    write_ops_map(
        w,
        "YANG_CONTAINER_OPS",
        "YangContainerOps<Provider>",
        yang_ctx
            .traverse()
            .filter(|snode| !snode.is_schema_only())
            .filter(|snode| snode.is_status_current())
            .filter(|snode| snode.is_state_container())
            .filter(|snode| snode.in_modules(modules))
            .filter(|snode| {
                !path_filter.is_some_and(|name| snode.has_ancestor_named(name))
            }),
        |name| {
            format!(
                "YangContainerOps {{ new: |p, le| {name}::new(p, le).map(|c| Box::new(c) as _) }}"
            )
        },
    )?;

    write_ops_map(
        w,
        "YANG_RPC_OPS",
        "YangRpcOps<Provider>",
        yang_ctx
            .traverse()
            .filter(|snode| !snode.is_schema_only())
            .filter(|snode| snode.is_status_current())
            .filter(|snode| snode.in_modules(modules))
            .filter(|snode| {
                !path_filter.is_some_and(|name| snode.has_ancestor_named(name))
            })
            .flat_map(|snode| {
                let actions = snode.actions();
                once(snode).chain(actions)
            })
            .filter(|snode| {
                matches!(
                    snode.kind(),
                    SchemaNodeKind::Rpc | SchemaNodeKind::Action
                )
            }),
        |name| {
            format!(
                "YangRpcOps {{ process: |dnode, provider| {{ \
                 let mut rpc = {name}::parse_input(dnode); \
                 rpc.invoke(provider)?; \
                 rpc.write_output(dnode); \
                 Ok(()) }} }}"
            )
        },
    )?;

    emit!(
        w,
        0,
        "pub const YANG_OPS_STATE: state::YangOps<Provider> = state::YangOps {{"
    )?;
    emit!(w, 2, "list: YANG_LIST_OPS,")?;
    emit!(w, 2, "container: YANG_CONTAINER_OPS,")?;
    emit!(w, 0, "}};")?;
    emit!(
        w,
        0,
        "pub const YANG_OPS_RPC: rpc::YangOps<Provider> = rpc::YangOps {{"
    )?;
    emit!(w, 2, "rpc: YANG_RPC_OPS,")?;
    emit!(w, 0, "}};")?;

    Ok(())
}

fn write_out_dir_file(filename: &str, output: &str) {
    let dst = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = dst.join(filename);
    std::fs::write(out_file, output).expect("Couldn't write to file");
}

// ===== global functions =====

pub fn build_yang_objects(
    yang_ctx: &Context,
    modules: &[&str],
    filename: &str,
) {
    let output = HEADER_YANG_OBJECTS.to_owned();
    let mut w = CodeWriter::new(output, 0);
    for snode in yang_ctx
        .modules(true)
        .flat_map(|module| {
            module
                .data()
                .chain(module.rpcs())
                .chain(module.notifications())
        })
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
    {
        generate_module(&mut w, modules, &snode)
            .expect("Failed to write to stdout");
    }
    write_out_dir_file(filename, &w.output);
}

pub fn build_yang_ops(
    yang_ctx: &Context,
    modules: &[&str],
    path_filter: Option<&str>,
    filename: &str,
) {
    let output = HEADER_YANG_OPS.to_owned();
    let mut w = CodeWriter::new(output, 0);
    generate_yang_ops(&mut w, modules, yang_ctx, path_filter)
        .expect("Failed to write to stdout");
    write_out_dir_file(filename, &w.output);
}
