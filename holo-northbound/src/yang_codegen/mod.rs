//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

pub mod struct_builder;
pub mod types;
pub mod yang;

use std::env;
use std::fmt::Write;
use std::path::PathBuf;

use check_keyword::CheckKeyword;
use convert_case::{Boundary, Case, Casing};
use yang4::context::Context;
use yang4::schema::{
    DataValueType, SchemaNode, SchemaNodeKind, SchemaPathFormat,
};

use crate::yang_codegen::struct_builder::StructBuilder;

const HEADER_YANG_OBJECTS: &str = r#"
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use holo_northbound::yang_codegen::yang;
use holo_yang::{YangObject, YangPath, YANG_CTX};
use yang4::data::DataNodeRef;
use yang4::schema::SchemaModule;

"#;

const HEADER_YANG_OPS: &str = r#"
use holo_northbound::state::{self, YangList, YangListOps, YangContainer, YangContainerOps};
use holo_northbound::rpc::{self, YangRpc, YangRpcOps};
use phf::phf_map;
use super::*;

"#;

// ===== helper functions =====

fn generate_module(
    output: &mut String,
    modules: &[&str],
    snode: &SchemaNode<'_>,
    level: usize,
) -> std::fmt::Result {
    let indent = " ".repeat(level * 2);
    let gen_module = !snode.is_schema_only()
        && (snode_module_matches(snode, modules)
            || matches!(
                snode.path(SchemaPathFormat::DATA).as_ref(),
                "/ietf-routing:routing"
                    | "/ietf-routing:routing/control-plane-protocols"
                    | "/ietf-routing:routing/control-plane-protocols/control-plane-protocol"
                    | "/ietf-interfaces:interfaces"
                    | "/ietf-interfaces:interfaces/interface"
                    | "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4"
                    | "/ietf-interfaces:interfaces/interface/ietf-ip:ipv6"
            ))
        && (snode.is_config()
            || matches!(
                snode.kind(),
                SchemaNodeKind::Container
                    | SchemaNodeKind::List
                    | SchemaNodeKind::Action
                    | SchemaNodeKind::Rpc
                    | SchemaNodeKind::Notification
            ));

    if gen_module {
        let name = snode_rust_name(snode, Case::Snake);

        // Generate module.
        writeln!(output, "{indent}pub mod {name} {{")?;
        writeln!(output, "{indent}  use super::*;")?;

        // Generate paths.
        generate_paths(output, snode, level)?;

        // Generate default value (if any).
        if snode.is_config()
            && let Ok(Some(dflt_value)) = snode.default_value_canonical()
            && let Some(leaf_type) = snode.leaf_type()
        {
            let dflt_type = leaf_type.base_type();
            let dflt_value = dflt_value.to_owned();
            generate_default_value(output, dflt_type, dflt_value, level)?;
        }

        // Generate object struct.
        match snode.kind() {
            SchemaNodeKind::Container | SchemaNodeKind::Notification => {
                let builder = StructBuilder::new(level, snode.clone());
                if !builder.fields.is_empty() {
                    builder.generate(output)?;
                }
            }
            SchemaNodeKind::List
            | SchemaNodeKind::Rpc
            | SchemaNodeKind::Action => {
                let builder = StructBuilder::new(level, snode.clone());
                builder.generate(output)?;
            }
            _ => (),
        }
    }

    // Iterate over child nodes.
    for snode in snode.actions() {
        generate_module(output, modules, &snode, level + 1)?;
    }
    for snode in snode.notifications() {
        generate_module(output, modules, &snode, level + 1)?;
    }
    for snode in snode.children().filter(|snode| snode.is_status_current()) {
        generate_module(output, modules, &snode, level + 1)?;
    }

    if gen_module {
        // Close generated module.
        writeln!(output, "{indent}}}")?;
    }

    Ok(())
}

fn generate_paths(
    output: &mut String,
    snode: &SchemaNode<'_>,
    level: usize,
) -> std::fmt::Result {
    let indent = " ".repeat(level * 2);

    // Generate data path.
    let path = snode.path(SchemaPathFormat::DATA);
    writeln!(
        output,
        "{indent}  pub const PATH: YangPath = YangPath::new(\"{path}\");"
    )?;

    // For notifications, generate data path relative to the nearest parent
    // list.
    if snode.kind() == SchemaNodeKind::Notification
        && let Some(snode_parent_list) = snode
            .ancestors()
            .find(|snode| snode.kind() == SchemaNodeKind::List)
    {
        let path_parent_list = snode_parent_list.path(SchemaPathFormat::DATA);
        let relative_path = &path[path_parent_list.len()..];

        writeln!(
            output,
            "{indent}  pub const RELATIVE_PATH: &str = \"{relative_path}\";"
        )?;
    }

    Ok(())
}

fn generate_default_value(
    output: &mut String,
    dflt_type: DataValueType,
    mut dflt_value: String,
    level: usize,
) -> std::fmt::Result {
    let indent = " ".repeat(level * 2);

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

    writeln!(
        output,
        "{indent}  pub const DFLT: {dflt_type} = {dflt_value};",
    )?;

    Ok(())
}

fn generate_yang_ops(
    output: &mut String,
    modules: &[&str],
    yang_ctx: &Context,
    path_filter: Option<&str>,
) -> std::fmt::Result {
    writeln!(
        output,
        "const YANG_LIST_OPS: phf::Map<&'static str, YangListOps<Provider>> = phf_map! {{"
    )?;
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode_is_state_list(snode))
        .filter(|snode| snode_module_matches(snode, modules))
        .filter(|snode| !snode_path_filter(snode, path_filter))
    {
        let path = snode.path(SchemaPathFormat::DATA);
        let list = snode_rust_name(&snode, Case::Pascal);
        writeln!(output, "    \"{}\" => {{", path)?;
        writeln!(
            output,
            "      use {}::{};",
            snode_rust_module_path(&snode),
            list
        )?;
        writeln!(
            output,
            "      YangListOps {{ iter: |p, le| {}::iter(p, le), new: |p, le| Box::new({}::new(p, le)) }}",
            list, list,
        )?;
        writeln!(output, "    }},")?;
    }
    writeln!(output, "}};")?;

    writeln!(
        output,
        "const YANG_CONTAINER_OPS: phf::Map<&'static str, YangContainerOps<Provider>> = phf_map! {{"
    )?;
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode_is_state_container(snode))
        .filter(|snode| snode_module_matches(snode, modules))
        .filter(|snode| !snode_path_filter(snode, path_filter))
    {
        let path = snode.path(SchemaPathFormat::DATA);
        let container = snode_rust_name(&snode, Case::Pascal);
        writeln!(output, "    \"{}\" => {{", path)?;
        writeln!(
            output,
            "      use {}::{};",
            snode_rust_module_path(&snode),
            container
        )?;
        writeln!(
            output,
            "      YangContainerOps {{ new: |p, le| {}::new(p, le).map(|c| Box::new(c) as _) }}",
            container
        )?;
        writeln!(output, "    }},")?;
    }
    writeln!(output, "}};")?;

    writeln!(
        output,
        "const YANG_RPC_OPS: phf::Map<&'static str, YangRpcOps<Provider>> = phf_map! {{"
    )?;
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| {
            matches!(snode.kind(), SchemaNodeKind::Rpc | SchemaNodeKind::Action)
        })
        .filter(|snode| snode_module_matches(snode, modules))
        .filter(|snode| !snode_path_filter(snode, path_filter))
    {
        let path = snode.path(SchemaPathFormat::DATA);
        let container = snode_rust_name(&snode, Case::Pascal);
        writeln!(output, "    \"{}\" => {{", path)?;
        writeln!(
            output,
            "      use {}::{};",
            snode_rust_module_path(&snode),
            container
        )?;
        writeln!(
            output,
            "      YangRpcOps {{ invoke: {}::invoke }}",
            container
        )?;
        writeln!(output, "    }},")?;
    }
    writeln!(output, "}};")?;

    writeln!(
        output,
        "
pub const YANG_OPS_STATE: state::YangOps<Provider> = state::YangOps {{
    list: YANG_LIST_OPS,
    container: YANG_CONTAINER_OPS,
}};
pub const YANG_OPS_RPC: rpc::YangOps<Provider> = rpc::YangOps {{
    rpc: YANG_RPC_OPS,
}};"
    )?;

    Ok(())
}

fn snode_contains_leaf_or_leaflist(snode: &SchemaNode<'_>) -> bool {
    match snode.kind() {
        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => true,
        SchemaNodeKind::Choice => snode
            .children()
            .flat_map(|snode| snode.children())
            .any(|snode| snode_contains_leaf_or_leaflist(&snode)),
        _ => false,
    }
}

fn snode_path_filter(snode: &SchemaNode<'_>, name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    snode.ancestors().any(|ancestor| ancestor.name() == name)
}

fn snode_module_matches(snode: &SchemaNode<'_>, modules: &[&str]) -> bool {
    modules
        .iter()
        .any(|module| *module == snode.module().name())
}

fn write_out_dir_file(filename: &str, output: String) {
    let dst = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = dst.join(filename);
    std::fs::write(out_file, output).expect("Couldn't write to file");
}

// ===== global functions =====

pub fn snode_rust_name(snode: &SchemaNode<'_>, case: Case<'_>) -> String {
    let mut name = snode.name().to_owned();

    // HACK: distinguish nodes with the same names but different namespaces.
    if matches!(
        snode.name(),
        "destination-address"
            | "destination-prefix"
            | "address"
            | "next-hop-address"
    ) {
        if snode.module().name() == "ietf-ipv4-unicast-routing" {
            name.insert_str(0, "ipv4-");
        }
        if snode.module().name() == "ietf-ipv6-unicast-routing" {
            name.insert_str(0, "ipv6-");
        }
        if snode.module().name() == "ietf-mpls" {
            name.insert_str(0, "mpls-");
        }
    }
    if let Some(snode_parent) = snode.ancestors().next()
        && snode_parent.module().name() == "ietf-routing"
    {
        if snode.module().name() == "ietf-ospf"
            && matches!(snode.name(), "route-type" | "tag" | "metric")
        {
            name.insert_str(0, "ospf-");
        }
        if snode.module().name() == "ietf-isis"
            && matches!(snode.name(), "route-type" | "tag" | "metric")
        {
            name.insert_str(0, "isis-");
        }
    }

    // Case conversion.
    name = name
        .from_case(Case::Kebab)
        .remove_boundaries(&[Boundary::UpperDigit, Boundary::LowerDigit])
        .to_case(case);

    // Handle Rust reserved keywords.
    name = name.into_safe();

    name
}

pub fn snode_rust_module_path(snode: &SchemaNode<'_>) -> String {
    let snodes = snode.inclusive_ancestors().collect::<Vec<_>>();
    snodes
        .iter()
        .rev()
        .filter(|snode| !snode.is_schema_only())
        .map(|snode| {
            let mut name = snode.name().to_owned();
            // Replace hyphens by underscores.
            name = str::replace(&name, "-", "_");
            // Handle Rust reserved keywords.
            name.into_safe()
        })
        .collect::<Vec<String>>()
        .join("::")
}

pub fn snode_is_state_list(snode: &SchemaNode<'_>) -> bool {
    if snode.kind() != SchemaNodeKind::List {
        return false;
    }

    if !snode.is_config() && !snode.is_state() {
        return false;
    }

    snode.traverse().any(|snode| snode.is_state())
}

pub fn snode_is_state_container(snode: &SchemaNode<'_>) -> bool {
    if snode.kind() != SchemaNodeKind::Container {
        return false;
    }

    if !snode.traverse().any(|snode| snode.is_state()) {
        return false;
    }

    snode.children().any(|snode| {
        if !snode.is_state() {
            return false;
        }

        snode_contains_leaf_or_leaflist(&snode)
    })
}

pub fn build_yang_objects(
    yang_ctx: &Context,
    modules: &[&str],
    filename: &str,
) {
    // Generate file header.
    let mut output = HEADER_YANG_OBJECTS.to_owned();

    // Generate modules.
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
        generate_module(&mut output, modules, &snode, 0)
            .expect("Failed to write to stdout");
    }

    write_out_dir_file(filename, output);
}

pub fn build_yang_ops(
    yang_ctx: &Context,
    modules: &[&str],
    path_filter: Option<&str>,
    filename: &str,
) {
    // Generate file header.
    let mut output = HEADER_YANG_OPS.to_owned();

    // Generate YANG ops.
    generate_yang_ops(&mut output, modules, yang_ctx, path_filter)
        .expect("Failed to write to stdout");

    write_out_dir_file(filename, output);
}
