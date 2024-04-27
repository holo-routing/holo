//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![feature(let_chains)]

use std::env;
use std::fmt::Write;
use std::path::PathBuf;

use check_keyword::CheckKeyword;
use convert_case::{Boundary, Case, Casing};
use holo_yang as yang;
use holo_yang::YANG_IMPLEMENTED_MODULES;
use yang2::schema::{DataValue, SchemaNode, SchemaNodeKind, SchemaPathFormat};

fn snode_normalized_name(snode: &SchemaNode<'_>, case: Case) -> String {
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

    // Case conversion.
    name = name
        .from_case(Case::Kebab)
        .without_boundaries(&[Boundary::DigitUpper, Boundary::DigitLower])
        .to_case(case);

    // Handle Rust reserved keywords.
    name = name.into_safe();

    name
}

fn generate_module(output: &mut String, snode: &SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);

    if !snode.is_schema_only() {
        let name = snode_normalized_name(snode, Case::Snake);

        // Generate module.
        writeln!(output, "{}pub mod {} {{", indent, name).unwrap();
        writeln!(output, "{}  use super::*;", indent).unwrap();

        // Generate paths.
        generate_paths(output, snode, level);

        // Generate default value (if any).
        if let Some(default) = snode.default_value() {
            generate_default_value(output, snode, default, level);
        }

        // Generate "list_keys()" function.
        if snode.kind() == SchemaNodeKind::List {
            generate_list_keys_fn(output, snode, level);
        }

        // Generate object struct.
        if matches!(
            snode.kind(),
            SchemaNodeKind::Container
                | SchemaNodeKind::List
                | SchemaNodeKind::Notification
        ) {
            generate_object_struct(output, snode, level);
        }
    }

    // Iterate over child nodes.
    if let Some(actions) = snode.actions() {
        for snode in actions {
            generate_module(output, &snode, level + 1);
        }
    }
    if let Some(notifications) = snode.notifications() {
        for snode in notifications {
            generate_module(output, &snode, level + 1);
        }
    }
    for snode in snode.children().filter(|snode| snode.is_status_current()) {
        writeln!(output).unwrap();
        generate_module(output, &snode, level + 1);
    }

    if !snode.is_schema_only() {
        // Close generated module.
        writeln!(output, "{}}}", indent).unwrap();
    }
}

fn generate_paths(output: &mut String, snode: &SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);

    // Generate data path.
    let path = snode.path(SchemaPathFormat::DATA);
    writeln!(
        output,
        "{}  pub const PATH: YangPath = YangPath::new(\"{}\");",
        indent, path
    )
    .unwrap();

    // Generate data path relative to the nearest parent list.
    if let Some(snode_parent_list) = snode
        .ancestors()
        .find(|snode| snode.kind() == SchemaNodeKind::List)
    {
        let path_parent_list = snode_parent_list.path(SchemaPathFormat::DATA);
        let relative_path = &path[path_parent_list.len()..];

        writeln!(
            output,
            "{}  pub const RELATIVE_PATH: &str = \"{}\";",
            indent, relative_path
        )
        .unwrap();
    }
}

fn generate_default_value(
    output: &mut String,
    snode: &SchemaNode<'_>,
    default: DataValue,
    level: usize,
) {
    let indent = " ".repeat(level * 2);

    let dflt_type = match default {
        DataValue::Uint8(_) => "u8",
        DataValue::Uint16(_) => "u16",
        DataValue::Uint32(_) => "u32",
        DataValue::Uint64(_) => "u64",
        DataValue::Bool(_) => "bool",
        DataValue::Empty => unreachable!(),
        DataValue::Int8(_) => "i8",
        DataValue::Int16(_) => "i16",
        DataValue::Int32(_) => "i32",
        DataValue::Int64(_) => "i64",
        // TODO: handle derived types.
        DataValue::Other(_) => "&str",
    };
    let mut dflt_value = snode.default_value_canonical().unwrap().to_owned();
    if matches!(default, DataValue::Other(_)) {
        dflt_value = format!("\"{}\"", dflt_value);
    }

    writeln!(
        output,
        "{}  pub const DFLT: {} = {};",
        indent, dflt_type, dflt_value,
    )
    .unwrap();
}

fn generate_list_keys_fn(
    output: &mut String,
    snode: &SchemaNode<'_>,
    level: usize,
) {
    let indent = " ".repeat(level * 2);

    let args = snode
        .list_keys()
        .map(|snode| {
            // TODO: require real types for extra type safety.
            format!(
                "{}: impl ToString",
                snode_normalized_name(&snode, Case::Snake)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let fmt_string = snode
        .list_keys()
        .map(|snode| format!("[{}='{{}}']", snode.name()))
        .collect::<Vec<_>>()
        .join("");
    let fmt_args = snode
        .list_keys()
        .map(|snode| {
            format!(
                "{}.to_string()",
                snode_normalized_name(&snode, Case::Snake)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    writeln!(
        output,
        "{}  #[allow(clippy::useless_format)]\n\
             {}  pub fn list_keys({}) -> String {{\n\
             {}    format!(\"{}\", {})\n\
             {}  }}",
        indent, indent, args, indent, fmt_string, fmt_args, indent,
    )
    .unwrap();
}

fn generate_object_struct(
    output: &mut String,
    snode: &SchemaNode<'_>,
    level: usize,
) {
    let indent = " ".repeat(level * 2);

    let struct_name = snode_normalized_name(snode, Case::Pascal);
    writeln!(output, "{}  pub struct {}<'a> {{", indent, struct_name).unwrap();
    let mut empty = true;
    for snode in snode
        .children()
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.kind() != SchemaNodeKind::List)
        .filter(|snode| snode.kind() != SchemaNodeKind::LeafList)
    {
        empty = false;
        if snode.kind() == SchemaNodeKind::Choice {
            for snode in snode
                .children()
                .filter(|snode| snode.is_status_current())
                .flat_map(|snode| snode.children())
            {
                generate_field(output, &snode, level + 1);
            }
        } else {
            generate_field(output, &snode, level + 1);
        }
    }
    if empty {
        writeln!(
            output,
            "{}    _marker: std::marker::PhantomData<&'a str>,",
            indent
        )
        .unwrap();
    }
    writeln!(output, "{}  }}", indent).unwrap();

    // Generate YangObject trait implementation.
    writeln!(output).unwrap();
    writeln!(
        output,
        "{}  impl<'a> YangObject for {}<'a> {{",
        indent, struct_name
    )
    .unwrap();
    writeln!(
        output,
        "{}    fn init_data_node(&self, dnode: &mut DataNodeRef<'_>) {{",
        indent
    )
    .unwrap();
    for snode in snode
        .children()
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.kind() != SchemaNodeKind::List)
        .filter(|snode| snode.kind() != SchemaNodeKind::LeafList)
    {
        if snode.kind() == SchemaNodeKind::Choice {
            for snode in snode
                .children()
                .filter(|snode| snode.is_status_current())
                .flat_map(|snode| snode.children())
            {
                generate_field_to_yang(output, &snode, level + 2);
            }
        } else {
            generate_field_to_yang(output, &snode, level + 2);
        }
    }
    writeln!(output, "{}    }}", indent).unwrap();
    writeln!(output, "{}  }}", indent).unwrap();
}

fn generate_field(output: &mut String, snode: &SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);
    let field_name = snode_normalized_name(snode, Case::Snake);
    if snode.kind() == SchemaNodeKind::Container {
        writeln!(
            output,
            "{}  pub {}: Option<{}::{}<'a>>,",
            indent,
            field_name,
            snode_normalized_name(snode, Case::Snake),
            snode_normalized_name(snode, Case::Pascal)
        )
        .unwrap();
    } else {
        writeln!(
            output,
            "{}  pub {}: Option<Cow<'a, str>>,",
            indent, field_name
        )
        .unwrap();
    }
}

fn generate_field_to_yang(
    output: &mut String,
    snode: &SchemaNode<'_>,
    level: usize,
) {
    let indent = " ".repeat(level * 2);
    let field_name = snode_normalized_name(snode, Case::Snake);
    let module = snode.module();

    writeln!(
        output,
        "{}  if let Some({}) = &self.{} {{",
        indent, field_name, field_name
    )
    .unwrap();

    if let Some(parent_snode) = snode.ancestors().next()
        && snode.module() != parent_snode.module()
    {
        writeln!(
            output,
            "{}    let module = YANG_CTX.get().unwrap().get_module_latest(\"{}\").unwrap();",
            indent,
            module.name()
        )
        .unwrap();
        writeln!(output, "{}    let module = Some(&module);", indent,).unwrap();
    } else {
        writeln!(output, "{}    let module = None;", indent,).unwrap();
    }

    if snode.kind() == SchemaNodeKind::Container {
        writeln!(
            output,
            "{}    let mut dnode = dnode.new_inner(module, \"{}\").unwrap();",
            indent,
            snode.name()
        )
        .unwrap();
        writeln!(
            output,
            "{}    {}.init_data_node(&mut dnode);",
            indent, field_name
        )
        .unwrap();
    } else {
        writeln!(
            output,
            "{}    dnode.new_term(module, \"{}\", {}).unwrap();",
            indent,
            snode.name(),
            field_name
        )
        .unwrap();
    }

    writeln!(output, "{}  }}", indent).unwrap();
}

fn main() {
    let dst = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = dst.join("paths.rs");

    // Create YANG context and load all implemented modules.
    let mut yang_ctx = yang::new_context();
    for module_name in YANG_IMPLEMENTED_MODULES.iter() {
        yang::load_module(&mut yang_ctx, module_name);
    }
    for module_name in YANG_IMPLEMENTED_MODULES.iter().rev() {
        yang::load_deviations(&mut yang_ctx, module_name);
    }

    // Generate file header.
    let mut output = String::new();
    writeln!(output, "use std::borrow::Cow;").unwrap();
    writeln!(output, "use holo_yang::{{YangObject, YangPath, YANG_CTX}};")
        .unwrap();
    writeln!(output, "use yang2::data::DataNodeRef;").unwrap();
    writeln!(output).unwrap();

    // Generate modules.
    for snode in yang_ctx
        .modules(true)
        .flat_map(|module| {
            let data = module.data();
            let rpcs = module.rpcs();
            let notifications = module.notifications();
            data.chain(rpcs).chain(notifications)
        })
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
    {
        generate_module(&mut output, &snode, 0);
    }

    // Write path modules to file.
    std::fs::write(out_file, output).expect("Couldn't write to file");
}
