//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::env;
use std::fmt::Write;
use std::path::PathBuf;

use holo_yang as yang;
use holo_yang::YANG_IMPLEMENTED_MODULES;
use yang2::schema::{DataValue, SchemaNode, SchemaNodeKind, SchemaPathFormat};

fn snode_normalized_name(snode: &SchemaNode<'_>) -> String {
    let mut name = snode.name().to_owned();

    // Replace hyphens by underscores.
    name = str::replace(&name, "-", "_");

    // Handle Rust reserved keywords.
    if name == "type" {
        name = "r#type".to_owned();
    }

    name
}

fn generate_paths(output: &mut String, snode: SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);

    if !snode.is_schema_only() {
        let name = snode_normalized_name(&snode);

        // Generate module.
        writeln!(output, "{}pub mod {} {{", indent, name).unwrap();
        writeln!(output, "{}  use super::YangPath;", indent).unwrap();

        // Generate data path.
        let path = snode.path(SchemaPathFormat::DATA);
        writeln!(
            output,
            "{}  pub const PATH: YangPath = YangPath::new(\"{}\");",
            indent, path
        )
        .unwrap();

        // Generate default value (if any).
        if let Some(default) = snode.default_value() {
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
            let mut dflt_value =
                snode.default_value_canonical().unwrap().to_owned();
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

        // Generate "list_keys()" function.
        if snode.kind() == SchemaNodeKind::List {
            let args = snode
                .list_keys()
                .map(|snode| {
                    // TODO: require real types for extra type safety.
                    format!("{}: impl ToString", snode_normalized_name(&snode))
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
                    format!("{}.to_string()", snode_normalized_name(&snode))
                })
                .collect::<Vec<_>>()
                .join(", ");

            writeln!(
                output,
                "{}  #[allow(clippy::useless_format)]\n\
             {}  pub fn list_keys({}) -> String {{\n\
             {}      format!(\"{}\", {})\n\
             {}  }}",
                indent, indent, args, indent, fmt_string, fmt_args, indent,
            )
            .unwrap();
        }
    }

    // Iterate over child nodes.
    for snode in snode.children().filter(|snode| snode.is_status_current()) {
        writeln!(output).unwrap();
        generate_paths(output, snode, level + 1);
    }

    if !snode.is_schema_only() {
        // Close generated module.
        writeln!(output, "{}}}", indent).unwrap();
    }
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
    writeln!(output, "use holo_yang::YangPath;").unwrap();

    // Generate paths.
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
        generate_paths(&mut output, snode, 0);
    }

    // Write path modules to file.
    std::fs::write(out_file, output).expect("Couldn't write to file");
}
