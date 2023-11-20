//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt::Write;

use check_keyword::CheckKeyword;
use clap::{App, Arg};
use holo_northbound::CallbackOp;
use holo_yang as yang;
use yang2::context::Context;
use yang2::schema::{DataValueType, SchemaModule, SchemaNode, SchemaNodeKind};

fn snode_module_path(snode: &SchemaNode<'_>) -> String {
    let snodes = snode.inclusive_ancestors().collect::<Vec<_>>();
    let mut path = snodes
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
        .join("::");
    write!(path, "::PATH").unwrap();
    path
}

fn config_callbacks(yang_ctx: &Context, module: SchemaModule<'_>) {
    // Header.
    println!(
        "\
        {{\
        \n    CallbacksBuilder::<Context>::default()"
    );

    // Callbacks.
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.module() == module)
    {
        let create = CallbackOp::Create.is_valid(&snode);
        let modify = CallbackOp::Modify.is_valid(&snode);
        let delete = CallbackOp::Delete.is_valid(&snode);
        let lookup = CallbackOp::Lookup.is_valid(&snode);
        if !create && !modify && !delete && !lookup {
            continue;
        }

        // Print path.
        let path = snode_module_path(&snode);
        println!("        .path({})", path);

        // Print callbacks.
        if create {
            println!(
                "        .create_apply(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n        }})"
            );
        }
        if modify {
            println!(
                "        .modify_apply(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n        }})"
            );
        }
        if delete {
            println!(
                "        .delete_apply(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n        }})"
            );
        }
        if lookup {
            println!(
                "        .lookup(|_context, _list_entry, _dnode| {{\
               \n            // TODO: implement me!\
               \n            todo!();\
               \n        }})"
            );
        }
    }

    // Footer.
    println!("        .build()");
    println!("}}");
}

fn rpc_callbacks(yang_ctx: &Context, module: SchemaModule<'_>) {
    // Header.
    println!(
        "\
        {{\
        \n    CallbacksBuilder::<Context>::default()"
    );

    // Callbacks.
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.module() == module)
    {
        let path = snode_module_path(&snode);

        if CallbackOp::Rpc.is_valid(&snode) {
            println!(
                "        .path({})\
               \n        .rpc(|_context, _args| {{\
               \n            Box::pin(async move {{\
               \n                // TODO: implement me!\
               \n                Ok(())\
               \n            }})\
               \n        }})",
                path
            );
        }
    }

    // Footer.
    println!("        .build()");
    println!("}}");
}

fn state_callbacks(yang_ctx: &Context, module: SchemaModule<'_>) {
    // Header.
    println!(
        "\
        {{\
        \n    CallbacksBuilder::<Context>::default()"
    );

    // Callbacks.
    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.module() == module)
    {
        let get_iterate = CallbackOp::GetIterate.is_valid(&snode);
        let get_element = CallbackOp::GetElement.is_valid(&snode);
        if !get_iterate && !get_element {
            continue;
        }

        // Print path.
        let path = snode_module_path(&snode);
        println!("        .path({})", path);

        if get_iterate {
            println!(
                "        .get_iterate(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n            None\
               \n        }})"
            );
        }
        if get_element {
            let suffix = if snode.kind() == SchemaNodeKind::Container {
                "container"
            } else {
                match snode.base_type().unwrap() {
                    DataValueType::Unknown => panic!("Unknown leaf type"),
                    // TODO
                    DataValueType::Binary => "string",
                    DataValueType::Uint8 => "u8",
                    DataValueType::Uint16 => "u16",
                    DataValueType::Uint32 => "u32",
                    DataValueType::Uint64 => "u64",
                    DataValueType::String => "string",
                    // TODO
                    DataValueType::Bits => "string",
                    DataValueType::Bool => "bool",
                    // TODO
                    DataValueType::Dec64 => "string",
                    // TODO
                    DataValueType::Empty => "empty",
                    // TODO
                    DataValueType::Enum => "string",
                    // TODO
                    DataValueType::IdentityRef => "string",
                    // TODO
                    DataValueType::InstanceId => "string",
                    // TODO
                    DataValueType::LeafRef => "string",
                    // TODO
                    DataValueType::Union => "string",
                    DataValueType::Int8 => "i8",
                    DataValueType::Int16 => "i16",
                    DataValueType::Int32 => "i32",
                    DataValueType::Int64 => "i64",
                }
            };

            println!(
                "        .get_element_{}(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n            None\
               \n        }})",
                suffix
            );
        }
    }

    // Footer.
    println!("        .build()");
    println!("}}");
}

fn main() {
    // Parse command-line parameters.
    let matches = App::new("Generate YANG deviations")
        .about(
            "Parses a YANG module and generate all required northbound \
             callbacks for its nodes",
        )
        .arg(
            Arg::with_name("MODULE")
                .long("module")
                .help("YANG module name")
                .value_name("MODULE")
                .required(true),
        )
        .arg(
            Arg::with_name("CALLBACK_TYPE")
                .long("type")
                .help("Callback type (config/state/rpc)")
                .value_name("CALLBACK_TYPE")
                .required(true),
        )
        .get_matches();

    let module_name = matches.value_of("MODULE").unwrap();
    let cb_type = matches.value_of("CALLBACK_TYPE").unwrap();

    // Initialize context.
    let mut yang_ctx = yang::new_context();

    // Load base YANG modules that define features used by other modules.
    yang::load_module(&mut yang_ctx, "ietf-bfd-types");

    // Load provided YANG module.
    yang::load_module(&mut yang_ctx, module_name);
    yang::load_deviations(&mut yang_ctx, module_name);
    let module = yang_ctx
        .get_module_latest(module_name)
        .expect("Failed to find loaded module");

    // Check callback type.
    match cb_type {
        "config" => config_callbacks(&yang_ctx, module),
        "rpc" => rpc_callbacks(&yang_ctx, module),
        "state" => state_callbacks(&yang_ctx, module),
        _ => panic!("Unknown callback type"),
    }
}
