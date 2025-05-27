//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use check_keyword::CheckKeyword;
use clap::{App, Arg};
use convert_case::{Boundary, Case, Casing};
use holo_northbound::CallbackOp;
use holo_yang as yang;
use yang3::context::Context;
use yang3::schema::{SchemaModule, SchemaNode, SchemaNodeKind};

fn snode_module(snode: &SchemaNode<'_>) -> String {
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

fn snode_module_path(snode: &SchemaNode<'_>) -> String {
    format!("{}::PATH", snode_module(snode))
}

fn snode_normalized_name(snode: &SchemaNode<'_>, case: Case<'_>) -> String {
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
        .without_boundaries(&[Boundary::UPPER_DIGIT, Boundary::LOWER_DIGIT])
        .to_case(case);

    // Handle Rust reserved keywords.
    name = name.into_safe();

    name
}

fn config_callbacks(yang_ctx: &Context, modules: Vec<SchemaModule<'_>>) {
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
        .filter(|snode| modules.iter().any(|module| snode.module() == *module))
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
        println!("        .path({path})");

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

fn rpc_callbacks(yang_ctx: &Context, modules: Vec<SchemaModule<'_>>) {
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
        .filter(|snode| modules.iter().any(|module| snode.module() == *module))
    {
        let path = snode_module_path(&snode);
        if CallbackOp::Rpc.is_valid(&snode) {
            println!(
                "        .path({path})\
               \n        .rpc(|_context, _args| {{\
               \n            Box::pin(async move {{\
               \n                // TODO: implement me!\
               \n                Ok(())\
               \n            }})\
               \n        }})"
            );
        }

        for snode in snode.actions() {
            let path = snode_module_path(&snode);
            if CallbackOp::Rpc.is_valid(&snode) {
                println!(
                    "        .path({path})\
                       \n        .rpc(|_context, _args| {{\
                       \n            Box::pin(async move {{\
                       \n                // TODO: implement me!\
                       \n                Ok(())\
                       \n            }})\
                       \n        }})"
                );
            }
        }
    }

    // Footer.
    println!("        .build()");
    println!("}}");
}

fn state_callbacks(yang_ctx: &Context, modules: Vec<SchemaModule<'_>>) {
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
        .filter(|snode| modules.iter().any(|module| snode.module() == *module))
    {
        let get_iterate = CallbackOp::GetIterate.is_valid(&snode);
        let get_object = CallbackOp::GetObject.is_valid(&snode);
        if !get_iterate && !get_object {
            continue;
        }

        // Print path.
        let indent1 = " ".repeat(2 * 4);
        let indent2 = " ".repeat(3 * 4);
        let indent3 = " ".repeat(4 * 4);
        let path = snode_module_path(&snode);
        println!("        .path({path})");

        if get_iterate {
            println!(
                "        .get_iterate(|_context, _args| {{\
               \n            // TODO: implement me!\
               \n            None\
               \n        }})"
            );
        }
        if get_object {
            let struct_name = snode_normalized_name(&snode, Case::Pascal);
            println!("{indent1}.get_object(|_context, _args| {{");
            println!(
                "{}use {}::{};",
                indent2,
                snode_module(&snode),
                struct_name
            );
            println!("{indent2}Box::new({struct_name} {{");
            for snode in snode
                .children()
                .filter(|snode| {
                    matches!(
                        snode.kind(),
                        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
                    )
                })
                .filter(|snode| snode.is_state() || snode.is_list_key())
            {
                let field_name = snode_normalized_name(&snode, Case::Snake);
                println!("{indent3}{field_name}: todo!(),");
            }
            println!("{indent2}}})");
            println!("{indent1}}})");
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
                .multiple(true)
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

    let module_names = matches.values_of("MODULE").unwrap().collect::<Vec<_>>();
    let cb_type = matches.value_of("CALLBACK_TYPE").unwrap();

    // Initialize context.
    let mut yang_ctx = yang::new_context();

    // Load base YANG modules that define features used by other modules.
    yang::load_module(&mut yang_ctx, "ietf-bfd-types");
    yang::load_module(&mut yang_ctx, "iana-bgp-types");

    // Load provided YANG module.
    for module_name in &module_names {
        yang::load_module(&mut yang_ctx, module_name);
        yang::load_deviations(&mut yang_ctx, module_name);
    }

    // Generate callbacks.
    let modules = module_names
        .into_iter()
        .map(|module_name| {
            yang_ctx
                .get_module_latest(module_name)
                .expect("Failed to find loaded module")
        })
        .collect::<Vec<_>>();
    match cb_type {
        "config" => config_callbacks(&yang_ctx, modules),
        "rpc" => rpc_callbacks(&yang_ctx, modules),
        "state" => state_callbacks(&yang_ctx, modules),
        _ => panic!("Unknown callback type"),
    }
}
