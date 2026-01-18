//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use clap::{App, Arg};
use holo_northbound::configuration::CallbackOp;
use holo_northbound::yang_codegen::snode_rust_module_path;
use holo_yang as yang;
use yang4::context::Context;
use yang4::schema::SchemaModule;

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
        let path = format!("{}::PATH", snode_rust_module_path(&snode));
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
        .get_matches();

    let module_names = matches.values_of("MODULE").unwrap().collect::<Vec<_>>();

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
    config_callbacks(&yang_ctx, modules);
}
