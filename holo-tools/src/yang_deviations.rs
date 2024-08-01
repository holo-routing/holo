//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use clap::{App, Arg};
use holo_yang as yang;
use yang3::schema::SchemaNode;

// Generate fully-prefixed schema path.
fn gen_fully_prefixed_path(snode: &SchemaNode<'_>) -> String {
    let mut path = String::new();

    for snode in snode
        .inclusive_ancestors()
        .collect::<Vec<SchemaNode<'_>>>()
        .iter()
        .rev()
    {
        // Append node name prefixed by its module prefix.
        path += &format!("/{}:{}", snode.module().prefix(), snode.name());
    }

    path
}

fn main() {
    // Parse command-line parameters.
    let matches = App::new("Generate YANG deviations")
        .about(
            "Parses a YANG module and generate a \"not-supported\" deviation \
             for all of its nodes",
        )
        .arg(
            Arg::with_name("MODULE")
                .help("YANG module name")
                .required(true)
                .index(1),
        )
        .get_matches();

    let module_name = matches.value_of("MODULE").unwrap();

    // Initialize YANG context.
    let mut yang_ctx = yang::new_context();

    // Load base YANG modules that define features used by other modules.
    yang::load_module(&mut yang_ctx, "ietf-bfd-types");
    yang::load_module(&mut yang_ctx, "iana-bgp-types");

    // Load requested YANG module.
    yang::load_module(&mut yang_ctx, module_name);
    let module = yang_ctx
        .get_module_latest(module_name)
        .expect("Failed to find loaded module");

    // Header.
    println!(
        "\
        module holo-{}-deviations {{\
        \n  yang-version 1.1;\
        \n  namespace \"http://holo-routing.org/yang/holo-{}-deviations\";\
        \n  prefix holo-{}-deviations;\
        \n\
        \n  import {} {{\
        \n    prefix {};\
        \n  }}\
        \n\
        \n  organization\
        \n    \"Holo Routing Stack\";\
        \n\
        \n  description\
        \n    \"This module defines deviation statements for the {}\
        \n     module.\";",
        module_name,
        module_name,
        module_name,
        module_name,
        module.prefix(),
        module_name
    );

    // "not-supported" deviations.
    fn print_deviation(snode: &SchemaNode<'_>) {
        println!(
            "\
        \n  /*\
        \n  deviation \"{}\" {{\
        \n    deviate not-supported;\
        \n  }}\
        \n  */",
            gen_fully_prefixed_path(snode),
        );
    }
    for snode in yang_ctx
        .traverse()
        .filter(|snode| snode.is_status_current())
        .filter(|snode| snode.module() == module)
    {
        print_deviation(&snode);
        if let Some(actions) = snode.actions() {
            for snode in actions.into_iter().flat_map(|snode| snode.traverse())
            {
                print_deviation(&snode);
            }
        }
        if let Some(notifications) = snode.notifications() {
            for snode in
                notifications.into_iter().flat_map(|snode| snode.traverse())
            {
                print_deviation(&snode);
            }
        }
    }

    // Footer.
    println!("}}");
}
