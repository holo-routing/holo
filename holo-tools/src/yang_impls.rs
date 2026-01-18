//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use clap::{App, Arg};
use convert_case::Case;
use holo_northbound::yang_codegen::struct_builder::StructBuilder;
use holo_northbound::yang_codegen::types::leaf_type_is_builtin;
use holo_northbound::yang_codegen::{
    snode_is_state_container, snode_is_state_list, snode_rust_module_path,
    snode_rust_name,
};
use holo_yang as yang;
use yang4::context::Context;
use yang4::schema::{SchemaModule, SchemaNodeKind};

fn gen_impl_blocks_rpc(yang_ctx: &Context, modules: Vec<SchemaModule<'_>>) {
    let indent1 = " ".repeat(4);
    let indent2 = " ".repeat(2 * 4);

    for snode in yang_ctx
        .traverse()
        .filter(|snode| snode.is_status_current())
        .filter(|snode| modules.iter().any(|module| snode.module() == *module))
    {
        if snode.kind() == SchemaNodeKind::Rpc {
            let module = snode_rust_module_path(&snode);
            let struct_name = snode_rust_name(&snode, Case::Pascal);
            println!(
                "impl YangRpc<Provider> for yang::{module}::{struct_name}"
            );
            println!("{{");
            println!(
                "{indent1}fn invoke(_provider: &mut Provider, _data: &mut DataTree<'static>, _rpc_path: &str) -> Result<(), String> {{"
            );
            println!("{indent2}Ok(())");
            println!("{indent1}}}");
            println!("}}");
            println!();
        }

        for snode in snode.actions() {
            let module = snode_rust_module_path(&snode);
            let struct_name = snode_rust_name(&snode, Case::Pascal);
            println!(
                "impl YangRpc<Provider> for yang::{module}::{struct_name}"
            );
            println!("{{");
            println!(
                "{indent1}fn invoke(_provider: &mut Provider, _data: &mut DataTree<'static>, _rpc_path: &str) -> Result<(), String> {{"
            );
            println!("{indent2}Ok(())");
            println!("{indent1}}}");
            println!("}}");
            println!();
        }
    }
}

fn gen_impl_blocks_state(yang_ctx: &Context, modules: Vec<SchemaModule<'_>>) {
    let indent1 = " ".repeat(4);
    let indent2 = " ".repeat(2 * 4);
    let indent3 = " ".repeat(3 * 4);

    for snode in yang_ctx
        .traverse()
        .filter(|snode| !snode.is_schema_only())
        .filter(|snode| snode.is_status_current())
        .filter(|snode| {
            matches!(
                snode.kind(),
                SchemaNodeKind::Container | SchemaNodeKind::List
            )
        })
        .filter(|snode| modules.iter().any(|module| snode.module() == *module))
    {
        let module = snode_rust_module_path(&snode);
        let struct_name = snode_rust_name(&snode, Case::Pascal);
        let mut fields = Vec::new();
        for snode in snode.children() {
            StructBuilder::extract_fields(snode, &mut fields);
        }
        let lifetime = if snode.is_within_notification()
            || fields.iter().any(|snode| {
                snode.kind() == SchemaNodeKind::LeafList
                    || !snode.leaf_type().is_some_and(|leaf_type| {
                        leaf_type_is_builtin(&leaf_type)
                    })
            }) {
            "<'a>"
        } else {
            ""
        };

        if snode_is_state_container(&snode) {
            if fields.is_empty() {
                continue;
            }
            println!(
                "impl<'a> YangContainer<'a, Provider> for {module}::{struct_name}{lifetime}"
            );
            println!("{{");
            println!(
                "{indent1}fn new(_provider: &'a Provider, _list_entry: &ListEntry<'a>) -> Option<Self> {{"
            );
            println!("{indent2}Some(Self {{");
            for snode in fields
                .iter()
                .filter(|snode| {
                    matches!(
                        snode.kind(),
                        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
                    )
                })
                .filter(|snode| snode.is_state() || snode.is_list_key())
            {
                let field_name = snode_rust_name(snode, Case::Snake);
                println!("{indent3}{field_name}: todo!(),");
            }
            println!("{indent2}}})");
            println!("{indent1}}}");
            println!("}}");
            println!();
        }
        if snode_is_state_list(&snode) {
            println!(
                "impl<'a> YangList<'a, Provider> for {module}::{struct_name}{lifetime}"
            );
            println!("{{");
            println!(
                "{indent1}fn iter(_provider: &'a Provider, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {{"
            );
            println!("{indent2}todo!()");
            println!("{indent1}}}");
            println!();
            println!(
                "{indent1}fn new(_provider: &'a Provider, _list_entry: &ListEntry<'a>) -> Self {{"
            );
            println!("{indent2}Self {{");
            for snode in fields
                .iter()
                .filter(|snode| {
                    matches!(
                        snode.kind(),
                        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
                    )
                })
                .filter(|snode| snode.is_state() || snode.is_list_key())
            {
                let field_name = snode_rust_name(snode, Case::Snake);
                println!("{indent3}{field_name}: todo!(),");
            }
            println!("{indent2}}}");
            println!("{indent1}}}");
            println!("}}");
            println!();
        }
    }
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
            Arg::with_name("TYPE")
                .long("type")
                .help("Type (state/rpc)")
                .value_name("TYPE")
                .required(true),
        )
        .get_matches();

    let module_names = matches.values_of("MODULE").unwrap().collect::<Vec<_>>();
    let impl_type = matches.value_of("TYPE").unwrap();

    // Initialize context.
    let mut yang_ctx = yang::new_context();

    // Load provided YANG module.
    for module_name in &module_names {
        yang::load_module(&mut yang_ctx, module_name);
        yang::load_deviations(&mut yang_ctx, module_name);
    }

    // Generate impl blocks.
    let modules = module_names
        .into_iter()
        .map(|module_name| {
            yang_ctx
                .get_module_latest(module_name)
                .expect("Failed to find loaded module")
        })
        .collect::<Vec<_>>();
    match impl_type {
        "rpc" => gen_impl_blocks_rpc(&yang_ctx, modules),
        "state" => gen_impl_blocks_state(&yang_ctx, modules),
        _ => panic!("Unknown type (valid options: rpc, state)"),
    }
}
