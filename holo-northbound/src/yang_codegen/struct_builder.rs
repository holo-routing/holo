//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::fmt::Write;

use convert_case::Case;
use yang4::schema::{SchemaNode, SchemaNodeKind};

use crate::yang_codegen::snode_rust_name;
use crate::yang_codegen::types::*;

pub struct StructBuilder<'a> {
    pub level: usize,
    pub snode: SchemaNode<'a>,
    pub fields: Vec<SchemaNode<'a>>,
}

// ===== impl StructBuilder =====

impl<'a> StructBuilder<'a> {
    pub fn new(level: usize, snode: SchemaNode<'a>) -> Self {
        let mut fields = Vec::new();
        for snode in snode.children() {
            Self::extract_fields(snode, &mut fields);
        }

        StructBuilder {
            level,
            snode,
            fields,
        }
    }

    pub fn extract_fields(
        snode: SchemaNode<'a>,
        fields: &mut Vec<SchemaNode<'a>>,
    ) {
        if !snode.is_status_current() {
            return;
        }

        match snode.kind() {
            SchemaNodeKind::List => {
                // Ignore.
            }
            SchemaNodeKind::Choice => {
                for snode in snode.children().flat_map(|snode| snode.children())
                {
                    Self::extract_fields(snode, fields);
                }
            }
            SchemaNodeKind::Container => {
                if snode.is_within_notification() {
                    let mut container_fields = Vec::new();
                    for snode in snode.children() {
                        Self::extract_fields(snode, &mut container_fields);
                    }
                    if !container_fields.is_empty() {
                        fields.push(snode);
                    }
                }
            }
            SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => {
                if !snode.is_config() || snode.is_list_key() {
                    fields.push(snode);
                }
            }
            _ => {}
        }
    }

    pub fn generate(self, output: &mut String) -> std::fmt::Result {
        let indent1 = " ".repeat((self.level + 1) * 2);
        let indent2 = " ".repeat((self.level + 2) * 2);
        let indent3 = " ".repeat((self.level + 3) * 2);
        let indent4 = " ".repeat((self.level + 4) * 2);
        let indent5 = " ".repeat((self.level + 5) * 2);
        let (lifetime, anon_lifetime) = if self.snode.is_within_notification()
            || self.fields.iter().any(|snode| {
                snode.kind() == SchemaNodeKind::LeafList
                    || !snode.leaf_type().is_some_and(|leaf_type| {
                        leaf_type_is_builtin(&leaf_type)
                    })
            }) {
            ("<'a>", "<'_>")
        } else {
            ("", "")
        };

        // Struct definition.
        let name = snode_rust_name(&self.snode, Case::Pascal);
        writeln!(output, "{indent1}pub struct {name}{lifetime} {{")?;
        for snode in &self.fields {
            let field_name = snode_rust_name(snode, Case::Snake);
            let field_type = match snode.kind() {
                SchemaNodeKind::Container => {
                    format!(
                        "Option<Box<{}::{}<'a>>>",
                        snode_rust_name(snode, Case::Snake),
                        snode_rust_name(snode, Case::Pascal)
                    )
                }
                SchemaNodeKind::Leaf => {
                    let leaf_type = snode.leaf_type().unwrap();
                    let field_type = leaf_type_map(&leaf_type).to_owned();
                    if snode.is_list_key() {
                        field_type
                    } else {
                        format!("Option<{field_type}>")
                    }
                }
                SchemaNodeKind::LeafList => {
                    let leaf_type = snode.leaf_type().unwrap();
                    format!(
                        "Option<Box<dyn Iterator<Item = {}> + 'a>>",
                        leaf_type_map(&leaf_type)
                    )
                }
                _ => unreachable!(),
            };

            writeln!(output, "{indent2}pub {field_name}: {field_type},",)?;
        }
        if self.snode.is_within_notification()
            && self.fields.iter().all(|snode| {
                snode
                    .leaf_type()
                    .is_some_and(|leaf_type| leaf_type_is_builtin(&leaf_type))
            })
        {
            writeln!(
                output,
                "{indent2}_marker: std::marker::PhantomData<&'a str>,"
            )?;
        }
        writeln!(output, "{indent1}}}")?;
        writeln!(output)?;

        // YangObject trait implementation.
        writeln!(
            output,
            "{indent1}impl YangObject for {name}{anon_lifetime} {{"
        )?;

        // into_data_node() function implementation.
        writeln!(
            output,
            "{indent2}fn into_data_node(self: Box<Self>, dnode: &mut DataNodeRef<'_>) {{"
        )?;
        writeln!(
            output,
            "{indent3}let module: Option<&SchemaModule<'_>> = None;"
        )?;
        for snode in self.fields.iter().filter(|snode| !snode.is_list_key()) {
            let field_name = snode_rust_name(snode, Case::Snake);
            let module = snode.module();

            writeln!(
                output,
                "{indent3}if let Some({field_name}) = self.{field_name} {{"
            )?;

            if let Some(parent_snode) = snode.ancestors().next()
                && snode.module() != parent_snode.module()
            {
                writeln!(
                    output,
                    "{}let module = YANG_CTX.get().unwrap().get_module_latest(\"{}\").unwrap();",
                    indent4,
                    module.name()
                )?;
                writeln!(output, "{indent4}let module = Some(&module);")?;
            }

            match snode.kind() {
                SchemaNodeKind::Container => {
                    writeln!(
                        output,
                        "{}let mut dnode = dnode.new_inner(module, \"{}\").unwrap();",
                        indent4,
                        snode.name()
                    )?;
                    writeln!(
                        output,
                        "{indent4}{field_name}.into_data_node(&mut dnode);"
                    )?;
                }
                SchemaNodeKind::Leaf => {
                    let leaf_type = snode.leaf_type().unwrap();
                    let value = leaf_type_value(&leaf_type, &field_name);
                    writeln!(
                        output,
                        "{}dnode.new_term(module, \"{}\", {}).unwrap();",
                        indent4,
                        snode.name(),
                        value
                    )?;
                }
                SchemaNodeKind::LeafList => {
                    let leaf_type = snode.leaf_type().unwrap();
                    writeln!(
                        output,
                        "{indent4}for element in {field_name} {{"
                    )?;
                    let value = leaf_type_value(&leaf_type, "element");
                    writeln!(
                        output,
                        "{}dnode.new_term(module, \"{}\", {}).unwrap();",
                        indent5,
                        snode.name(),
                        value
                    )?;
                    writeln!(output, "{indent4}}}")?;
                }
                _ => unreachable!(),
            }
            writeln!(output, "{indent3}}}")?;
        }
        writeln!(output, "{indent2}}}")?;

        // list_keys() function implementation.
        if self.snode.kind() == SchemaNodeKind::List
            && !self.snode.is_keyless_list()
        {
            writeln!(output, "{indent2}fn list_keys(&self) -> String {{")?;

            let fmt_string = self
                .snode
                .list_keys()
                .map(|snode| format!("[{}='{{}}']", snode.name()))
                .collect::<Vec<_>>()
                .join("");
            let fmt_args = self
                .snode
                .list_keys()
                .map(|snode| {
                    let field_name = snode_rust_name(&snode, Case::Snake);
                    format!("self.{field_name}")
                })
                .collect::<Vec<_>>()
                .join(", ");

            writeln!(output, "{indent3}format!(\"{fmt_string}\", {fmt_args})")?;
            writeln!(output, "{indent2}}}")?;
        }

        writeln!(output, "{indent1}}}")?;

        Ok(())
    }
}
