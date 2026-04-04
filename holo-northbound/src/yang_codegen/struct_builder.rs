//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use convert_case::Case;
use yang4::schema::{SchemaNode, SchemaNodeKind};

use crate::yang_codegen::SchemaNodeCodegenExt;
use crate::yang_codegen::code_writer::{CodeWriter, emit};
use crate::yang_codegen::types::SchemaLeafTypeCodegenExt;

pub struct StructBuilder<'a> {
    pub snode: SchemaNode<'a>,
    pub fields: Vec<SchemaNode<'a>>,
}

// ===== impl StructBuilder =====

impl<'a> StructBuilder<'a> {
    pub fn new(snode: SchemaNode<'a>) -> Self {
        let mut fields = Vec::new();
        for snode in snode.children() {
            Self::extract_fields(snode, &mut fields);
        }
        StructBuilder { snode, fields }
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
            SchemaNodeKind::Container if snode.is_within_notification() => {
                let mut container_fields = Vec::new();
                for snode in snode.children() {
                    Self::extract_fields(snode, &mut container_fields);
                }
                if !container_fields.is_empty() {
                    fields.push(snode);
                }
            }
            SchemaNodeKind::Leaf | SchemaNodeKind::LeafList
                if (!snode.is_config() || snode.is_list_key()) =>
            {
                fields.push(snode);
            }
            _ => {}
        }
    }

    pub(crate) fn generate(self, w: &mut CodeWriter) -> std::fmt::Result {
        let (lifetime, anon_lifetime) = if self.needs_lifetime() {
            ("<'a>", "<'_>")
        } else {
            ("", "")
        };
        self.generate_struct_def(w, lifetime)?;
        self.generate_yang_object_impl(w, anon_lifetime)?;
        Ok(())
    }

    // Returns true if the generated struct needs a lifetime parameter.
    fn needs_lifetime(&self) -> bool {
        self.snode.is_within_notification()
            || self.fields.iter().any(|snode| {
                snode.kind() == SchemaNodeKind::LeafList
                    || !snode.leaf_type().is_some_and(|t| t.is_builtin())
            })
    }

    // Returns the Rust type string for a struct field node.
    fn field_type(&self, snode: &SchemaNode<'a>) -> String {
        match snode.kind() {
            SchemaNodeKind::Container => format!(
                "Option<{}::{}<'a>>",
                snode.rust_name(Case::Snake),
                snode.rust_name(Case::Pascal)
            ),
            SchemaNodeKind::Leaf => {
                let leaf_type = snode.leaf_type().unwrap();
                let field_type = leaf_type.spec().rust_type;
                if snode.is_list_key() {
                    field_type.to_owned()
                } else {
                    format!("Option<{field_type}>")
                }
            }
            SchemaNodeKind::LeafList => {
                let leaf_type = snode.leaf_type().unwrap();
                format!(
                    "Option<Box<dyn Iterator<Item = {}> + 'a>>",
                    leaf_type.spec().rust_type
                )
            }
            _ => unreachable!(),
        }
    }

    fn generate_struct_def(
        &self,
        w: &mut CodeWriter,
        lifetime: &str,
    ) -> std::fmt::Result {
        let name = &self.snode.rust_name(Case::Pascal);

        emit!(w, 1, "pub struct {name}{lifetime} {{")?;
        for snode in &self.fields {
            let field_name = snode.rust_name(Case::Snake);
            let field_type = self.field_type(snode);
            emit!(w, 2, "pub {field_name}: {field_type},")?;
        }
        if self.snode.is_within_notification()
            && self
                .fields
                .iter()
                .all(|snode| snode.leaf_type().is_some_and(|t| t.is_builtin()))
        {
            emit!(w, 2, "_marker: std::marker::PhantomData<&'a str>,")?;
        }
        emit!(w, 1, "}}")?;
        Ok(())
    }

    fn generate_yang_object_impl(
        &self,
        w: &mut CodeWriter,
        anon_lifetime: &str,
    ) -> std::fmt::Result {
        let name = &self.snode.rust_name(Case::Pascal);

        emit!(w, 1, "impl YangObject for {name}{anon_lifetime} {{")?;
        self.generate_into_data_node_fn(w)?;
        if self.snode.kind() == SchemaNodeKind::List
            && !self.snode.is_keyless_list()
        {
            self.generate_list_keys_fn(w)?;
        }
        emit!(w, 1, "}}")?;
        Ok(())
    }

    fn generate_into_data_node_fn(
        &self,
        w: &mut CodeWriter,
    ) -> std::fmt::Result {
        emit!(
            w,
            2,
            "fn into_data_node(self, dnode: &mut DataNodeRef<'_>) {{"
        )?;
        emit!(w, 3, "let module: Option<&SchemaModule<'_>> = None;")?;
        for snode in self.fields.iter().filter(|snode| !snode.is_list_key()) {
            let field_name = snode.rust_name(Case::Snake);
            let module = snode.module();

            emit!(w, 3, "if let Some({field_name}) = self.{field_name} {{")?;
            // If the field belongs to a different module than its parent,
            // override the module variable for this node.
            if let Some(parent) = snode.ancestors().next()
                && snode.module() != parent.module()
            {
                emit!(
                    w,
                    4,
                    "let module = YANG_CTX.get().unwrap().get_module_latest(\"{}\").unwrap();",
                    module.name()
                )?;
                emit!(w, 4, "let module = Some(&module);")?;
            }
            match snode.kind() {
                SchemaNodeKind::Container => {
                    emit!(
                        w,
                        4,
                        "let mut dnode = dnode.new_inner(module, \"{}\").unwrap();",
                        snode.name()
                    )?;
                    emit!(w, 4, "{field_name}.into_data_node(&mut dnode);")?;
                }
                SchemaNodeKind::Leaf => {
                    let leaf_type = snode.leaf_type().unwrap();
                    let value = (leaf_type.spec().to_yang)(&field_name);
                    emit!(
                        w,
                        4,
                        "dnode.new_term(module, \"{}\", {value}).unwrap();",
                        snode.name()
                    )?;
                }
                SchemaNodeKind::LeafList => {
                    let leaf_type = snode.leaf_type().unwrap();
                    emit!(w, 4, "for element in {field_name} {{")?;
                    let value = (leaf_type.spec().to_yang)("element");
                    emit!(
                        w,
                        5,
                        "dnode.new_term(module, \"{}\", {value}).unwrap();",
                        snode.name()
                    )?;
                    emit!(w, 4, "}}")?;
                }
                _ => unreachable!(),
            }
            emit!(w, 3, "}}")?;
        }
        emit!(w, 2, "}}")?;
        Ok(())
    }

    fn generate_list_keys_fn(&self, w: &mut CodeWriter) -> std::fmt::Result {
        let fmt_string = self
            .snode
            .list_keys()
            .map(|snode| format!("[{}='{{}}']", snode.name()))
            .collect::<Vec<_>>()
            .join("");
        let fmt_args = self
            .snode
            .list_keys()
            .map(|snode| format!("self.{}", &snode.rust_name(Case::Snake)))
            .collect::<Vec<_>>()
            .join(", ");

        emit!(w, 2, "fn list_keys(&self) -> String {{")?;
        emit!(w, 3, "format!(\"{fmt_string}\", {fmt_args})")?;
        emit!(w, 2, "}}")?;
        Ok(())
    }
}
