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
    pub use_owned_types: bool,
}

// ===== impl StructBuilder =====

impl<'a> StructBuilder<'a> {
    pub fn new(snode: SchemaNode<'a>) -> Self {
        let mut fields = Vec::new();
        for snode in snode.children() {
            Self::extract_fields(snode, &mut fields);
        }
        let use_owned_types = snode.kind() == SchemaNodeKind::Input
            || snode.kind() == SchemaNodeKind::Output
            || snode.is_within_input()
            || snode.is_within_output();
        StructBuilder {
            snode,
            fields,
            use_owned_types,
        }
    }

    fn extract_fields(snode: SchemaNode<'a>, fields: &mut Vec<SchemaNode<'a>>) {
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
            SchemaNodeKind::Container
                if snode.is_within_notification()
                    || snode.is_within_input()
                    || snode.is_within_output() =>
            {
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
            SchemaNodeKind::Input | SchemaNodeKind::Output => {
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
        if matches!(
            self.snode.kind(),
            SchemaNodeKind::Container
                | SchemaNodeKind::List
                | SchemaNodeKind::Notification
                | SchemaNodeKind::Output
        ) {
            self.generate_yang_object_impl(w, anon_lifetime)?;
        }
        if matches!(
            self.snode.kind(),
            SchemaNodeKind::Rpc | SchemaNodeKind::Action
        ) {
            self.generate_yang_rpc_object_impl(w)?;
        }
        Ok(())
    }

    // Returns true if the generated struct needs a lifetime parameter.
    pub fn needs_lifetime(&self) -> bool {
        if self.use_owned_types {
            return false;
        }
        self.fields.iter().any(|snode| match snode.kind() {
            SchemaNodeKind::Leaf => {
                !snode.leaf_type().is_some_and(|t| t.spec().copy_semantics)
            }
            SchemaNodeKind::LeafList => true,
            _ => StructBuilder::new(snode.clone()).needs_lifetime(),
        })
    }

    // Returns the Rust type string for a struct field node.
    fn field_type(&self, snode: &SchemaNode<'a>) -> String {
        match snode.kind() {
            SchemaNodeKind::Container => {
                let lifetime = if self.use_owned_types { "" } else { "<'a>" };
                format!(
                    "Option<{}::{}{lifetime}>",
                    snode.rust_name(Case::Snake),
                    snode.rust_name(Case::Pascal)
                )
            }
            SchemaNodeKind::Leaf => {
                let leaf_type = snode.leaf_type().unwrap();
                let spec = leaf_type.spec();
                let field_type = if spec.copy_semantics || self.use_owned_types
                {
                    spec.rust_type
                } else {
                    &borrowed_type(spec.rust_type)
                };
                if snode.is_list_key() {
                    field_type.to_owned()
                } else {
                    format!("Option<{field_type}>")
                }
            }
            SchemaNodeKind::LeafList => {
                let leaf_type = snode.leaf_type().unwrap();
                let spec = leaf_type.spec();
                if self.use_owned_types {
                    format!("Vec<{}>", spec.rust_type)
                } else {
                    let iter_item = if spec.copy_semantics {
                        spec.rust_type
                    } else {
                        &borrowed_type(spec.rust_type)
                    };
                    format!(
                        "Option<Box<dyn Iterator<Item = {iter_item}> + 'a>>"
                    )
                }
            }
            SchemaNodeKind::Input | SchemaNodeKind::Output => {
                let lifetime =
                    if StructBuilder::new(snode.clone()).needs_lifetime() {
                        "<'a>"
                    } else {
                        ""
                    };
                format!(
                    "{}::{}{}",
                    snode.rust_name(Case::Snake),
                    snode.rust_name(Case::Pascal),
                    lifetime
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

        if self.snode.kind() == SchemaNodeKind::Output {
            emit!(w, 1, "#[derive(Default)]")?;
        }
        emit!(w, 1, "pub struct {name}{lifetime} {{")?;
        for snode in &self.fields {
            let field_name = snode.rust_name(Case::Snake);
            let field_type = self.field_type(snode);
            emit!(w, 2, "pub {field_name}: {field_type},")?;
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
                    let spec = leaf_type.spec();
                    let value = to_yang_expr(spec.rust_type, &field_name);
                    emit!(
                        w,
                        4,
                        "dnode.new_term(module, \"{}\", {value}).unwrap();",
                        snode.name()
                    )?;
                }
                SchemaNodeKind::LeafList => {
                    let leaf_type = snode.leaf_type().unwrap();
                    let spec = leaf_type.spec();
                    emit!(w, 4, "for element in {field_name} {{")?;
                    let value = to_yang_expr(spec.rust_type, "element");
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

    fn generate_yang_rpc_object_impl(
        &self,
        w: &mut CodeWriter,
    ) -> std::fmt::Result {
        let name = &self.snode.rust_name(Case::Pascal);

        emit!(w, 1, "impl YangRpcObject for {name} {{")?;
        self.generate_parse_input_fn(w)?;
        self.generate_write_output_fn(w)?;
        emit!(w, 1, "}}")?;
        Ok(())
    }

    fn generate_parse_input_fn(&self, w: &mut CodeWriter) -> std::fmt::Result {
        let name = &self.snode.rust_name(Case::Pascal);

        emit!(w, 2, "fn parse_input(dnode: &DataNodeRef<'_>) -> Self {{")?;
        emit!(w, 3, "{name} {{")?;
        for snode in &self.fields {
            match snode.kind() {
                SchemaNodeKind::Input => {
                    let mod_name = snode.rust_name(Case::Snake);
                    let type_name = snode.rust_name(Case::Pascal);
                    emit!(w, 4, "{mod_name}: {mod_name}::{type_name} {{")?;
                    Self::generate_parse_input_fields(w, snode, 5, &mod_name)?;
                    emit!(w, 4, "}},")?;
                }
                SchemaNodeKind::Output => {
                    let mod_name = snode.rust_name(Case::Snake);
                    emit!(w, 4, "{mod_name}: Default::default(),")?;
                }
                _ => {}
            }
        }
        emit!(w, 3, "}}")?;
        emit!(w, 2, "}}")?;
        Ok(())
    }

    fn generate_write_output_fn(&self, w: &mut CodeWriter) -> std::fmt::Result {
        emit!(
            w,
            2,
            "fn write_output(self, dnode: &mut DataNodeRef<'_>) {{"
        )?;
        emit!(w, 3, "self.output.into_data_node(dnode);")?;
        emit!(w, 2, "}}")?;
        Ok(())
    }

    fn generate_parse_input_fields(
        w: &mut CodeWriter,
        parent_snode: &SchemaNode<'_>,
        depth: usize,
        module_prefix: &str,
    ) -> std::fmt::Result {
        let builder = StructBuilder::new(parent_snode.clone());
        for snode in &builder.fields {
            let snode_name = snode.name();
            let field_name = snode.rust_name(Case::Snake);

            match snode.kind() {
                SchemaNodeKind::Leaf => {
                    let spec = snode.leaf_type().unwrap().spec();
                    let expr = from_yang_expr(spec.rust_type, snode_name);
                    emit!(w, depth, "{field_name}: {expr},")?;
                }
                SchemaNodeKind::LeafList => {
                    emit!(
                        w,
                        depth,
                        "{field_name}: dnode.find_xpath(\"./{snode_name}\")\
                         .unwrap().filter_map(|dnode| {{ \
                         dnode.value_canonical().and_then(|v| TryFromYang::try_from_yang(&v)) \
                         }}).collect(),"
                    )?;
                }
                SchemaNodeKind::Container => {
                    let container_mod = snode.rust_name(Case::Snake);
                    let container_type = snode.rust_name(Case::Pascal);
                    let nested_prefix =
                        format!("{module_prefix}::{container_mod}");
                    emit!(
                        w,
                        depth,
                        "{field_name}: dnode.find_xpath(\"./{snode_name}\")\
                         .unwrap().next().map(|dnode| {{"
                    )?;
                    emit!(
                        w,
                        depth + 1,
                        "{module_prefix}::{container_mod}::\
                         {container_type} {{"
                    )?;
                    Self::generate_parse_input_fields(
                        w,
                        snode,
                        depth + 2,
                        &nested_prefix,
                    )?;
                    emit!(w, depth + 1, "}}")?;
                    emit!(w, depth, "}}),")?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ===== helper functions =====

// Maps an owned Rust type to its borrowed equivalent.
fn borrowed_type(rust_type: &str) -> String {
    match rust_type {
        "String" => "Cow<'a, str>".to_owned(),
        "Base64String" => "Base64Str<'a>".to_owned(),
        "HexString" => "HexStr<'a>".to_owned(),
        t => format!("Cow<'a, {t}>"),
    }
}

// Returns the generated code expression for converting a field value to its
// YANG string representation.
fn to_yang_expr(rust_type: &str, field: &str) -> String {
    match rust_type {
        "()" => "None".to_owned(),
        "String" => format!("Some({field}.as_ref())"),
        _ => format!("Some({field}.to_yang().as_ref())"),
    }
}

// Returns the generated code expression for extracting a leaf value from a
// YANG data node.
fn from_yang_expr(rust_type: &str, snode_name: &str) -> String {
    match rust_type {
        "()" => format!(
            "if dnode.exists(\"./{snode_name}\") {{ Some(()) }} else {{ None }}"
        ),
        "String" => {
            format!("dnode.get_string_relative(\"./{snode_name}\")")
        }
        _ => format!(
            "dnode.get_string_relative(\"./{snode_name}\").and_then(|v| TryFromYang::try_from_yang(&v))"
        ),
    }
}
