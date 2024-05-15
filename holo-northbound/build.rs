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
use yang2::schema::{
    DataValue, DataValueType, SchemaNode, SchemaNodeKind, SchemaPathFormat,
};

const HEADER: &str = r#"
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use holo_yang::{YangObject, YangPath, YANG_CTX};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use yang2::data::DataNodeRef;
use yang2::schema::SchemaModule;

fn timer_secs16_to_yang(timer: &Duration) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u16::try_from(remaining).unwrap_or(u16::MAX);
    remaining.to_string()
}

#[allow(dead_code)]
fn timer_secs32_to_yang(timer: &Duration) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

fn timer_millis_to_yang(timer: &Duration) -> String {
    let remaining = timer.as_millis();
    // Round up the remaining time to 1 in case it's less than one millisecond.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

fn timeticks_to_yang(timeticks: &Instant) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u32::try_from(uptime.as_millis() / 10).unwrap_or(u32::MAX);
    uptime.to_string()
}

fn timeticks64_to_yang(timeticks: &Instant) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u64::try_from(uptime.as_millis() / 10).unwrap_or(u64::MAX);
    uptime.to_string()
}
"#;

struct StructBuilder<'a> {
    level: usize,
    name: String,
    fields: Vec<SchemaNode<'a>>,
}

// ===== impl StructBuilder =====

impl<'a> StructBuilder<'a> {
    fn new(level: usize, snode: &SchemaNode<'a>) -> Self {
        let mut fields = Vec::new();
        for snode in snode.children() {
            Self::extract_fields(snode, &mut fields);
        }

        StructBuilder {
            level,
            name: snode_normalized_name(snode, Case::Pascal),
            fields,
        }
    }

    fn extract_fields(snode: SchemaNode<'a>, fields: &mut Vec<SchemaNode<'a>>) {
        if !snode.is_status_current() {
            return;
        }

        match snode.kind() {
            SchemaNodeKind::List | SchemaNodeKind::LeafList => {
                // Ignore.
            }
            SchemaNodeKind::Choice => {
                for snode in snode
                    .children()
                    .filter(|snode| snode.is_status_current())
                    .flat_map(|snode| snode.children())
                {
                    Self::extract_fields(snode, fields);
                }
            }
            SchemaNodeKind::Container => {
                let mut container_fields = Vec::new();
                for snode in snode.children() {
                    Self::extract_fields(snode, &mut container_fields);
                }
                if !container_fields.is_empty() {
                    fields.push(snode);
                }
            }
            _ => {
                fields.push(snode);
            }
        }
    }

    fn generate(self, output: &mut String) {
        let indent1 = " ".repeat((self.level + 1) * 2);
        let indent2 = " ".repeat((self.level + 2) * 2);
        let indent3 = " ".repeat((self.level + 3) * 2);
        let indent4 = " ".repeat((self.level + 4) * 2);

        // Struct definition.
        writeln!(output, "{}pub struct {}<'a> {{", indent1, self.name).unwrap();
        for snode in &self.fields {
            let field_name = snode_normalized_name(snode, Case::Snake);
            let field_type = if snode.kind() == SchemaNodeKind::Container {
                format!(
                    "{}::{}<'a>",
                    snode_normalized_name(snode, Case::Snake),
                    snode_normalized_name(snode, Case::Pascal)
                )
            } else {
                snode_type_map(snode).to_owned()
            };

            writeln!(
                output,
                "{}pub {}: Option<{}>,",
                indent2, field_name, field_type,
            )
            .unwrap();
        }
        if self.fields.iter().all(|snode| snode_is_base_type(snode)) {
            writeln!(
                output,
                "{}_marker: std::marker::PhantomData<&'a str>,",
                indent2
            )
            .unwrap();
        }
        writeln!(output, "{}}}", indent1).unwrap();

        // YangObject trait implementation.
        writeln!(output).unwrap();
        writeln!(
            output,
            "{}impl<'a> YangObject for {}<'a> {{",
            indent1, self.name
        )
        .unwrap();
        writeln!(
            output,
            "{}fn init_data_node(&self, dnode: &mut DataNodeRef<'_>) {{",
            indent2
        )
        .unwrap();
        writeln!(
            output,
            "{}let module: Option<&SchemaModule<'_>> = None;",
            indent3
        )
        .unwrap();
        for snode in &self.fields {
            let field_name = snode_normalized_name(snode, Case::Snake);
            let module = snode.module();

            writeln!(
                output,
                "{}if let Some({}) = &self.{} {{",
                indent3, field_name, field_name
            )
            .unwrap();

            if let Some(parent_snode) = snode.ancestors().next()
                && snode.module() != parent_snode.module()
            {
                writeln!(
                    output,
                    "{}let module = YANG_CTX.get().unwrap().get_module_latest(\"{}\").unwrap();",
                    indent4,
                    module.name()
                )
                .unwrap();
                writeln!(output, "{}let module = Some(&module);", indent4)
                    .unwrap();
            }

            if snode.kind() == SchemaNodeKind::Container {
                writeln!(
                    output,
                    "{}let mut dnode = dnode.new_inner(module, \"{}\").unwrap();",
                    indent4,
                    snode.name()
                )
                .unwrap();
                writeln!(
                    output,
                    "{}{}.init_data_node(&mut dnode);",
                    indent4, field_name
                )
                .unwrap();
            } else {
                let value = snode_type_value(snode, &field_name);
                writeln!(
                    output,
                    "{}dnode.new_term(module, \"{}\", {}).unwrap();",
                    indent4,
                    snode.name(),
                    value
                )
                .unwrap();
            }
            writeln!(output, "{}}}", indent3).unwrap();
        }
        writeln!(output, "{}}}", indent2).unwrap();
        writeln!(output, "{}}}", indent1).unwrap();
    }
}

// ===== helper functions =====

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

fn snode_is_base_type(snode: &SchemaNode<'_>) -> bool {
    matches!(
        snode.base_type(),
        Some(
            DataValueType::Uint8
                | DataValueType::Uint16
                | DataValueType::Uint32
                | DataValueType::Uint64
                | DataValueType::Int8
                | DataValueType::Int16
                | DataValueType::Int32
                | DataValueType::Int64
                | DataValueType::Bool
                | DataValueType::Empty
        )
    )
}

fn snode_typedef_map(snode: &SchemaNode<'_>) -> Option<&'static str> {
    match snode.typedef_name().as_deref() {
        Some("ip-address") => Some("&'a IpAddr"),
        Some("ipv4-address") => Some("&'a Ipv4Addr"),
        Some("ipv6-address") => Some("&'a Ipv6Addr"),
        Some("ip-prefix") => Some("&'a IpNetwork"),
        Some("ipv4-prefix") => Some("&'a Ipv4Network"),
        Some("ipv6-prefix") => Some("&'a Ipv6Network"),
        Some("date-and-time") => Some("&'a DateTime<Utc>"),
        Some("timer-value-seconds16") => Some("&'a Duration"),
        Some("timer-value-seconds32") => Some("&'a Duration"),
        Some("timer-value-milliseconds") => Some("&'a Duration"),
        Some("timeticks") => Some("&'a Instant"),
        Some("timeticks64") => Some("&'a Instant"),
        _ => None,
    }
}

fn snode_typedef_value(
    snode: &SchemaNode<'_>,
    field_name: &str,
) -> Option<String> {
    match snode.typedef_name().as_deref() {
        Some("ip-address") | Some("ipv4-address") | Some("ipv6-address")
        | Some("ip-prefix") | Some("ipv4-prefix") | Some("ipv6-prefix") => {
            Some(format!("Some(&{}.to_string())", field_name))
        }
        Some("date-and-time") => {
            Some(format!("Some(&{}.to_rfc3339())", field_name))
        }
        Some("timer-value-seconds16") => {
            Some(format!("Some(&timer_secs16_to_yang({}))", field_name))
        }
        Some("timer-value-seconds32") => {
            Some(format!("Some(&timer_secs32_to_yang({}))", field_name))
        }
        Some("timer-value-milliseconds") => {
            Some(format!("Some(&timer_millis_to_yang({}))", field_name))
        }
        Some("timeticks") => {
            Some(format!("Some(&timeticks_to_yang({}))", field_name))
        }
        Some("timeticks64") => {
            Some(format!("Some(&timeticks64_to_yang({}))", field_name))
        }
        _ => None,
    }
}

fn snode_type_map(snode: &SchemaNode<'_>) -> &'static str {
    if let Some(typedef) = snode_typedef_map(snode) {
        return typedef;
    }

    match snode.base_type().unwrap() {
        DataValueType::Unknown => panic!("Unknown leaf type"),
        DataValueType::Uint8 => "u8",
        DataValueType::Uint16 => "u16",
        DataValueType::Uint32 => "u32",
        DataValueType::Uint64 => "u64",
        DataValueType::Int8 => "i8",
        DataValueType::Int16 => "i16",
        DataValueType::Int32 => "i32",
        DataValueType::Int64 => "i64",
        DataValueType::Bool => "bool",
        DataValueType::Empty => "()",
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::LeafRef
        | DataValueType::Binary
        | DataValueType::Bits => "Cow<'a, str>",
    }
}

fn snode_type_value(snode: &SchemaNode<'_>, field_name: &str) -> String {
    if let Some(typedef_value) = snode_typedef_value(snode, field_name) {
        return typedef_value;
    }

    match snode.base_type().unwrap() {
        DataValueType::Unknown => panic!("Unknown leaf type"),
        DataValueType::Uint8
        | DataValueType::Uint16
        | DataValueType::Uint32
        | DataValueType::Uint64
        | DataValueType::Int8
        | DataValueType::Int16
        | DataValueType::Int32
        | DataValueType::Int64
        | DataValueType::Bool => {
            format!("Some(&{}.to_string())", field_name)
        }
        DataValueType::Empty => "None".to_owned(),
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::LeafRef
        | DataValueType::Binary
        | DataValueType::Bits => format!("Some({})", field_name),
    }
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
            let builder = StructBuilder::new(level, snode);
            if !builder.fields.is_empty() {
                builder.generate(output);
            }
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

// ===== main =====

fn main() {
    let dst = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = dst.join("yang.rs");

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
    writeln!(output, "{}", HEADER).unwrap();

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
