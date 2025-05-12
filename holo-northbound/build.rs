//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::env;
use std::fmt::Write;
use std::path::PathBuf;

use check_keyword::CheckKeyword;
use convert_case::{Boundary, Case, Casing};
use holo_yang as yang;
use holo_yang::YANG_IMPLEMENTED_MODULES;
use yang3::schema::{
    DataValue, DataValueType, SchemaLeafType, SchemaNode, SchemaNodeKind,
    SchemaPathFormat,
};

const HEADER: &str = r#"
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use holo_yang::{YangObject, YangPath, YANG_CTX};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;
use yang3::data::DataNodeRef;
use yang3::schema::SchemaModule;

fn binary_to_yang(value: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn hex_string_to_yang(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).join(":")
}

fn timer_secs16_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u16::try_from(remaining).unwrap_or(u16::MAX);
    remaining.to_string()
}

#[expect(unused)]
fn timer_secs32_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_secs();
    // Round up the remaining time to 1 in case it's less than one second.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

fn timer_millis_to_yang(timer: Cow<'_, Duration>) -> String {
    let remaining = timer.as_millis();
    // Round up the remaining time to 1 in case it's less than one millisecond.
    let remaining = if remaining == 0 { 1 } else { remaining };
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    remaining.to_string()
}

fn timeticks_to_yang(timeticks: Cow<'_, Instant>) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u32::try_from(uptime.as_millis() / 10).unwrap_or(u32::MAX);
    uptime.to_string()
}

fn timeticks64_to_yang(timeticks: Cow<'_, Instant>) -> String {
    let uptime = Instant::now() - *timeticks;
    let uptime = u64::try_from(uptime.as_millis() / 10).unwrap_or(u64::MAX);
    uptime.to_string()
}

fn bandwidth_ieee_float32_to_yang(value: &f32) -> String {
    // Get the binary representation of the float value.
    let bits = value.to_bits();

    // Extract the sign bit, exponent, and fraction.
    let sign = (bits >> 31) & 0x1;
    let exponent = ((bits >> 23) & 0xFF) as i32 - 127;
    let fraction = bits & 0x7FFFFF;

    // Normalize the fraction by adding the leading 1.
    let mut fraction_hex = format!("{fraction:x}");

    // Ensure 6 digits in hexadecimal.
    while fraction_hex.len() < 6 {
        fraction_hex = format!("0{fraction_hex}");
    }

    // Format the exponent as a signed decimal.
    let exponent_str = if exponent >= 0 {
        format!("p+{exponent}")
    } else {
        format!("p{exponent}")
    };

    // Build the final string.
    format!("0x1.{fraction_hex}{exponent_str}")
}

fn fletcher_checksum16_to_yang(cksum: u16) -> String {
    format!("{cksum:#06x}")
}
"#;

struct StructBuilder<'a> {
    level: usize,
    snode: SchemaNode<'a>,
    fields: Vec<SchemaNode<'a>>,
}

// ===== impl StructBuilder =====

impl<'a> StructBuilder<'a> {
    fn new(level: usize, snode: SchemaNode<'a>) -> Self {
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

    fn generate(self, output: &mut String) {
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
        let name = snode_normalized_name(&self.snode, Case::Pascal);
        if self.snode.kind() != SchemaNodeKind::List
            || self.snode.is_keyless_list()
        {
            writeln!(output, "{indent1}#[derive(Default)]").unwrap();
        }
        writeln!(output, "{indent1}pub struct {name}{lifetime} {{").unwrap();
        for snode in &self.fields {
            let field_name = snode_normalized_name(snode, Case::Snake);
            let field_type = match snode.kind() {
                SchemaNodeKind::Container => {
                    format!(
                        "Option<Box<{}::{}<'a>>>",
                        snode_normalized_name(snode, Case::Snake),
                        snode_normalized_name(snode, Case::Pascal)
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

            writeln!(output, "{indent2}pub {field_name}: {field_type},",)
                .unwrap();
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
            )
            .unwrap();
        }
        writeln!(output, "{indent1}}}").unwrap();

        // YangObject trait implementation.
        writeln!(output).unwrap();
        writeln!(
            output,
            "{indent1}impl YangObject for {name}{anon_lifetime} {{"
        )
        .unwrap();

        // into_data_node() function implementation.
        writeln!(
            output,
            "{indent2}fn into_data_node(self: Box<Self>, dnode: &mut DataNodeRef<'_>) {{"
        )
        .unwrap();
        writeln!(
            output,
            "{indent3}let module: Option<&SchemaModule<'_>> = None;"
        )
        .unwrap();
        for snode in self.fields.iter().filter(|snode| !snode.is_list_key()) {
            let field_name = snode_normalized_name(snode, Case::Snake);
            let module = snode.module();

            writeln!(
                output,
                "{indent3}if let Some({field_name}) = self.{field_name} {{"
            )
            .unwrap();

            if let Some(parent_snode) = snode.ancestors().next()
                && snode.module() != parent_snode.module()
            {
                writeln!(output, "{}let module = YANG_CTX.get().unwrap().get_module_latest(\"{}\").unwrap();", indent4, module.name()).unwrap();
                writeln!(output, "{indent4}let module = Some(&module);")
                    .unwrap();
            }

            match snode.kind() {
                SchemaNodeKind::Container => {
                    writeln!(output, "{}let mut dnode = dnode.new_inner(module, \"{}\").unwrap();", indent4, snode.name()).unwrap();
                    writeln!(
                        output,
                        "{indent4}{field_name}.into_data_node(&mut dnode);"
                    )
                    .unwrap();
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
                    )
                    .unwrap();
                }
                SchemaNodeKind::LeafList => {
                    let leaf_type = snode.leaf_type().unwrap();
                    writeln!(output, "{indent4}for element in {field_name} {{")
                        .unwrap();
                    let value = leaf_type_value(&leaf_type, "element");
                    writeln!(
                        output,
                        "{}dnode.new_term(module, \"{}\", {}).unwrap();",
                        indent5,
                        snode.name(),
                        value
                    )
                    .unwrap();
                    writeln!(output, "{indent4}}}").unwrap();
                }
                _ => unreachable!(),
            }
            writeln!(output, "{indent3}}}").unwrap();
        }
        writeln!(output, "{indent2}}}").unwrap();

        // list_keys() function implementation.
        if self.snode.kind() == SchemaNodeKind::List
            && !self.snode.is_keyless_list()
        {
            writeln!(output, "{indent2}fn list_keys(&self) -> String {{")
                .unwrap();

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
                    let field_name = snode_normalized_name(&snode, Case::Snake);
                    format!("self.{field_name}")
                })
                .collect::<Vec<_>>()
                .join(", ");

            writeln!(output, "{indent3}format!(\"{fmt_string}\", {fmt_args})")
                .unwrap();
            writeln!(output, "{indent2}}}").unwrap();
        }

        writeln!(output, "{indent1}}}").unwrap();
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
            | "clear-database"
            | "if-state-change"
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
        if snode.module().name() == "ietf-isis" {
            name.insert_str(0, "isis-");
        }
    }
    if let Some(snode_parent) = snode.ancestors().next()
        && snode_parent.module().name() == "ietf-routing"
    {
        if snode.module().name() == "ietf-ospf"
            && matches!(snode.name(), "route-type" | "tag" | "metric")
        {
            name.insert_str(0, "ospf-");
        }
        if snode.module().name() == "ietf-isis"
            && matches!(snode.name(), "route-type" | "tag" | "metric")
        {
            name.insert_str(0, "isis-");
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

fn leaf_type_is_builtin(leaf_type: &SchemaLeafType<'_>) -> bool {
    matches!(
        leaf_type.base_type(),
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
}

fn leaf_typedef_map(leaf_type: &SchemaLeafType<'_>) -> Option<&'static str> {
    match leaf_type.typedef_name().as_deref() {
        Some("ip-address") => Some("Cow<'a, IpAddr>"),
        Some("ipv4-address" | "dotted-quad" | "router-id") => {
            Some("Cow<'a, Ipv4Addr>")
        }
        Some("ipv6-address") => Some("Cow<'a, Ipv6Addr>"),
        Some("ip-prefix") => Some("Cow<'a, IpNetwork>"),
        Some("ipv4-prefix") => Some("Cow<'a, Ipv4Network>"),
        Some("ipv6-prefix") => Some("Cow<'a, Ipv6Network>"),
        Some("date-and-time") => Some("Cow<'a, DateTime<Utc>>"),
        Some("timer-value-seconds16") => Some("Cow<'a, Duration>"),
        Some("timer-value-seconds32") => Some("Cow<'a, Duration>"),
        Some("timer-value-milliseconds") => Some("Cow<'a, Duration>"),
        Some("timeticks") => Some("Cow<'a, Instant>"),
        Some("timeticks64") => Some("Cow<'a, Instant>"),
        Some("hex-string") => Some("&'a [u8]"),
        Some("bandwidth-ieee-float32") => Some("&'a f32"),
        // ietf-ospf
        Some("fletcher-checksum16-type") => Some("u16"),
        _ => None,
    }
}

fn leaf_typedef_value(
    leaf_type: &SchemaLeafType<'_>,
    field_name: &str,
) -> Option<String> {
    match leaf_type.typedef_name().as_deref() {
        Some(
            "ip-address" | "ipv4-address" | "dotted-quad" | "router-id"
            | "ipv6-address" | "ip-prefix" | "ipv4-prefix" | "ipv6-prefix",
        ) => Some(format!("Some(&{field_name}.to_string())")),
        Some("date-and-time") => {
            Some(format!("Some(&{field_name}.to_rfc3339())"))
        }
        Some("timer-value-seconds16") => {
            Some(format!("Some(&timer_secs16_to_yang({field_name}))"))
        }
        Some("timer-value-seconds32") => {
            Some(format!("Some(&timer_secs32_to_yang({field_name}))"))
        }
        Some("timer-value-milliseconds") => {
            Some(format!("Some(&timer_millis_to_yang({field_name}))"))
        }
        Some("timeticks") => {
            Some(format!("Some(&timeticks_to_yang({field_name}))"))
        }
        Some("timeticks64") => {
            Some(format!("Some(&timeticks64_to_yang({field_name}))"))
        }
        Some("hex-string") => {
            Some(format!("Some(&hex_string_to_yang({field_name}))"))
        }
        Some("bandwidth-ieee-float32") => Some(format!(
            "Some(&bandwidth_ieee_float32_to_yang({field_name}))"
        )),
        // ietf-ospf
        Some("fletcher-checksum16-type") => {
            Some(format!("Some(&fletcher_checksum16_to_yang({field_name}))"))
        }
        _ => None,
    }
}

fn leaf_type_map(leaf_type: &SchemaLeafType<'_>) -> &'static str {
    if let Some(typedef) = leaf_typedef_map(leaf_type) {
        return typedef;
    }

    match leaf_type.base_type() {
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
        DataValueType::Binary => "&'a [u8]",
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::Bits => "Cow<'a, str>",
        DataValueType::LeafRef => {
            let real_type = leaf_type.leafref_real_type().unwrap();
            leaf_type_map(&real_type)
        }
    }
}

fn leaf_type_value(leaf_type: &SchemaLeafType<'_>, field_name: &str) -> String {
    if let Some(typedef_value) = leaf_typedef_value(leaf_type, field_name) {
        return typedef_value;
    }

    match leaf_type.base_type() {
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
            format!("Some(&{field_name}.to_string())")
        }
        DataValueType::Empty => "None".to_owned(),
        DataValueType::Binary => {
            format!("Some(&binary_to_yang({field_name}))")
        }
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::Bits => format!("Some(&{field_name})"),
        DataValueType::LeafRef => {
            let real_type = leaf_type.leafref_real_type().unwrap();
            leaf_type_value(&real_type, field_name)
        }
    }
}

fn generate_module(output: &mut String, snode: &SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);

    if !snode.is_schema_only() {
        let name = snode_normalized_name(snode, Case::Snake);

        // Generate module.
        writeln!(output, "{indent}pub mod {name} {{").unwrap();
        writeln!(output, "{indent}  use super::*;").unwrap();

        // Generate paths.
        generate_paths(output, snode, level);

        // Generate default value (if any).
        if let Some(default) = snode.default_value() {
            generate_default_value(output, snode, default, level);
        }

        // Generate object struct.
        if matches!(
            snode.kind(),
            SchemaNodeKind::Container
                | SchemaNodeKind::List
                | SchemaNodeKind::Notification
        ) {
            let builder = StructBuilder::new(level, snode.clone());
            if !builder.fields.is_empty() {
                builder.generate(output);
            }
        }
    }

    // Iterate over child nodes.
    for snode in snode.actions() {
        generate_module(output, &snode, level + 1);
    }
    for snode in snode.notifications() {
        generate_module(output, &snode, level + 1);
    }
    for snode in snode.children().filter(|snode| snode.is_status_current()) {
        writeln!(output).unwrap();
        generate_module(output, &snode, level + 1);
    }

    if !snode.is_schema_only() {
        // Close generated module.
        writeln!(output, "{indent}}}").unwrap();
    }
}

fn generate_paths(output: &mut String, snode: &SchemaNode<'_>, level: usize) {
    let indent = " ".repeat(level * 2);

    // Generate data path.
    let path = snode.path(SchemaPathFormat::DATA);
    writeln!(
        output,
        "{indent}  pub const PATH: YangPath = YangPath::new(\"{path}\");"
    )
    .unwrap();

    // For notifications, generate data path relative to the nearest parent
    // list.
    if snode.kind() == SchemaNodeKind::Notification
        && let Some(snode_parent_list) = snode
            .ancestors()
            .find(|snode| snode.kind() == SchemaNodeKind::List)
    {
        let path_parent_list = snode_parent_list.path(SchemaPathFormat::DATA);
        let relative_path = &path[path_parent_list.len()..];

        writeln!(
            output,
            "{indent}  pub const RELATIVE_PATH: &str = \"{relative_path}\";"
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
        dflt_value = format!("\"{dflt_value}\"");
    }

    writeln!(
        output,
        "{indent}  pub const DFLT: {dflt_type} = {dflt_value};",
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
    writeln!(output, "{HEADER}").unwrap();

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
