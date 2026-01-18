//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use yang4::schema::{DataValueType, SchemaLeafType};

pub fn leaf_type_is_builtin(leaf_type: &SchemaLeafType<'_>) -> bool {
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

pub fn leaf_type_map(leaf_type: &SchemaLeafType<'_>) -> &'static str {
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

pub fn leaf_type_value(
    leaf_type: &SchemaLeafType<'_>,
    field_name: &str,
) -> String {
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
            format!("Some(&yang::binary_to_yang({field_name}))")
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

pub fn leaf_typedef_map(
    leaf_type: &SchemaLeafType<'_>,
) -> Option<&'static str> {
    match leaf_type.typedef_name().as_deref() {
        Some("ip-address") => Some("Cow<'a, IpAddr>"),
        Some("ipv4-address" | "dotted-quad" | "router-id") => {
            Some("Cow<'a, Ipv4Addr>")
        }
        Some("ipv6-address") => Some("Cow<'a, Ipv6Addr>"),
        Some("ip-prefix") => Some("Cow<'a, ipnetwork::IpNetwork>"),
        Some("ipv4-prefix") => Some("Cow<'a, ipnetwork::Ipv4Network>"),
        Some("ipv6-prefix") => Some("Cow<'a, ipnetwork::Ipv6Network>"),
        Some("date-and-time") => Some("Cow<'a, chrono::DateTime<chrono::Utc>>"),
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

pub fn leaf_typedef_value(
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
            Some(format!("Some(&yang::timer_secs16_to_yang({field_name}))"))
        }
        Some("timer-value-seconds32") => {
            Some(format!("Some(&yang::timer_secs32_to_yang({field_name}))"))
        }
        Some("timer-value-milliseconds") => {
            Some(format!("Some(&yang::timer_millis_to_yang({field_name}))"))
        }
        Some("timeticks") => {
            Some(format!("Some(&yang::timeticks_to_yang({field_name}))"))
        }
        Some("timeticks64") => {
            Some(format!("Some(&yang::timeticks64_to_yang({field_name}))"))
        }
        Some("hex-string") => {
            Some(format!("Some(&yang::hex_string_to_yang({field_name}))"))
        }
        Some("bandwidth-ieee-float32") => Some(format!(
            "Some(&yang::bandwidth_ieee_float32_to_yang({field_name}))"
        )),
        // ietf-ospf
        Some("fletcher-checksum16-type") => Some(format!(
            "Some(&yang::fletcher_checksum16_to_yang({field_name}))"
        )),
        _ => None,
    }
}
