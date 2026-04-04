//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::sync::OnceLock;

use yang4::schema::{DataValueType, SchemaLeafType};

// Extra typedef mappings registered by individual crates.
static EXTRA_TYPEDEFS: OnceLock<HashMap<&'static str, TypeSpec>> =
    OnceLock::new();

// Maps a YANG leaf type to its Rust type and defines how to convert values
// to a YANG string representation.
#[derive(Clone, Copy, Debug)]
pub struct TypeSpec {
    pub rust_type: &'static str,
    pub to_yang: fn(&str) -> String,
}

// Extension methods for SchemaLeafType.
pub trait SchemaLeafTypeCodegenExt {
    // Returns true for base types.
    fn is_builtin(&self) -> bool;

    // Returns the `TypeSpec` describing this leaf type.
    fn spec(&self) -> TypeSpec;
}

// ===== impl SchemaLeafType =====

impl SchemaLeafTypeCodegenExt for SchemaLeafType<'_> {
    fn is_builtin(&self) -> bool {
        matches!(
            self.base_type(),
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

    fn spec(&self) -> TypeSpec {
        // Handle typedef.
        if let Some(typedef_name) = self.typedef_name()
            && let Some(spec) = typedef_spec(&typedef_name)
        {
            return spec;
        }

        // Handle leafref.
        if let Some(real_type) = self.leafref_real_type() {
            return real_type.spec();
        }

        // Handle base type.
        base_type_spec(self.base_type())
    }
}

// ===== global functions =====

// Registers crate-specific YANG typedef mappings before code generation.
// Must be called at most once per build script.
pub fn register_typedefs(typedefs: &[(&'static str, TypeSpec)]) {
    EXTRA_TYPEDEFS
        .set(typedefs.iter().copied().collect())
        .expect("typedefs already registered");
}

// ===== helper functions =====

fn base_type_spec(base_type: DataValueType) -> TypeSpec {
    match base_type {
        DataValueType::Uint8 => TypeSpec {
            rust_type: "u8",
            to_yang: to_string,
        },
        DataValueType::Uint16 => TypeSpec {
            rust_type: "u16",
            to_yang: to_string,
        },
        DataValueType::Uint32 => TypeSpec {
            rust_type: "u32",
            to_yang: to_string,
        },
        DataValueType::Uint64 => TypeSpec {
            rust_type: "u64",
            to_yang: to_string,
        },
        DataValueType::Int8 => TypeSpec {
            rust_type: "i8",
            to_yang: to_string,
        },
        DataValueType::Int16 => TypeSpec {
            rust_type: "i16",
            to_yang: to_string,
        },
        DataValueType::Int32 => TypeSpec {
            rust_type: "i32",
            to_yang: to_string,
        },
        DataValueType::Int64 => TypeSpec {
            rust_type: "i64",
            to_yang: to_string,
        },
        DataValueType::Bool => TypeSpec {
            rust_type: "bool",
            to_yang: to_string,
        },
        DataValueType::Empty => TypeSpec {
            rust_type: "()",
            to_yang: |_| "None".to_owned(),
        },
        DataValueType::Binary => TypeSpec {
            rust_type: "&'a [u8]",
            to_yang: |f| format!("Some(&yang::binary_to_yang({f}))"),
        },
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::Bits => TypeSpec {
            rust_type: "Cow<'a, str>",
            to_yang: |f| format!("Some(&{f})"),
        },
        DataValueType::LeafRef => {
            unreachable!()
        }
        DataValueType::Unknown => panic!("Unknown data value type"),
    }
}

fn typedef_spec(typedef_name: &str) -> Option<TypeSpec> {
    match typedef_name {
        // ietf-inet-types
        "ip-address" => Some(TypeSpec {
            rust_type: "Cow<'a, IpAddr>",
            to_yang: to_string,
        }),
        // ietf-inet-types, ietf-yang-types, ietf-routing-types
        "ipv4-address" | "dotted-quad" | "router-id" => Some(TypeSpec {
            rust_type: "Cow<'a, Ipv4Addr>",
            to_yang: to_string,
        }),
        // ietf-inet-types
        "ipv6-address" => Some(TypeSpec {
            rust_type: "Cow<'a, Ipv6Addr>",
            to_yang: to_string,
        }),
        // ietf-inet-types
        "ip-prefix" => Some(TypeSpec {
            rust_type: "Cow<'a, ipnetwork::IpNetwork>",
            to_yang: to_string,
        }),
        // ietf-inet-types
        "ipv4-prefix" => Some(TypeSpec {
            rust_type: "Cow<'a, ipnetwork::Ipv4Network>",
            to_yang: to_string,
        }),
        // ietf-inet-types
        "ipv6-prefix" => Some(TypeSpec {
            rust_type: "Cow<'a, ipnetwork::Ipv6Network>",
            to_yang: to_string,
        }),
        // ietf-yang-types
        "date-and-time" => Some(TypeSpec {
            rust_type: "Cow<'a, chrono::DateTime<chrono::Utc>>",
            to_yang: |f| format!("Some(&{f}.to_rfc3339())"),
        }),
        // ietf-routing-types
        "timer-value-seconds16" => Some(TypeSpec {
            rust_type: "Cow<'a, Duration>",
            to_yang: |f| format!("Some(&yang::timer_secs16_to_yang({f}))"),
        }),
        // ietf-routing-types
        "timer-value-seconds32" => Some(TypeSpec {
            rust_type: "Cow<'a, Duration>",
            to_yang: |f| format!("Some(&yang::timer_secs32_to_yang({f}))"),
        }),
        // ietf-routing-types
        "timer-value-milliseconds" => Some(TypeSpec {
            rust_type: "Cow<'a, Duration>",
            to_yang: |f| format!("Some(&yang::timer_millis_to_yang({f}))"),
        }),
        // ietf-yang-types
        "timeticks" => Some(TypeSpec {
            rust_type: "Cow<'a, Instant>",
            to_yang: |f| format!("Some(&yang::timeticks_to_yang({f}))"),
        }),
        // ietf-routing-types
        "timeticks64" => Some(TypeSpec {
            rust_type: "Cow<'a, Instant>",
            to_yang: |f| format!("Some(&yang::timeticks64_to_yang({f}))"),
        }),
        // ietf-yang-types
        "hex-string" => Some(TypeSpec {
            rust_type: "&'a [u8]",
            to_yang: |f| format!("Some(&yang::hex_string_to_yang({f}))"),
        }),
        // ietf-routing-types
        "bandwidth-ieee-float32" => Some(TypeSpec {
            rust_type: "&'a f32",
            to_yang: |f| {
                format!("Some(&yang::bandwidth_ieee_float32_to_yang({f}))")
            },
        }),
        _ => EXTRA_TYPEDEFS
            .get()
            .and_then(|map| map.get(typedef_name).copied()),
    }
}

fn to_string(f: &str) -> String {
    format!("Some(&{f}.to_string())")
}
