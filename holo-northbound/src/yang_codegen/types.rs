//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::sync::OnceLock;

use yang5::schema::{DataValueType, SchemaLeafType};

// Extra typedef mappings registered by individual crates.
static EXTRA_TYPEDEFS: OnceLock<HashMap<&'static str, TypeSpec>> =
    OnceLock::new();

// Maps a YANG leaf type to its Rust type.
#[derive(Clone, Copy, Debug)]
pub struct TypeSpec {
    pub rust_type: &'static str,
    pub copy_semantics: bool,
}

// Extension methods for SchemaLeafType.
pub trait SchemaLeafTypeCodegenExt {
    // Returns the `TypeSpec` describing this leaf type.
    fn spec(&self) -> TypeSpec;
}

// ===== impl SchemaLeafType =====

impl SchemaLeafTypeCodegenExt for SchemaLeafType<'_> {
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
            copy_semantics: true,
        },
        DataValueType::Uint16 => TypeSpec {
            rust_type: "u16",
            copy_semantics: true,
        },
        DataValueType::Uint32 => TypeSpec {
            rust_type: "u32",
            copy_semantics: true,
        },
        DataValueType::Uint64 => TypeSpec {
            rust_type: "u64",
            copy_semantics: true,
        },
        DataValueType::Int8 => TypeSpec {
            rust_type: "i8",
            copy_semantics: true,
        },
        DataValueType::Int16 => TypeSpec {
            rust_type: "i16",
            copy_semantics: true,
        },
        DataValueType::Int32 => TypeSpec {
            rust_type: "i32",
            copy_semantics: true,
        },
        DataValueType::Int64 => TypeSpec {
            rust_type: "i64",
            copy_semantics: true,
        },
        DataValueType::Bool => TypeSpec {
            rust_type: "bool",
            copy_semantics: true,
        },
        DataValueType::Empty => TypeSpec {
            rust_type: "()",
            copy_semantics: true,
        },
        DataValueType::Binary => TypeSpec {
            rust_type: "Base64String",
            copy_semantics: false,
        },
        DataValueType::String
        | DataValueType::Union
        | DataValueType::Dec64
        | DataValueType::Enum
        | DataValueType::IdentityRef
        | DataValueType::InstanceId
        | DataValueType::Bits => TypeSpec {
            rust_type: "String",
            copy_semantics: false,
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
            rust_type: "IpAddr",
            copy_semantics: true,
        }),
        // ietf-inet-types, ietf-yang-types, ietf-routing-types
        "ipv4-address" | "dotted-quad" | "router-id" => Some(TypeSpec {
            rust_type: "Ipv4Addr",
            copy_semantics: true,
        }),
        // ietf-inet-types
        "ipv6-address" => Some(TypeSpec {
            rust_type: "Ipv6Addr",
            copy_semantics: true,
        }),
        // ietf-inet-types
        "ip-prefix" => Some(TypeSpec {
            rust_type: "ipnetwork::IpNetwork",
            copy_semantics: true,
        }),
        // ietf-inet-types
        "ipv4-prefix" => Some(TypeSpec {
            rust_type: "ipnetwork::Ipv4Network",
            copy_semantics: true,
        }),
        // ietf-inet-types
        "ipv6-prefix" => Some(TypeSpec {
            rust_type: "ipnetwork::Ipv6Network",
            copy_semantics: true,
        }),
        // ietf-yang-types
        "date-and-time" => Some(TypeSpec {
            rust_type: "chrono::DateTime<chrono::Utc>",
            copy_semantics: true,
        }),
        // ietf-routing-types
        "timer-value-seconds16" => Some(TypeSpec {
            rust_type: "TimerValueSecs16",
            copy_semantics: true,
        }),
        // ietf-routing-types
        "timer-value-seconds32" => Some(TypeSpec {
            rust_type: "TimerValueSecs32",
            copy_semantics: true,
        }),
        // ietf-routing-types
        "timer-value-milliseconds" => Some(TypeSpec {
            rust_type: "TimerValueMillis",
            copy_semantics: true,
        }),
        // ietf-yang-types
        "timeticks" => Some(TypeSpec {
            rust_type: "Timeticks",
            copy_semantics: true,
        }),
        // ietf-routing-types
        "timeticks64" => Some(TypeSpec {
            rust_type: "Timeticks64",
            copy_semantics: true,
        }),
        // ietf-yang-types
        "hex-string" => Some(TypeSpec {
            rust_type: "HexString",
            copy_semantics: false,
        }),
        // ietf-routing-types
        "bandwidth-ieee-float32" => Some(TypeSpec {
            rust_type: "f32",
            copy_semantics: true,
        }),
        _ => EXTRA_TYPEDEFS
            .get()
            .and_then(|map| map.get(typedef_name).copied()),
    }
}
