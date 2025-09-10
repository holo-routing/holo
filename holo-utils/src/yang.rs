//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use holo_yang::TryFromYang;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use yang3::context::Context;
use yang3::data::{Data, DataNodeRef};
use yang3::schema::{DataValue, SchemaNode, SchemaPathFormat};

use crate::ip::AddressFamily;

/// Extension methods for `Context`.
pub trait ContextExt {
    fn cache_data_paths(&self);
}

/// Extension methods for `SchemaNode`.
pub trait SchemaNodeExt {
    fn cache_data_path(&self);
    fn data_path(&self) -> String;
}

/// Extension methods for `DataNodeRef`.
pub trait DataNodeRefExt {
    fn exists(&self, path: &str) -> bool;
    fn get_u8(&self) -> u8;
    fn get_u8_relative(&self, path: &str) -> Option<u8>;
    fn get_u16(&self) -> u16;
    fn get_u16_relative(&self, path: &str) -> Option<u16>;
    fn get_u32(&self) -> u32;
    fn get_u32_relative(&self, path: &str) -> Option<u32>;
    fn get_u64(&self) -> u64;
    fn get_u64_relative(&self, path: &str) -> Option<u64>;
    fn get_bool(&self) -> bool;
    fn get_bool_relative(&self, path: &str) -> Option<bool>;
    fn get_int8(&self) -> i8;
    fn get_int8_relative(&self, path: &str) -> Option<i8>;
    fn get_int16(&self) -> i16;
    fn get_int16_relative(&self, path: &str) -> Option<i16>;
    fn get_int32(&self) -> i32;
    fn get_int32_relative(&self, path: &str) -> Option<i32>;
    fn get_int64(&self) -> i64;
    fn get_int64_relative(&self, path: &str) -> Option<i64>;
    fn get_string(&self) -> String;
    fn get_string_relative(&self, path: &str) -> Option<String>;
    fn get_ip(&self) -> IpAddr;
    fn get_ip_relative(&self, path: &str) -> Option<IpAddr>;
    fn get_ipv4(&self) -> Ipv4Addr;
    fn get_ipv4_relative(&self, path: &str) -> Option<Ipv4Addr>;
    fn get_ipv6(&self) -> Ipv6Addr;
    fn get_ipv6_relative(&self, path: &str) -> Option<Ipv6Addr>;
    fn get_prefix(&self) -> IpNetwork;
    fn get_prefix_relative(&self, path: &str) -> Option<IpNetwork>;
    fn get_prefix4(&self) -> Ipv4Network;
    fn get_prefix4_relative(&self, path: &str) -> Option<Ipv4Network>;
    fn get_prefix6(&self) -> Ipv6Network;
    fn get_prefix6_relative(&self, path: &str) -> Option<Ipv6Network>;
    fn get_af(&self) -> AddressFamily;
    fn get_af_relative(&self, path: &str) -> Option<AddressFamily>;
}

// ===== impl Context =====

impl ContextExt for Context {
    fn cache_data_paths(&self) {
        for snode in self.traverse() {
            snode.cache_data_path();
            for action in snode.actions() {
                for snode in action.traverse() {
                    snode.cache_data_path();
                }
            }
            for notification in snode.notifications() {
                for snode in notification.traverse() {
                    snode.cache_data_path();
                }
            }
        }
    }
}

// ===== impl SchemaNode =====

impl SchemaNodeExt for SchemaNode<'_> {
    fn cache_data_path(&self) {
        let data_path = self.path(SchemaPathFormat::DATA);
        let data_path = CString::new(data_path).unwrap();
        unsafe { self.set_private(data_path.into_raw() as _) };
    }

    fn data_path(&self) -> String {
        let data_path = self
            .get_private()
            .expect("Schema node private pointer uninitialized");
        let data_path = unsafe { std::ffi::CStr::from_ptr(data_path as _) };
        data_path.to_str().expect("Invalid UTF-8").to_owned()
    }
}

// ===== impl DataNodeRef =====

impl DataNodeRefExt for DataNodeRef<'_> {
    fn exists(&self, path: &str) -> bool {
        self.find_xpath(path).unwrap().next().is_some()
    }

    fn get_u8(&self) -> u8 {
        if let DataValue::Uint8(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "uint8");
        }
    }

    fn get_u8_relative(&self, path: &str) -> Option<u8> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_u8())
    }

    fn get_u16(&self) -> u16 {
        if let DataValue::Uint16(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "uint16");
        }
    }

    fn get_u16_relative(&self, path: &str) -> Option<u16> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_u16())
    }

    fn get_u32(&self) -> u32 {
        if let DataValue::Uint32(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "uint32");
        }
    }

    fn get_u32_relative(&self, path: &str) -> Option<u32> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_u32())
    }

    fn get_u64(&self) -> u64 {
        if let DataValue::Uint64(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "uint64");
        }
    }

    fn get_u64_relative(&self, path: &str) -> Option<u64> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_u64())
    }

    fn get_bool(&self) -> bool {
        if let DataValue::Bool(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "bool");
        }
    }

    fn get_bool_relative(&self, path: &str) -> Option<bool> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_bool())
    }

    fn get_int8(&self) -> i8 {
        if let DataValue::Int8(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "int8");
        }
    }

    fn get_int8_relative(&self, path: &str) -> Option<i8> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_int8())
    }

    fn get_int16(&self) -> i16 {
        if let DataValue::Int16(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "int16");
        }
    }

    fn get_int16_relative(&self, path: &str) -> Option<i16> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_int16())
    }

    fn get_int32(&self) -> i32 {
        if let DataValue::Int32(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "int32");
        }
    }

    fn get_int32_relative(&self, path: &str) -> Option<i32> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_int32())
    }

    fn get_int64(&self) -> i64 {
        if let DataValue::Int64(value) =
            self.value().expect("data node doesn't hold any value")
        {
            value
        } else {
            panic_wrong_dnode_type(self, "int64");
        }
    }

    fn get_int64_relative(&self, path: &str) -> Option<i64> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_int64())
    }

    fn get_string(&self) -> String {
        self.value_canonical()
            .expect("data node doesn't hold any value")
    }

    fn get_string_relative(&self, path: &str) -> Option<String> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_string())
    }

    fn get_ip(&self) -> IpAddr {
        IpAddr::from_str(&self.get_string()).unwrap()
    }

    fn get_ip_relative(&self, path: &str) -> Option<IpAddr> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_ip())
    }

    fn get_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from_str(&self.get_string()).unwrap()
    }

    fn get_ipv4_relative(&self, path: &str) -> Option<Ipv4Addr> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_ipv4())
    }

    fn get_ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from_str(&self.get_string()).unwrap()
    }

    fn get_ipv6_relative(&self, path: &str) -> Option<Ipv6Addr> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_ipv6())
    }

    fn get_prefix(&self) -> IpNetwork {
        IpNetwork::from_str(&self.get_string()).unwrap()
    }

    fn get_prefix_relative(&self, path: &str) -> Option<IpNetwork> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_prefix())
    }

    fn get_prefix4(&self) -> Ipv4Network {
        Ipv4Network::from_str(&self.get_string()).unwrap()
    }

    fn get_prefix4_relative(&self, path: &str) -> Option<Ipv4Network> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_prefix4())
    }

    fn get_prefix6(&self) -> Ipv6Network {
        Ipv6Network::from_str(&self.get_string()).unwrap()
    }

    fn get_prefix6_relative(&self, path: &str) -> Option<Ipv6Network> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_prefix6())
    }

    fn get_af(&self) -> AddressFamily {
        AddressFamily::try_from_yang(&self.get_string()).unwrap()
    }

    fn get_af_relative(&self, path: &str) -> Option<AddressFamily> {
        self.find_xpath(path)
            .unwrap()
            .next()
            .map(|dnode| dnode.get_af())
    }
}

// ===== helper functions =====

fn panic_wrong_dnode_type(dnode: &DataNodeRef<'_>, expected: &str) -> ! {
    panic!(
        "wrong data node type (was expecting {}): {}",
        expected,
        dnode.path()
    );
}
