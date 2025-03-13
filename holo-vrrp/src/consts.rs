//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

pub const MAX_VIRTUAL_IP_COUNT: usize = 20;
pub const VALID_VRRP_VERSIONS: [u8; 2] = [2, 3];
pub const VRRP_PROTO_NUMBER: i32 = 112;

// Multicast Addresses
pub static VRRP_MULTICAST_ADDR_IPV4: Lazy<Ipv4Addr> =
    Lazy::new(|| Ipv4Addr::from_str("224.0.0.18").unwrap());
pub static VRRP_MULTICAST_ADDR_IPV6: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("ff02::12").unwrap());
pub static SOLICITATION_BASE_ADDR: Lazy<Ipv6Addr> =
    Lazy::new(|| Ipv6Addr::from_str("ff02::1:ff00:0").unwrap());
