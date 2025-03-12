//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{Ipv4Addr, Ipv6Addr};

pub const VALID_VRRP_VERSIONS: [u8; 2] = [2, 3];
pub const VRRP_PROTO_NUMBER: i32 = 112;

// Multicast Addresses
pub const VRRP_V2_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
pub const VRRP_V3_MULTICAST_ADDRESS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12);

pub const SOLICITATION_BASE_ADDRESS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x00);
