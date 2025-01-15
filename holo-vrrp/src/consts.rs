//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;

// ==== VRRP ===

// valid vrrp versions
pub const VALID_VRRP_VERSIONS: [u8; 1] = [2];
pub const VRRP_PROTO_NUMBER: i32 = 112;

pub const VRRP_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
