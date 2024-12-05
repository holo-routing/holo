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
// maximum size of vrrp header
pub const VRRP_HDR_MAX: usize = 96;
// minimum size of vrrp header.
pub const VRRP_HDR_MIN: usize = 16;
// maximum size of IP + vrrp header.
// For when we use the layer 2 socket
pub const IP_VRRP_HDR_MAX: usize = 130;
pub const VRRP_MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

// max size of ip + vrrp header maximum
// number of virtual IP addresses that can be on a VRRP header.
pub const VRRP_IP_COUNT_MAX: usize = 20;

// ==== IP ====

pub const IP_HDR_MIN: usize = 20;
