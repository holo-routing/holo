//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ip::AddressFamily;
use serde::{Deserialize, Serialize};

use crate::consts::MAX_VIRTUAL_IP_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[derive(PartialOrd, Ord)]
pub enum VrrpVersion {
    V2,
    V3(AddressFamily),
}

impl VrrpVersion {
    // Minimum number of bytes in a VRRP packet
    pub const MIN_PACKET_LENGTH: u8 = 8;

    pub fn new(version: u8, address_family: AddressFamily) -> Option<Self> {
        match address_family {
            AddressFamily::Ipv6 => {
                if version == 3 {
                    return Some(Self::V3(address_family));
                }
                None
            }
            AddressFamily::Ipv4 => match version {
                2 => Some(Self::V2),
                3 => Some(Self::V3(address_family)),
                _ => None,
            },
        }
    }

    pub fn address_family(&self) -> AddressFamily {
        match self {
            Self::V2 => AddressFamily::Ipv4,
            Self::V3(addr_family) => *addr_family,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3(_) => 3,
        }
    }

    // Maximum number of bytes in a packet.
    pub fn max_length(&self) -> usize {
        // (number of bytes per IPVx packet * MAX_VIRTUAL_IP_COUNT) +
        //      no of bytes in invariant header.
        match self.address_family() {
            AddressFamily::Ipv4 => (4 * MAX_VIRTUAL_IP_COUNT) + 8,
            AddressFamily::Ipv6 => (6 * MAX_VIRTUAL_IP_COUNT) + 8,
        }
    }
}
