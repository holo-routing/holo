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

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[derive(PartialOrd, Ord)]
pub enum VrrpVersion {
    V2,
    V3(AddressFamily),
}

impl VrrpVersion {
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
}
