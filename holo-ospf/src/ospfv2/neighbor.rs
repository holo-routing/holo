//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use crate::neighbor::{NeighborNetId, NeighborVersion};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl NeighborVersion<Self> for Ospfv2 {
    fn network_id(addr: &Ipv4Addr, _router_id: Ipv4Addr) -> NeighborNetId {
        NeighborNetId::from(*addr)
    }
}
