//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::neighbor::{NeighborNetId, NeighborVersion};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl NeighborVersion<Self> for Ospfv3 {
    fn network_id(_addr: &Ipv6Addr, router_id: Ipv4Addr) -> NeighborNetId {
        NeighborNetId::from(router_id)
    }
}
