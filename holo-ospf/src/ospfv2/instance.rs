//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_utils::ip::AddressFamily;

use crate::instance::{Instance, InstanceVersion};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl InstanceVersion<Self> for Ospfv2 {
    fn address_family(_instance: &Instance<Self>) -> AddressFamily {
        // OSPFv2 supports only IPv4 routing.
        AddressFamily::Ipv4
    }
}
