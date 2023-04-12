//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_utils::ip::AddressFamily;

use crate::instance::{Instance, InstanceVersion};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl InstanceVersion<Self> for Ospfv3 {
    fn address_family(instance: &Instance<Self>) -> AddressFamily {
        // OSPFv3 supports both IPv6 and IPv4 routing (default is IPv6).
        instance.config.af.unwrap_or(AddressFamily::Ipv6)
    }
}
