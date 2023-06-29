//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::time::{SystemTime, UNIX_EPOCH};

use holo_utils::ip::AddressFamily;

use crate::instance::{Instance, InstanceVersion};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl InstanceVersion<Self> for Ospfv2 {
    const STRICT_AUTH_SEQNO_CHECK: bool = false;

    fn address_family(_instance: &Instance<Self>) -> AddressFamily {
        // OSPFv2 supports only IPv4 routing.
        AddressFamily::Ipv4
    }

    fn initial_auth_seqno(_boot_count: u32) -> u64 {
        // Initialize the authentication sequence number as the number of
        // seconds since the Unix epoch (1 January 1970).
        // By using this approach, the chances of successfully replaying
        // packets from a restarted OSPF instance are significantly reduced.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }
}
