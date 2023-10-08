//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ip::AddressFamily;

use crate::instance::{Instance, InstanceVersion};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl InstanceVersion<Self> for Ospfv3 {
    const STRICT_AUTH_SEQNO_CHECK: bool = true;

    fn address_family(instance: &Instance<Self>) -> AddressFamily {
        // OSPFv3 supports both IPv6 and IPv4 routing (default is IPv6).
        instance.config.af.unwrap_or(AddressFamily::Ipv6)
    }

    fn initial_auth_seqno(boot_count: u32) -> u64 {
        // RFC 7166 - Section 4.1:
        // "OSPFv3 routers implementing this specification MUST use available
        // mechanisms to preserve the sequence number's strictly increasing
        // property for the deployed life of the OSPFv3 router (including cold
        // restarts). One mechanism for accomplishing this would be to use the
        // high-order 32 bits of the sequence number as a wrap/boot count that
        // is incremented anytime the OSPFv3 router loses its sequence number
        // state".
        (boot_count as u64) << 32
    }
}
