//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use ipnetwork::Ipv4Network;

use crate::debug::Debug;
use crate::ibus::rx::IbusRxVersion;
use crate::interface::Interface;
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

impl IbusRxVersion<Self> for Ospfv2 {
    fn process_addr_add(
        iface: &mut Interface<Self>,
        addr: Ipv4Network,
        unnumbered: bool,
    ) {
        if iface.system.primary_addr.is_none() {
            Debug::<Self>::InterfacePrimaryAddrSelect(&iface.name, &addr).log();

            // Mark address as the primary one.
            iface.system.primary_addr = Some(addr);
            iface.system.unnumbered = unnumbered;
        }
    }

    fn process_addr_del(iface: &mut Interface<Self>, addr: Ipv4Network) {
        if iface.system.primary_addr == Some(addr) {
            Debug::<Self>::InterfacePrimaryAddrDelete(&iface.name).log();

            // Remove primary address.
            iface.system.primary_addr = None;

            // Try to find other address to select as primary.
            if let Some(addr) = iface
                .system
                .addr_list
                .iter()
                .find(|addr| addr.ip().is_usable())
            {
                Debug::<Self>::InterfacePrimaryAddrSelect(&iface.name, addr)
                    .log();

                iface.system.primary_addr = Some(*addr);
            }
        }
    }
}
