//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use holo_utils::ip::IpNetworkKind;
use ipnetwork::Ipv6Network;

use crate::area::Area;
use crate::debug::Debug;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::southbound::rx::SouthboundRxVersion;
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl SouthboundRxVersion<Self> for Ospfv3 {
    fn process_ifindex_update(
        iface: &mut Interface<Self>,
        area: &Area<Self>,
        instance: &InstanceUpView<'_, Self>,
    ) {
        // Synchronize interface's Hello Tx task (updated interface ID).
        iface.sync_hello_tx(area, instance);
    }

    fn process_addr_add(iface: &mut Interface<Self>, addr: Ipv6Network) {
        if iface.system.linklocal_addr.is_none()
            && addr.ip().is_unicast_link_local()
        {
            Debug::<Self>::InterfaceLinkLocalSelect(&iface.name, &addr).log();

            // Mark link-local address as the primary one.
            iface.system.linklocal_addr = Some(addr);
        }
    }

    fn process_addr_del(iface: &mut Interface<Self>, addr: Ipv6Network) {
        if iface.system.linklocal_addr == Some(addr) {
            Debug::<Self>::InterfaceLinkLocalDelete(&iface.name).log();

            // Remove primary link-local address.
            iface.system.linklocal_addr = None;

            // Try to find other link-local address.
            if let Some(addr) = iface
                .system
                .addr_list
                .iter()
                .filter_map(|addr| Ipv6Network::get(*addr))
                .find(|addr| addr.ip().is_unicast_link_local())
            {
                Debug::<Self>::InterfaceLinkLocalSelect(&iface.name, &addr)
                    .log();

                iface.system.linklocal_addr = Some(addr);
            }
        }
    }
}
