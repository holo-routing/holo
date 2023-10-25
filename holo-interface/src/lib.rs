//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![feature(lazy_cell)]

mod netlink;
pub mod northbound;

use std::collections::{btree_map, BTreeMap};
use std::net::{IpAddr, Ipv4Addr};

use futures::stream::StreamExt;
use holo_northbound::{
    process_northbound_msg, NbDaemonReceiver, NbDaemonSender, NbProviderSender,
    ProviderBase,
};
use holo_utils::ibus::{IbusMsg, IbusReceiver, IbusSender};
use holo_utils::ip::{IpNetworkKind, Ipv4NetworkExt};
use holo_utils::southbound::{
    AddressFlags, AddressMsg, InterfaceFlags, InterfaceUpdateMsg,
};
use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::mpsc;
use tracing::Instrument;

#[derive(Debug)]
pub struct Master {
    // Northbound Tx channel.
    pub nb_tx: NbProviderSender,
    // Internal bus Tx channel.
    pub ibus_tx: IbusSender,
    // Auto-generated Router ID.
    pub router_id: Option<Ipv4Addr>,
    // List of interfaces.
    pub interfaces: BTreeMap<String, Interface>,
}

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub ifindex: u32,
    pub mtu: u32,
    pub flags: InterfaceFlags,
    pub addresses: BTreeMap<IpNetwork, InterfaceAddress>,
}

#[derive(Debug)]
pub struct InterfaceAddress {
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

// ===== impl Master =====

impl Master {
    async fn run(
        &mut self,
        mut nb_rx: NbDaemonReceiver,
        mut ibus_rx: IbusReceiver,
    ) {
        let mut resources = vec![];

        // Netlink initialization.
        let mut netlink_monitor = netlink::init(self).await;

        loop {
            tokio::select! {
                Some(request) = nb_rx.recv() => {
                    process_northbound_msg(
                        self,
                        &mut resources,
                        request,
                    )
                    .await;
                }
                Some((msg, _)) = netlink_monitor.next() => {
                    netlink::process_msg(self, msg);
                }
                Ok(msg) = ibus_rx.recv() => {
                    process_ibus_msg(self, msg);
                }
            }
        }
    }

    pub(crate) fn interface_update(
        &mut self,
        ifname: String,
        ifindex: u32,
        mtu: u32,
        flags: InterfaceFlags,
        notify: bool,
    ) {
        match self.interfaces.entry(ifname.clone()) {
            btree_map::Entry::Vacant(v) => {
                // If the interface does not exist, create a new entry.
                v.insert(Interface {
                    name: ifname.clone(),
                    ifindex,
                    mtu,
                    flags,
                    addresses: Default::default(),
                });
            }
            btree_map::Entry::Occupied(o) => {
                let iface = o.into_mut();

                // If nothing of interest has changed, return early.
                if iface.ifindex == ifindex
                    && iface.mtu == mtu
                    && iface.flags == flags
                {
                    return;
                }

                // Update the existing interface with the new information.
                iface.ifindex = ifindex;
                iface.mtu = mtu;
                iface.flags = flags;
            }
        }

        // Notify protocol instances about the interface update.
        if notify {
            self.ibus_notify_interface_update(ifname, ifindex, mtu, flags);
        }
    }

    pub(crate) fn interface_remove(&mut self, ifname: String, notify: bool) {
        // Remove interface.
        if self.interfaces.remove(&ifname).is_none() {
            return;
        }

        // Notify protocol instances.
        if notify {
            self.ibus_notify_interface_del(ifname);
        }

        // Check if the Router ID needs to be updated.
        self.update_router_id();
    }

    pub(crate) fn interface_addr_add(
        &mut self,
        ifindex: u32,
        addr: IpNetwork,
        notify: bool,
    ) {
        // Ignore loopback addresses.
        if addr.ip().is_loopback() {
            return;
        }

        // Lookup interface.
        let Some(iface) = self
            .interfaces
            .values_mut()
            .find(|iface| iface.ifindex == ifindex)
        else {
            return;
        };

        // Add address to the interface.
        let mut flags = AddressFlags::empty();
        if !iface.flags.contains(InterfaceFlags::LOOPBACK)
            && addr.is_ipv4()
            && addr.prefix() == Ipv4Network::MAX_PREFIXLEN
        {
            flags.insert(AddressFlags::UNNUMBERED);
        }
        let iface_addr = InterfaceAddress { addr, flags };
        iface.addresses.insert(addr, iface_addr);

        // Notify protocol instances.
        if notify {
            let ifname = iface.name.clone();
            self.ibus_notify_addr_add(ifname, addr, flags);
        }

        // Check if the Router ID needs to be updated.
        self.update_router_id();
    }

    pub(crate) fn interface_addr_del(
        &mut self,
        ifindex: u32,
        addr: IpNetwork,
        notify: bool,
    ) {
        // Lookup interface.
        let Some(iface) = self
            .interfaces
            .values_mut()
            .find(|iface| iface.ifindex == ifindex)
        else {
            return;
        };

        // Remove address from the interface.
        if let Some(iface_addr) = iface.addresses.remove(&addr) {
            // Notify protocol instances.
            if notify {
                let ifname = iface.name.clone();
                self.ibus_notify_addr_del(
                    ifname,
                    iface_addr.addr,
                    iface_addr.flags,
                );
            }

            // Check if the Router ID needs to be updated.
            self.update_router_id();
        }
    }

    fn update_router_id(&mut self) {
        let loopback_interfaces = self
            .interfaces
            .values()
            .filter(|iface| iface.flags.contains(InterfaceFlags::LOOPBACK));
        let non_loopback_interfaces = self
            .interfaces
            .values()
            .filter(|iface| !iface.flags.contains(InterfaceFlags::LOOPBACK));

        // Helper function to find the highest IPv4 address among a list of
        // interfaces.
        fn highest_ipv4_addr<'a>(
            interfaces: impl Iterator<Item = &'a Interface>,
        ) -> Option<Ipv4Addr> {
            interfaces
                .flat_map(|iface| iface.addresses.values())
                .filter_map(|addr| {
                    if let IpAddr::V4(addr) = addr.addr.ip() {
                        Some(addr)
                    } else {
                        None
                    }
                })
                .filter(|addr| !addr.is_loopback())
                .filter(|addr| !addr.is_link_local())
                .filter(|addr| !addr.is_multicast())
                .filter(|addr| !addr.is_broadcast())
                .max()
        }

        // First, check for the highest IPv4 address on loopback interfaces.
        // If none exist or lack IPv4 addresses, try the non-loopback interfaces.
        let router_id = highest_ipv4_addr(loopback_interfaces)
            .or_else(|| highest_ipv4_addr(non_loopback_interfaces));

        if self.router_id != router_id {
            // Update the Router ID with the new value.
            self.router_id = router_id;

            // Notify the protocol instances about the Router ID update.
            let msg = IbusMsg::RouterIdUpdate(router_id);
            self.ibus_notify(msg);
        }
    }

    fn ibus_notify_router_id_update(&self) {
        let msg = IbusMsg::RouterIdUpdate(self.router_id);
        self.ibus_notify(msg);
    }

    fn ibus_notify_interface_update(
        &self,
        ifname: String,
        ifindex: u32,
        mtu: u32,
        flags: InterfaceFlags,
    ) {
        let msg = IbusMsg::InterfaceUpd(InterfaceUpdateMsg {
            ifname,
            ifindex,
            mtu,
            flags,
        });
        self.ibus_notify(msg);
    }

    fn ibus_notify_interface_del(&self, ifname: String) {
        let msg = IbusMsg::InterfaceDel(ifname);
        self.ibus_notify(msg);
    }

    fn ibus_notify_addr_add(
        &self,
        ifname: String,
        addr: IpNetwork,
        flags: AddressFlags,
    ) {
        let msg = IbusMsg::InterfaceAddressAdd(AddressMsg {
            ifname,
            addr,
            flags,
        });
        self.ibus_notify(msg);
    }

    fn ibus_notify_addr_del(
        &self,
        ifname: String,
        addr: IpNetwork,
        flags: AddressFlags,
    ) {
        let msg = IbusMsg::InterfaceAddressDel(AddressMsg {
            ifname,
            addr,
            flags,
        });
        self.ibus_notify(msg);
    }

    fn ibus_notify(&self, msg: IbusMsg) {
        let _ = self.ibus_tx.send(msg);
    }
}

// ===== helper functions =====

fn process_ibus_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        IbusMsg::InterfaceDump => {
            for iface in master.interfaces.values() {
                master.ibus_notify_interface_update(
                    iface.name.clone(),
                    iface.ifindex,
                    iface.mtu,
                    iface.flags,
                );
            }
        }
        IbusMsg::InterfaceQuery { ifname, af } => {
            if let Some(iface) = master.interfaces.get(&ifname) {
                master.ibus_notify_interface_update(
                    iface.name.clone(),
                    iface.ifindex,
                    iface.mtu,
                    iface.flags,
                );

                for iface_addr in
                    iface.addresses.values().filter(|iface_addr| match af {
                        Some(af) => iface_addr.addr.address_family() == af,
                        None => true,
                    })
                {
                    master.ibus_notify_addr_add(
                        iface.name.clone(),
                        iface_addr.addr,
                        iface_addr.flags,
                    );
                }
            }
        }
        IbusMsg::RouterIdQuery => {
            master.ibus_notify_router_id_update();
        }
        // Ignore other events.
        _ => {}
    }
}

// ===== global functions =====

pub fn start(
    nb_tx: NbProviderSender,
    ibus_tx: IbusSender,
    ibus_rx: IbusReceiver,
) -> NbDaemonSender {
    let (nb_daemon_tx, nb_daemon_rx) = mpsc::channel(4);

    tokio::spawn(async move {
        let span = Master::debug_span("");
        let mut master = Master {
            nb_tx,
            ibus_tx,
            router_id: None,
            interfaces: Default::default(),
        };

        // Run task main loop.
        master.run(nb_daemon_rx, ibus_rx).instrument(span).await;
    });

    nb_daemon_tx
}
