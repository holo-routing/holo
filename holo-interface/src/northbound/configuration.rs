//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::paths::interfaces;
use holo_utils::yang::DataNodeRefExt;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use crate::interface::Owner;
use crate::{netlink, Master};

static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Interface(String),
    Address(String, IpNetwork),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InterfaceDelete(String),
    AddressInstall(String, IpNetwork),
    AddressUninstall(String, IpNetwork),
}

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct InterfaceCfg {
    pub addr_list: BTreeSet<IpNetwork>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(interfaces::interface::PATH)
        .create_apply(|master, args| {
            let ifname = args.dnode.get_string_relative("./name").unwrap();

            master.interfaces.add(ifname);
        })
        .delete_apply(|_master, args| {
            let ifname = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceDelete(ifname));
        })
        .lookup(|_instance, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("./name").unwrap();
            ListEntry::Interface(ifname)
        })
        .path(interfaces::interface::description::PATH)
        .modify_apply(|_master, _args| {
            // Nothing to do.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::r#type::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::enabled::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::PATH)
        .create_apply(|_context, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::enabled::PATH)
        .modify_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv4::address::PATH)
        .create_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let addr = args.dnode.get_ipv4_relative("./ip").unwrap();
            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();
            let addr = Ipv4Network::new(addr, plen).unwrap().into();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.insert(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressInstall(ifname, addr));
        })
        .delete_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.remove(&addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressUninstall(ifname, addr));
        })
        .lookup(|_master, list_entry, dnode| {
            let ifname = list_entry.into_interface().unwrap();
            let addr = dnode.get_ipv4_relative("./ip").unwrap();
            let plen = dnode.get_u8_relative("./prefix-length").unwrap();
            let addr = Ipv4Network::new(addr, plen).unwrap();
            ListEntry::Address(ifname, addr.into())
        })
        .path(interfaces::interface::ipv4::address::prefix_length::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::ipv6::PATH)
        .create_apply(|_context, _args| {
            // TODO: implement me!
        })
        .delete_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv6::enabled::PATH)
        .modify_apply(|_context, _args| {
            // TODO: implement me!
        })
        .path(interfaces::interface::ipv6::address::PATH)
        .create_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let addr = args.dnode.get_ipv6_relative("./ip").unwrap();
            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();
            let addr = Ipv6Network::new(addr, plen).unwrap().into();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.insert(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressInstall(ifname, addr));
        })
        .delete_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.remove(&addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressUninstall(ifname, addr));
        })
        .lookup(|_master, list_entry, dnode| {
            let ifname = list_entry.into_interface().unwrap();
            let addr = dnode.get_ipv6_relative("./ip").unwrap();
            let plen = dnode.get_u8_relative("./prefix-length").unwrap();
            let addr = Ipv6Network::new(addr, plen).unwrap();
            ListEntry::Address(ifname, addr.into())
        })
        .path(interfaces::interface::ipv6::address::prefix_length::PATH)
        .modify_apply(|_master, _args| {
            // TODO: implement me!
        })
        .build()
}

// ===== impl Master =====

#[async_trait]
impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }

    async fn process_event(&mut self, event: Event) {
        match event {
            Event::InterfaceDelete(ifname) => {
                self.interfaces
                    .remove(&ifname, Owner::CONFIG, &self.netlink_handle, None)
                    .await;
            }
            Event::AddressInstall(ifname, addr) => {
                // If the interface is active, install the address using the
                // netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    netlink::addr_install(&self.netlink_handle, ifindex, &addr)
                        .await;
                }
            }
            Event::AddressUninstall(ifname, addr) => {
                // If the interface is active, uninstall the address using the
                // netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    netlink::addr_uninstall(
                        &self.netlink_handle,
                        ifindex,
                        &addr,
                    )
                    .await;
                }
            }
        }
    }
}
