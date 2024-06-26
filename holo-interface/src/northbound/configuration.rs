//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::interfaces;
use holo_utils::yang::DataNodeRefExt;
use ipnetwork::IpNetwork;

use crate::interface::Owner;
use crate::{netlink, Master};

static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Interface(String),
    Address(String, IpAddr),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InterfaceDelete(String),
    AdminStatusChange(String, bool),
    MtuChange(String, u32),
    VlanCreate(String, u16),
    AddressInstall(String, IpAddr, u8),
    AddressUninstall(String, IpAddr, u8),
}

// ===== configuration structs =====

#[derive(Debug)]
pub struct InterfaceCfg {
    pub enabled: bool,
    pub mtu: Option<u32>,
    pub parent: Option<String>,
    pub vlan_id: Option<u16>,
    pub addr_list: BTreeMap<IpAddr, u8>,
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
        .modify_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let enabled = args.dnode.get_bool();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::AdminStatusChange(ifname, enabled));
        })
        .path(interfaces::interface::parent_interface::PATH)
        .modify_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let parent = args.dnode.get_string();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.parent = Some(parent);
        })
        .delete_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.parent = None;
        })
        .path(interfaces::interface::encapsulation::dot1q_vlan::outer_tag::vlan_id::PATH)
        .modify_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let vlan_id = args.dnode.get_u16();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.vlan_id = Some(vlan_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::VlanCreate(ifname, vlan_id));
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
        .path(interfaces::interface::ipv4::mtu::PATH)
        .modify_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let mtu = args.dnode.get_u16() as u32;

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.mtu = Some(mtu);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MtuChange(ifname, mtu));
        })
        .delete_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.mtu = None;
        })
        .path(interfaces::interface::ipv4::address::PATH)
        .create_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let addr = args.dnode.get_ipv4_relative("./ip").unwrap().into();
            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.insert(addr, plen);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
        })
        .delete_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();
            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.remove(&addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressUninstall(ifname, addr, plen));
        })
        .lookup(|_master, list_entry, dnode| {
            let ifname = list_entry.into_interface().unwrap();
            let addr = dnode.get_ipv4_relative("./ip").unwrap();
            ListEntry::Address(ifname, addr.into())
        })
        .path(interfaces::interface::ipv4::address::prefix_length::PATH)
        .modify_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            let plen = args.dnode.get_u8();
            let old_plen = iface.config.addr_list.insert(addr, plen).unwrap();

            let event_queue = args.event_queue;
            if plen != old_plen {
                event_queue.insert(Event::AddressUninstall(ifname.clone(), addr, old_plen));
            }
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
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
        .path(interfaces::interface::ipv6::mtu::PATH)
        .modify_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let mtu = args.dnode.get_u32();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.mtu = Some(mtu);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MtuChange(ifname, mtu));
        })
        .delete_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.mtu = None;
        })
        .path(interfaces::interface::ipv6::address::PATH)
        .create_apply(|master, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let addr = args.dnode.get_ipv6_relative("./ip").unwrap().into();
            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.insert(addr, plen);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
        })
        .delete_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let plen = args.dnode.get_u8_relative("./prefix-length").unwrap();
            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            iface.config.addr_list.remove(&addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AddressUninstall(ifname, addr, plen));
        })
        .lookup(|_master, list_entry, dnode| {
            let ifname = list_entry.into_interface().unwrap();
            let addr = dnode.get_ipv6_relative("./ip").unwrap();
            ListEntry::Address(ifname, addr.into())
        })
        .path(interfaces::interface::ipv6::address::prefix_length::PATH)
        .modify_apply(|master, args| {
            let (ifname, addr) = args.list_entry.into_address().unwrap();

            let iface = master.interfaces.get_mut_by_name(&ifname).unwrap();
            let plen = args.dnode.get_u8();
            let old_plen = iface.config.addr_list.insert(addr, plen).unwrap();

            let event_queue = args.event_queue;
            if plen != old_plen {
                event_queue.insert(Event::AddressUninstall(ifname.clone(), addr, old_plen));
            }
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(interfaces::interface::PATH)
        .validate(|args| {
            // Validate MTUs.
            if let Some(mtu4) = args.dnode.get_u16_relative("./ipv4/mtu")
                && let Some(mtu6) = args.dnode.get_u32_relative("./ipv6/mtu")
                && mtu4 as u32 != mtu6
            {
                return Err("IPv4 MTU and IPv6 MTU must be the same".to_owned());
            }

            Ok(())
        })
        .build()
}

// ===== impl Master =====

#[async_trait]
impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

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
            Event::AdminStatusChange(ifname, enabled) => {
                // If the interface is active, change its administrative status
                // using the netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    netlink::admin_status_change(
                        &self.netlink_handle,
                        ifindex,
                        enabled,
                    )
                    .await;
                }
            }
            Event::MtuChange(ifname, mtu) => {
                // If the interface is active, change its MTU using the netlink
                // handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    netlink::mtu_change(&self.netlink_handle, ifindex, mtu)
                        .await;
                }
            }
            Event::VlanCreate(ifname, vlan_id) => {
                // If the parent interface is active, create VLAN subinterface
                // using the netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && iface.ifindex.is_none()
                    && let Some(parent) = &iface.config.parent
                    && let Some(parent) = self.interfaces.get_by_name(parent)
                    && let Some(parent_ifindex) = parent.ifindex
                {
                    netlink::vlan_create(
                        &self.netlink_handle,
                        iface.name.clone(),
                        parent_ifindex,
                        vlan_id,
                    )
                    .await;
                }
            }
            Event::AddressInstall(ifname, addr, plen) => {
                // If the interface is active, install the address using the
                // netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    let addr = IpNetwork::new(addr, plen).unwrap();
                    netlink::addr_install(&self.netlink_handle, ifindex, &addr)
                        .await;
                }
            }
            Event::AddressUninstall(ifname, addr, plen) => {
                // If the interface is active, uninstall the address using the
                // netlink handle.
                if let Some(iface) = self.interfaces.get_by_name(&ifname)
                    && let Some(ifindex) = iface.ifindex
                {
                    let addr = IpNetwork::new(addr, plen).unwrap();
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

// ===== configuration defaults =====

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let enabled = interfaces::interface::enabled::DFLT;

        InterfaceCfg {
            enabled,
            mtu: None,
            parent: None,
            vlan_id: None,
            addr_list: Default::default(),
        }
    }
}
