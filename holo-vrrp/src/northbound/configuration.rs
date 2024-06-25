//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;
use std::sync::LazyLock as Lazy;

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::interfaces;
use holo_utils::yang::DataNodeRefExt;
use ipnetwork::Ipv4Network;

use crate::interface::Interface;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Vrid(u8),
    VirtualIpv4Addr(u8, Ipv4Network),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    // instance events
    InstanceCreate { vrid: u8 },
    InstanceDelete { vrid: u8 },

    // virtual address events
    VirtualAddressCreate { vrid: u8, addr: Ipv4Network },
    VirtualAddressDelete { vrid: u8, addr: Ipv4Network },

    // priority events
    PriorityUpdate { vrid: u8, priority: u8 },
}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Interface>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub log_state_change: bool,
    pub preempt: bool,
    pub priority: u8,
    pub advertise_interval: u8,
    pub virtual_addresses: BTreeSet<Ipv4Network>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Interface> {
    CallbacksBuilder::<Interface>::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::PATH)
        .create_apply(|_interface, args| {
            let vrid = args.dnode.get_u8_relative("./vrid").unwrap();
            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceCreate { vrid });
        })
        .delete_apply(|_interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceDelete { vrid });
        })
        .lookup(|_instance, _list_entry, dnode| {
            let vrid = dnode.get_u8_relative("./vrid").unwrap();
            ListEntry::Vrid(vrid)
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::version::PATH)
        .modify_apply(|_interface, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::log_state_change::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            let log_state_change = args.dnode.get_bool();
            instance.config.log_state_change = log_state_change;
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::preempt::enabled::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            let preempt = args.dnode.get_bool();
            instance.config.preempt = preempt;
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::priority::PATH)
        .modify_apply(|_interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let event_queue = args.event_queue;
            let priority = args.dnode.get_u8();

            event_queue.insert(Event::PriorityUpdate { vrid, priority  });
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::advertise_interval_sec::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            let advertise_interval = args.dnode.get_u8();
            instance.config.advertise_interval = advertise_interval;
        })
        .delete_apply(|_interface, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::virtual_ipv4_addresses::virtual_ipv4_address::PATH)
        .create_apply(|_interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let addr = args.dnode.get_prefix4_relative("ipv4-address").unwrap();
            let event_queue = args.event_queue;
            event_queue.insert (
                Event::VirtualAddressCreate { vrid, addr }
            );
        })
        .delete_apply(|_interface, args| {
            let (vrid, addr) = args.list_entry.into_virtual_ipv4_addr().unwrap();
            let event_queue = args.event_queue;
            event_queue.insert(Event::VirtualAddressDelete { vrid, addr });
        })
        .lookup(|_interface, list_entry, dnode| {
            let vrid = list_entry.into_vrid().unwrap();
            let addr = dnode.get_prefix4_relative("ipv4-address").unwrap();
            ListEntry::VirtualIpv4Addr(vrid, addr)
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::version::PATH)
        .validate(|args| {
            let version = args.dnode.get_string();
            if version != "ietf-vrrp:vrrp-v2" {
                return Err("unsupported VRRP version".to_string());
            }

            Ok(())
        })
        .build()
}

// ===== impl Interface =====

#[async_trait]
impl Provider for Interface {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> Option<&'static Callbacks<Interface>> {
        Some(&CALLBACKS)
    }

    async fn process_event(&mut self, event: Event) {
        match event {
            // instance events
            Event::InstanceCreate { vrid } => {
                self.create_instance(vrid);

                // reminder to remove the following line.
                // currently up due to state not being properly maintained on startup.
                self.change_state(vrid, crate::instance::State::Backup);
            }
            Event::InstanceDelete { vrid } => {
                self.delete_instance(vrid);
            }

            // virtual address events
            Event::VirtualAddressCreate { vrid, addr } => {
                self.add_instance_virtual_address(vrid, addr);
            }
            Event::VirtualAddressDelete { vrid, addr } => {
                self.delete_instance_virtual_address(vrid, addr);
            }

            // priority events
            Event::PriorityUpdate { vrid, priority } => {
                if let Some(instance) = self.instances.get_mut(&vrid) {
                    instance.config.priority = priority;
                    self.reset_timer(vrid);
                }
            }
        }
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        use interfaces::interface::ipv4::vrrp;

        let log_state_change = vrrp::vrrp_instance::log_state_change::DFLT;
        let preempt = vrrp::vrrp_instance::preempt::enabled::DFLT;
        let priority = vrrp::vrrp_instance::priority::DFLT;
        let advertise_interval =
            vrrp::vrrp_instance::advertise_interval_sec::DFLT;
        InstanceCfg {
            log_state_change,
            preempt,
            priority,
            advertise_interval,
            virtual_addresses: Default::default(),
        }
    }
}
