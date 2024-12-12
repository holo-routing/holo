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

use crate::instance::{fsm, Instance};
use crate::interface::Interface;
use crate::southbound;

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
    InstanceStart { vrid: u8 },
    InstanceDelete { vrid: u8 },
    VirtualAddressCreate { vrid: u8, addr: Ipv4Network },
    VirtualAddressDelete { vrid: u8, addr: Ipv4Network },
    ResetTimer { vrid: u8 },
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
        .create_apply(|interface, args| {
            let vrid = args.dnode.get_u8_relative("./vrid").unwrap();
            let mut instance = Instance::new(vrid);
            instance.state.last_event = fsm::Event::Startup;
            interface.instances.insert(vrid, instance);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceStart { vrid });
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
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            let priority = args.dnode.get_u8();
            instance.config.priority = priority;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetTimer { vrid });
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
        .create_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            let addr = args.dnode.get_prefix4_relative("ipv4-address").unwrap();
            instance.config.virtual_addresses.insert(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::VirtualAddressCreate { vrid, addr });
        })
        .delete_apply(|interface, args| {
            let (vrid, addr) = args.list_entry.into_virtual_ipv4_addr().unwrap();
            let instance = interface.instances.get_mut(&vrid).unwrap();

            instance.config.virtual_addresses.remove(&addr);

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
            Event::InstanceStart { vrid } => {
                let (interface, instance) = self.get_instance(vrid).unwrap();

                // Create macvlan interface.
                let virtual_mac_addr: [u8; 6] =
                    [0x00, 0x00, 0x5e, 0x00, 0x01, vrid];
                southbound::tx::mvlan_create(
                    &interface.tx.ibus,
                    interface.name.to_owned(),
                    instance.mvlan.name.clone(),
                    virtual_mac_addr,
                );
            }
            Event::InstanceDelete { vrid } => {
                let mut instance = self.instances.remove(&vrid).unwrap();
                let interface = self.as_view();

                // Shut down the instance.
                instance.shutdown(&interface);

                // Delete macvlan interface.
                southbound::tx::mvlan_delete(
                    &interface.tx.ibus,
                    &instance.mvlan.name,
                );
            }
            Event::VirtualAddressCreate { vrid, addr } => {
                let (interface, instance) = self.get_instance(vrid).unwrap();

                if instance.state.state == fsm::State::Master {
                    southbound::tx::ip_addr_add(
                        &interface.tx.ibus,
                        &instance.mvlan.name,
                        addr,
                    );
                    instance.timer_set(&interface);
                }
            }
            Event::VirtualAddressDelete { vrid, addr } => {
                let (interface, instance) = self.get_instance(vrid).unwrap();

                if instance.state.state == fsm::State::Master {
                    southbound::tx::ip_addr_del(
                        &interface.tx.ibus,
                        &instance.mvlan.name,
                        addr,
                    );
                    instance.timer_set(&interface);
                }
            }
            Event::ResetTimer { vrid } => {
                let (_, instance) = self.get_instance(vrid).unwrap();
                instance.timer_reset();
            }
        }
    }
}

// ===== configuration helpers =====

impl InstanceCfg {
    pub(crate) const fn master_down_interval(&self) -> u32 {
        (3 * self.advertise_interval as u32) + self.skew_time() as u32
    }

    pub(crate) const fn skew_time(&self) -> f32 {
        (256_f32 - self.priority as f32) / 256_f32
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
