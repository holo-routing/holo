//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_utils::yang::DataNodeRefExt;

use crate::instance::Instance;
use crate::interface::Interface;
use crate::northbound::yang_gen::igmp;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Interface(String),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InterfaceUpdate(String),
    InterfaceIbusSub(String),
}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub last_member_query_interval: u16,
    pub query_interval: u16,
    pub query_max_response_time: u16,
    pub robustness_variable: u8,
    pub enabled: bool,
    pub join_group: BTreeSet<Ipv4Addr>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(igmp::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let ifname =
                args.dnode.get_string_relative("./interface-name").unwrap();
            let iface = Interface::new(ifname.clone());
            instance.interfaces.insert(ifname.clone(), iface);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(ifname.clone()));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        })
        .delete_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            instance.interfaces.remove(&ifname);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("./interface-name").unwrap();
            ListEntry::Interface(ifname)
        })
        .path(igmp::interfaces::interface::last_member_query_interval::PATH)
        .modify_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let interval = args.dnode.get_u16();
            iface.config.last_member_query_interval = interval;
        })
        .path(igmp::interfaces::interface::query_interval::PATH)
        .modify_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let interval = args.dnode.get_u16();
            iface.config.query_interval = interval;
        })
        .path(igmp::interfaces::interface::query_max_response_time::PATH)
        .modify_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let time = args.dnode.get_u16();
            iface.config.query_max_response_time = time;
        })
        .path(igmp::interfaces::interface::robustness_variable::PATH)
        .modify_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let robustness_variable = args.dnode.get_u8();
            iface.config.robustness_variable = robustness_variable;
        })
        .path(igmp::interfaces::interface::enabled::PATH)
        .modify_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let enabled = args.dnode.get_bool();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(ifname));
        })
        .path(igmp::interfaces::interface::join_group::PATH)
        .create_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let group = args.dnode.get_ipv4();
            iface.config.join_group.insert(group);
        })
        .delete_apply(|instance, args| {
            let ifname = args.list_entry.into_interface().unwrap();
            let iface = instance.interfaces.get_mut(&ifname).unwrap();

            let group = args.dnode.get_ipv4();
            iface.config.join_group.remove(&group);
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default().build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InterfaceUpdate(ifname) => {
                let Some((mut instance, interfaces)) = self.as_up() else {
                    return;
                };
                let iface = interfaces.get_mut(&ifname).unwrap();
                iface.update(&mut instance);
            }
            Event::InterfaceIbusSub(ifname) => {
                let iface = self.interfaces.get(&ifname).unwrap();
                self.tx.ibus.interface_sub(Some(iface.name.clone()), None);
            }
        }
    }
}

// ===== configuration defaults =====

#[allow(clippy::derivable_impls)]
impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        InstanceCfg {}
    }
}

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let last_member_query_interval =
            igmp::interfaces::interface::last_member_query_interval::DFLT;
        let query_interval = igmp::interfaces::interface::query_interval::DFLT;
        let query_max_response_time =
            igmp::interfaces::interface::query_max_response_time::DFLT;
        let robustness_variable =
            igmp::interfaces::interface::robustness_variable::DFLT;
        let enabled = igmp::interfaces::interface::enabled::DFLT;

        InterfaceCfg {
            last_member_query_interval,
            query_interval,
            query_max_response_time,
            robustness_variable,
            enabled,
            join_group: Default::default(),
        }
    }
}
