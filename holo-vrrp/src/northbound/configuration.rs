//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock as Lazy, atomic};

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang::interfaces;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use crate::ibus;
use crate::instance::{Instance, Version, fsm};
use crate::interface::Interface;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Vrid(u8),
    VirtualIpv4Addr(u8, Ipv4Network),
    VirtualIpv6Addr(u8, Ipv6Network),
    TraceOption(TraceOption),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceStart {
        vrid: u8,
        af: AddressFamily,
    },
    InstanceDelete {
        vrid: u8,
        af: AddressFamily,
    },
    VirtualAddressCreate {
        vrid: u8,
        af: AddressFamily,
        addr: IpNetwork,
    },
    VirtualAddressDelete {
        vrid: u8,
        af: AddressFamily,
        addr: IpNetwork,
    },
    ResetTimer {
        vrid: u8,
        af: AddressFamily,
    },
}

pub static CALLBACKS: Lazy<Callbacks<Interface>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug, Default)]
pub struct InterfaceCfg {
    pub trace_opts: TraceOptions,
}

#[derive(Debug)]
pub struct InstanceCfg {
    pub log_state_change: bool,
    pub preempt: bool,
    pub priority: u8,
    pub advertise_interval: u16,
    pub version: Version,
    pub virtual_addresses: BTreeSet<IpNetwork>,
}

#[derive(Clone, Copy, Debug)]
pub enum TraceOption {
    Events,
    InternalBus,
    Packets,
}

#[derive(Debug, Default)]
pub struct TraceOptions {
    pub events: bool,
    pub ibus: bool,
    pub packets: Arc<AtomicBool>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Interface> {
    CallbacksBuilder::<Interface>::default()
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::PATH)
        .create_apply(|interface, args| {
            let vrid = args.dnode.get_u8_relative("./vrid").unwrap();
            let mut instance = Instance::new(vrid, AddressFamily::Ipv4);
            instance.state.last_event = fsm::Event::Startup;
            interface.vrrp_ipv4_instances.insert(vrid, instance);

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv4;
            event_queue.insert(Event::InstanceStart { vrid, af });
        })
        .delete_apply(|_interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv4;
            event_queue.insert(Event::InstanceDelete { vrid, af });
        })
        .lookup(|_instance, _list_entry, dnode| {
            let vrid = dnode.get_u8_relative("./vrid").unwrap();
            ListEntry::Vrid(vrid)
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::version::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let version = args.dnode.get_string();
            let version = match version.as_str() {
                "ietf-vrrp:vrrp-v2" => Version::V2,
                "ietf-vrrp:vrrp-v3" => Version::V3(AddressFamily::Ipv4),
                _ => unreachable!(),
            };
            instance.config.version = version;
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::log_state_change::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let log_state_change = args.dnode.get_bool();
            instance.config.log_state_change = log_state_change;
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::preempt::enabled::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let preempt = args.dnode.get_bool();
            instance.config.preempt = preempt;
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::priority::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let priority = args.dnode.get_u8();
            instance.config.priority = priority;

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv4;
            event_queue.insert(Event::ResetTimer { vrid, af });
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::advertise_interval_sec::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let advertise_interval = args.dnode.get_u8();
            instance.config.advertise_interval = advertise_interval as u16;
        })
        .delete_apply(|_interface, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::advertise_interval_centi_sec::PATH)
        .modify_apply(|interface, args|{
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let advertise_interval = args.dnode.get_u16();
            instance.config.advertise_interval = advertise_interval;
        })
        .delete_apply(|_interface, _args| {
            // Nothing to do
        })
        .path(interfaces::interface::ipv4::vrrp::vrrp_instance::virtual_ipv4_addresses::virtual_ipv4_address::PATH)
        .create_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();

            let addr = IpNetwork::V4(
                args.dnode.get_prefix4_relative("ipv4-address").unwrap()
            );
            instance.config.virtual_addresses.insert(addr);

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv4;
            event_queue.insert(Event::VirtualAddressCreate { vrid, af, addr });
        })
        .delete_apply(|interface, args| {
            let (vrid, addr) = args.list_entry.into_virtual_ipv4_addr().unwrap();
            let instance = interface.vrrp_ipv4_instances.get_mut(&vrid).unwrap();
            let addr = IpNetwork::V4(addr);

            instance.config.virtual_addresses.remove(&addr);

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv4;
            event_queue.insert(Event::VirtualAddressDelete { vrid, af, addr });
        })
        .lookup(|_interface, list_entry, dnode| {
            let vrid = list_entry.into_vrid().unwrap();
            let addr = dnode.get_prefix4_relative("ipv4-address").unwrap();
            ListEntry::VirtualIpv4Addr(vrid, addr)
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::PATH)
        .create_apply(|interface, args| {
            let vrid = args.dnode.get_u8_relative("./vrid").unwrap();
            let mut instance = Instance::new(vrid, AddressFamily::Ipv6);
            instance.state.last_event = fsm::Event::Startup;
            interface.vrrp_ipv6_instances.insert(vrid, instance);

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv6;
            event_queue.insert(Event::InstanceStart { vrid, af });
        })
        .delete_apply(|_interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv6;
            event_queue.insert(Event::InstanceDelete { vrid, af });
        })
        .lookup(|_instance, _list_entry, dnode| {
            let vrid = dnode.get_u8_relative("./vrid").unwrap();
            ListEntry::Vrid(vrid)
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::version::PATH)
        .modify_apply(|_interface, _args| {
            // Nothing to do.
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::log_state_change::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();

            let log_state_change = args.dnode.get_bool();
            instance.config.log_state_change = log_state_change;
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::preempt::enabled::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();

            let preempt = args.dnode.get_bool();
            instance.config.preempt = preempt;
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::priority::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();

            let priority = args.dnode.get_u8();
            instance.config.priority = priority;

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv6;
            event_queue.insert(Event::ResetTimer { vrid, af } );
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::advertise_interval_centi_sec::PATH)
        .modify_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();

            let advertise_interval = args.dnode.get_u16();
            instance.config.advertise_interval = advertise_interval;
        })
        .path(interfaces::interface::ipv6::vrrp::vrrp_instance::virtual_ipv6_addresses::virtual_ipv6_address::PATH)
        .create_apply(|interface, args| {
            let vrid = args.list_entry.into_vrid().unwrap();
            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();

            let addr = IpNetwork::V6(
                args.dnode.get_prefix6_relative("ipv6-address").unwrap()
            );
            instance.config.virtual_addresses.insert(addr);

            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv6;
            event_queue.insert(Event::VirtualAddressCreate { vrid, af, addr });
        })
        .delete_apply(|interface, args| {
            let (vrid, addr) = args.list_entry.into_virtual_ipv6_addr().unwrap();

            let instance = interface.vrrp_ipv6_instances.get_mut(&vrid).unwrap();
            let addr = IpNetwork::V6(addr);

            instance.config.virtual_addresses.remove(&addr);


            let event_queue = args.event_queue;
            let af = AddressFamily::Ipv6;
            event_queue.insert(Event::VirtualAddressDelete{ vrid, af, addr });
        })
        .lookup(|_interface, list_entry, dnode| {
            let vrid = list_entry.into_vrid().unwrap();
            let addr = dnode.get_prefix6_relative("ipv6-address").unwrap();
            ListEntry::VirtualIpv6Addr(vrid, addr)
        })
        .path(interfaces::interface::vrrp::trace_options::flag::PATH)
        .create_apply(|interface, args| {
            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = TraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut interface.config.trace_opts;
            match trace_opt {
                TraceOption::Events => trace_opts.events = true,
                TraceOption::InternalBus => trace_opts.ibus = true,
                TraceOption::Packets => trace_opts.packets.store(true, atomic::Ordering::Relaxed),
            }
        })
        .delete_apply(|interface, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let trace_opts = &mut interface.config.trace_opts;
            match trace_opt {
                TraceOption::Events => trace_opts.events = false,
                TraceOption::InternalBus => trace_opts.ibus = false,
                TraceOption::Packets => trace_opts.packets.store(false, atomic::Ordering::Relaxed),
            }

        })
        .lookup(|_interface, _list_entry, dnode| {
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = TraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::TraceOption(trace_opt)
        })
        .build()
}

// ===== impl Interface =====

impl Provider for Interface {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> &'static Callbacks<Interface> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceStart { vrid, af } => {
                let (interface, instance) =
                    self.get_instance(vrid, af).unwrap();

                let virtual_mac_addr = match af {
                    AddressFamily::Ipv4 => {
                        MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x01, vrid])
                    }
                    AddressFamily::Ipv6 => {
                        MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x02, vrid])
                    }
                };
                ibus::tx::mvlan_create(
                    &interface.tx.ibus,
                    interface.name.to_owned(),
                    instance.mvlan.name.clone(),
                    virtual_mac_addr,
                );
            }
            Event::InstanceDelete { vrid, af } => {
                let mut instance = match af {
                    AddressFamily::Ipv4 => {
                        self.vrrp_ipv4_instances.remove(&vrid).unwrap()
                    }
                    AddressFamily::Ipv6 => {
                        self.vrrp_ipv6_instances.remove(&vrid).unwrap()
                    }
                };
                let interface = self.as_view();

                // Shut down the instance.
                instance.shutdown(&interface);

                // Delete macvlan interface.
                ibus::tx::mvlan_delete(
                    &interface.tx.ibus,
                    &instance.mvlan.name,
                );
            }
            Event::VirtualAddressCreate { vrid, af, addr } => {
                let (interface, instance) =
                    self.get_instance(vrid, af).unwrap();

                if instance.state.state == fsm::State::Master {
                    ibus::tx::ip_addr_add(
                        &interface.tx.ibus,
                        &instance.mvlan.name,
                        addr,
                    );
                    instance.timer_set(&interface);
                }
            }
            Event::VirtualAddressDelete { vrid, af, addr } => {
                let (interface, instance) =
                    self.get_instance(vrid, af).unwrap();

                if instance.state.state == fsm::State::Master {
                    ibus::tx::ip_addr_del(
                        &interface.tx.ibus,
                        &instance.mvlan.name,
                        addr,
                    );
                    instance.timer_set(&interface);
                }
            }
            Event::ResetTimer { vrid, af } => {
                let (_, instance) = self.get_instance(vrid, af).unwrap();
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

impl InstanceCfg {
    pub(crate) fn default(af: AddressFamily) -> InstanceCfg {
        match af {
            AddressFamily::Ipv4 => {
                use interfaces::interface::ipv4::vrrp;

                let log_state_change =
                    vrrp::vrrp_instance::log_state_change::DFLT;
                let preempt = vrrp::vrrp_instance::preempt::enabled::DFLT;
                let priority = vrrp::vrrp_instance::priority::DFLT;
                let advertise_interval =
                    vrrp::vrrp_instance::advertise_interval_sec::DFLT;
                InstanceCfg {
                    log_state_change,
                    preempt,
                    priority,
                    advertise_interval: advertise_interval.into(),
                    virtual_addresses: Default::default(),
                    version: Version::V2,
                }
            }
            AddressFamily::Ipv6 => {
                use interfaces::interface::ipv6::vrrp;

                let log_state_change =
                    vrrp::vrrp_instance::log_state_change::DFLT;
                let preempt = vrrp::vrrp_instance::preempt::enabled::DFLT;
                let priority = vrrp::vrrp_instance::priority::DFLT;
                let advertise_interval =
                    vrrp::vrrp_instance::advertise_interval_centi_sec::DFLT;
                InstanceCfg {
                    log_state_change,
                    preempt,
                    priority,
                    advertise_interval,
                    virtual_addresses: Default::default(),
                    version: Version::V3(AddressFamily::Ipv6),
                }
            }
        }
    }
}
