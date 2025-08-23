//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashSet;
use std::sync::LazyLock as Lazy;
use std::time::Duration;

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::rip;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::IpAddrKind;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::{ToYang, TryFromYang};

use crate::debug::{Debug, InterfaceInactiveReason};
use crate::ibus;
use crate::instance::Instance;
use crate::interface::{InterfaceIndex, SplitHorizon};
use crate::route::{Metric, RouteFlags};
use crate::version::{Ripng, Ripv2, Version};

#[derive(Debug, EnumAsInner)]
pub enum ListEntry<V: Version> {
    None,
    Interface(InterfaceIndex),
    StaticNbr(InterfaceIndex, V::IpAddr),
    TraceOption(TraceOption),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InterfaceUpdate(InterfaceIndex),
    InterfaceDelete(InterfaceIndex),
    InterfaceCostUpdate(InterfaceIndex),
    InterfaceRestartNetTasks(InterfaceIndex),
    InterfaceIbusSub(String),
    JoinMulticast(InterfaceIndex),
    LeaveMulticast(InterfaceIndex),
    ReinstallRoutes,
    ResetUpdateInterval,
}

pub static VALIDATION_CALLBACKS_RIPV2: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ripv2);
pub static VALIDATION_CALLBACKS_RIPNG: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ripng);
pub static CALLBACKS_RIPV2: Lazy<Callbacks<Instance<Ripv2>>> =
    Lazy::new(load_callbacks_ripv2);
pub static CALLBACKS_RIPNG: Lazy<Callbacks<Instance<Ripng>>> =
    Lazy::new(load_callbacks_ripng);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub default_metric: Metric,
    pub distance: u8,
    pub triggered_update_threshold: u8,
    pub update_interval: u16,
    pub invalid_interval: u16,
    pub flush_interval: u16,
    pub trace_opts: TraceOptions,
}

#[derive(Debug)]
pub struct InterfaceCfg<V: Version> {
    pub cost: Metric,
    pub explicit_neighbors: HashSet<V::IpAddr>,
    pub no_listen: bool,
    pub passive: bool,
    pub split_horizon: SplitHorizon,
    pub invalid_interval: u16,
    pub flush_interval: u16,
    pub auth_key: Option<String>,
    pub auth_algo: Option<CryptoAlgo>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TraceOption {
    Events,
    InternalBus,
    Packets,
    Route,
}

#[derive(Debug, Default)]
pub struct TraceOptions {
    pub events: bool,
    pub ibus: bool,
    pub packets_tx: bool,
    pub packets_rx: bool,
    pub route: bool,
}

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(rip::default_metric::PATH)
        .modify_apply(|instance, args| {
            let default_metric = args.dnode.get_u8();
            let default_metric = Metric::from(default_metric);
            instance.config.default_metric = default_metric;
        })
        .path(rip::distance::PATH)
        .modify_apply(|instance, args| {
            let distance = args.dnode.get_u8();
            instance.config.distance = distance;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(rip::triggered_update_threshold::PATH)
        .modify_apply(|instance, args| {
            let threshold = args.dnode.get_u8();
            instance.config.triggered_update_threshold = threshold;
        })
        .path(rip::timers::update_interval::PATH)
        .modify_apply(|instance, args| {
            let update_interval = args.dnode.get_u16();
            instance.config.update_interval = update_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetUpdateInterval);
        })
        .path(rip::timers::invalid_interval::PATH)
        .modify_apply(|instance, args| {
            let invalid_interval = args.dnode.get_u16();
            instance.config.invalid_interval = invalid_interval;
        })
        .path(rip::timers::flush_interval::PATH)
        .modify_apply(|instance, args| {
            let flush_interval = args.dnode.get_u16();
            instance.config.flush_interval = flush_interval;
        })
        .path(rip::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = TraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                TraceOption::Events => trace_opts.events = true,
                TraceOption::InternalBus => trace_opts.ibus = true,
                TraceOption::Packets => {
                    trace_opts.packets_tx = true;
                    trace_opts.packets_rx = true;
                }
                TraceOption::Route => trace_opts.route = true,
            }
        })
        .delete_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                TraceOption::Events => trace_opts.events = false,
                TraceOption::InternalBus => trace_opts.ibus = false,
                TraceOption::Packets => {
                    trace_opts.packets_tx = false;
                    trace_opts.packets_rx = false;
                }
                TraceOption::Route => trace_opts.route = false,
            }
        })
        .lookup(|_instance, _list_entry, dnode| {
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = TraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::TraceOption(trace_opt)
        })
        .path(rip::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            if trace_opt == TraceOption::Packets {
                trace_opts.packets_tx = enable;
            }
        })
        .path(rip::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            if trace_opt == TraceOption::Packets {
                trace_opts.packets_rx = enable;
            }
        })
        .path(rip::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let ifname = args.dnode.get_string_relative("interface").unwrap();
            let (iface_idx, _) = instance.interfaces.add(&ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        })
        .delete_apply(|_instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceDelete(iface_idx));
        })
        .lookup(|instance, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("./interface").unwrap();
            instance
                .interfaces
                .get_mut_by_name(&ifname)
                .map(|(iface_idx, _)| ListEntry::Interface(iface_idx))
                .expect("could not find RIP interface")
        })
        .path(rip::interfaces::interface::cost::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let cost = args.dnode.get_u8();
            let cost = Metric::from(cost);
            iface.config.cost = cost;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceCostUpdate(iface_idx));
        })
        .path(rip::interfaces::interface::neighbors::neighbor::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let addr = args.dnode.get_ip_relative("address").unwrap();
            let addr = V::IpAddr::get(addr).unwrap();
            iface.config.explicit_neighbors.insert(addr);
        })
        .delete_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.explicit_neighbors.remove(&addr);
        })
        .lookup(|_instance, list_entry, dnode| {
            let iface_idx = list_entry.into_interface().unwrap();

            let addr = dnode.get_ip_relative("address").unwrap();
            let addr = V::IpAddr::get(addr).unwrap();
            ListEntry::StaticNbr(iface_idx, addr)
        })
        .path(rip::interfaces::interface::no_listen::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.no_listen = true;

            let event_queue = args.event_queue;
            event_queue.insert(Event::LeaveMulticast(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.no_listen = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::JoinMulticast(iface_idx));
        })
        .path(rip::interfaces::interface::passive::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.passive = true;
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.passive = false;
        })
        .path(rip::interfaces::interface::split_horizon::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let split_horizon = args.dnode.get_string();
            let split_horizon =
                SplitHorizon::try_from_yang(&split_horizon).unwrap();
            iface.config.split_horizon = split_horizon;
        })
        .path(rip::interfaces::interface::timers::invalid_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let invalid_interval = args.dnode.get_u16();
            iface.config.invalid_interval = invalid_interval;
        })
        .path(rip::interfaces::interface::timers::flush_interval::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let flush_interval = args.dnode.get_u16();
            iface.config.flush_interval = flush_interval;
        })
        .build()
}

fn load_callbacks_ripv2() -> Callbacks<Instance<Ripv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ripv2>>::new(core_cbs)
        .path(rip::interfaces::interface::authentication::key::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
        })
        .path(
            rip::interfaces::interface::authentication::crypto_algorithm::PATH,
        )
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
        })
        .build()
}

fn load_callbacks_ripng() -> Callbacks<Instance<Ripng>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ripng>>::new(core_cbs).build()
}

fn load_validation_callbacks_ripv2() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(rip::interfaces::interface::neighbors::neighbor::address::PATH)
        .validate(|args| {
            if args.dnode.get_ip().is_ipv6() {
                return Err("unexpected IPv6 address".to_owned());
            }
            Ok(())
        })
        .path(
            rip::interfaces::interface::authentication::crypto_algorithm::PATH,
        )
        .validate(|args| {
            let algo = args.dnode.get_string();
            if algo != CryptoAlgo::Md5.to_yang() {
                return Err(format!(
                    "unsupported cryptographic algorithm (valid options: \"{}\")",
                    CryptoAlgo::Md5.to_yang()
                ));
            }
            Ok(())
        })
        .build()
}

fn load_validation_callbacks_ripng() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(rip::interfaces::interface::neighbors::neighbor::address::PATH)
        .validate(|args| {
            if args.dnode.get_ip().is_ipv4() {
                return Err("unexpected IPv4 address".to_owned());
            }
            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry = ListEntry<V>;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        V::validation_callbacks()
    }

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::configuration_callbacks()
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InterfaceUpdate(iface_idx) => {
                let Some((mut instance, interfaces)) = self.as_up() else {
                    return;
                };

                let iface = &mut interfaces[iface_idx];
                iface.update(&mut instance);
            }
            Event::InterfaceDelete(iface_idx) => {
                if let Some((mut instance, interfaces)) = self.as_up() {
                    let iface = &mut interfaces[iface_idx];

                    // Stop interface if it's active.
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.stop(&mut instance, reason);
                }

                // Cancel ibus subscription.
                let iface = &mut self.interfaces[iface_idx];
                self.tx.ibus.interface_unsub(Some(iface.name.clone()));

                self.interfaces.delete(iface_idx);
            }
            Event::InterfaceCostUpdate(iface_idx) => {
                let Some((instance, interfaces)) = self.as_up() else {
                    return;
                };

                let iface = &interfaces[iface_idx];
                if !iface.state.active {
                    return;
                }

                let distance = instance.config.distance;
                for route in instance
                    .state
                    .routes
                    .values_mut()
                    .filter(|route| !route.metric.is_infinite())
                {
                    // Calculate new route metric.
                    let mut metric = iface.config.cost;
                    if let Some(rcvd_metric) = route.rcvd_metric {
                        metric.add(rcvd_metric);
                    }

                    if instance.config.trace_opts.route {
                        Debug::<V>::RouteUpdate(
                            &route.prefix,
                            &route.source,
                            &metric,
                        )
                        .log();
                    }

                    // Update route.
                    route.metric = metric;
                    route.flags.insert(RouteFlags::CHANGED);

                    // Signal the output process to trigger an update.
                    instance.tx.protocol_input.trigger_update();

                    if !metric.is_infinite() {
                        // Reinstall route.
                        ibus::tx::route_install(
                            &instance.tx.ibus,
                            route,
                            distance,
                        );
                    } else {
                        // Uninstall route.
                        ibus::tx::route_uninstall(&instance.tx.ibus, route);
                        route.garbage_collection_start(
                            iface.config.flush_interval,
                            &instance.tx.protocol_input.route_gc_timeout,
                        );
                    }
                }
            }
            Event::InterfaceRestartNetTasks(iface_idx) => {
                let Some((instance, interfaces)) = self.as_up() else {
                    return;
                };

                let iface = &mut interfaces[iface_idx];
                if !iface.state.active {
                    return;
                }

                // Restart network Tx/Rx tasks.
                let auth = iface.auth(&instance.state.auth_seqno);
                if let Some(net) = &mut iface.state.net {
                    net.restart_tasks(auth, instance.tx);
                }
            }
            Event::InterfaceIbusSub(ifname) => {
                self.tx
                    .ibus
                    .interface_sub(Some(ifname), Some(V::ADDRESS_FAMILY));
            }
            Event::JoinMulticast(iface_idx) => {
                let iface = &mut self.interfaces[iface_idx];
                if let Some(net) = &iface.state.net {
                    iface.system.join_multicast(&net.socket);
                }
            }
            Event::LeaveMulticast(iface_idx) => {
                let iface = &mut self.interfaces[iface_idx];
                if let Some(net) = &iface.state.net {
                    iface.system.leave_multicast(&net.socket);
                }
            }
            Event::ReinstallRoutes => {
                let Some((instance, _)) = self.as_up() else {
                    return;
                };

                for route in instance.state.routes.values() {
                    let distance = instance.config.distance;
                    ibus::tx::route_install(&instance.tx.ibus, route, distance);
                }
            }
            Event::ResetUpdateInterval => {
                let Some((instance, _)) = self.as_up() else {
                    return;
                };

                let interval =
                    Duration::from_secs(instance.config.update_interval.into());
                instance.state.update_interval_task.reset(Some(interval));
            }
        }
    }
}

// ===== impl ListEntry =====

#[allow(clippy::derivable_impls)]
impl<V> Default for ListEntry<V>
where
    V: Version,
{
    fn default() -> ListEntry<V> {
        ListEntry::None
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let default_metric = Metric::from(rip::default_metric::DFLT);
        let distance = rip::distance::DFLT;
        let triggered_update_threshold = rip::triggered_update_threshold::DFLT;
        let update_interval = rip::timers::update_interval::DFLT;
        let invalid_interval = rip::timers::invalid_interval::DFLT;
        let flush_interval = rip::timers::flush_interval::DFLT;

        InstanceCfg {
            default_metric,
            distance,
            triggered_update_threshold,
            update_interval,
            invalid_interval,
            flush_interval,
            trace_opts: Default::default(),
        }
    }
}

impl<V> Default for InterfaceCfg<V>
where
    V: Version,
{
    fn default() -> InterfaceCfg<V> {
        let cost = Metric::from(rip::interfaces::interface::cost::DFLT);
        let split_horizon = rip::interfaces::interface::split_horizon::DFLT;
        let split_horizon = SplitHorizon::try_from_yang(split_horizon).unwrap();
        let invalid_interval =
            rip::interfaces::interface::timers::invalid_interval::DFLT;
        let flush_interval =
            rip::interfaces::interface::timers::flush_interval::DFLT;

        InterfaceCfg {
            cost,
            explicit_neighbors: Default::default(),
            no_listen: false,
            passive: false,
            split_horizon,
            invalid_interval,
            flush_interval,
            auth_key: None,
            auth_algo: None,
        }
    }
}
