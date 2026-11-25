//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::{ApplyError, ValidationError};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::IpAddrKind;
use holo_utils::protocol::Protocol;
use holo_utils::yang::{DataNodeRefExt, DataTreeExt};
use holo_yang::TryFromYang;
use yang5::data::DataTree;

use crate::debug::{Debug, InterfaceInactiveReason};
use crate::ibus;
use crate::instance::Instance;
use crate::interface::{Interface, InterfaceIndex, SplitHorizon};
use crate::northbound::yang_gen::config::{self, ConfigChange, InterfaceChange, InterfaceEntryChange, InterfaceNeighborChange, TraceOptionsFlagChange, TraceOptionsFlagEntryChange};
use crate::northbound::yang_gen::rip;
use crate::northbound::yang_gen::routing::control_plane_protocols::control_plane_protocol;
use crate::route::{Metric, RouteFlags};
use crate::version::Version;

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

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub default_metric: Metric,
    pub distance: u8,
    pub triggered_update_threshold: u8,
    pub update_interval: Duration,
    pub invalid_interval: Duration,
    pub flush_interval: Duration,
    pub trace_opts: TraceOptions,
}

#[derive(Debug)]
pub struct InterfaceCfg<V: Version> {
    pub cost: Metric,
    pub explicit_neighbors: HashSet<V::IpAddr>,
    pub no_listen: bool,
    pub passive: bool,
    pub split_horizon: SplitHorizon,
    pub invalid_interval: Duration,
    pub flush_interval: Duration,
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

// ===== helper functions =====

fn apply_instance<V>(instance: &mut Instance<V>, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        ConfigChange::DefaultMetric(default_metric) => {
            instance.config.default_metric = Metric::from(default_metric);
        }
        ConfigChange::Distance(distance) => {
            instance.config.distance = distance;
            event_queue.insert(Event::ReinstallRoutes);
        }
        ConfigChange::TriggeredUpdateThreshold(threshold) => {
            instance.config.triggered_update_threshold = threshold;
        }
        ConfigChange::TimersUpdateInterval(update_interval) => {
            instance.config.update_interval = Duration::from_secs(update_interval.into());
            event_queue.insert(Event::ResetUpdateInterval);
        }
        ConfigChange::TimersInvalidInterval(invalid_interval) => {
            instance.config.invalid_interval = Duration::from_secs(invalid_interval.into());
        }
        ConfigChange::TimersFlushInterval(flush_interval) => {
            instance.config.flush_interval = Duration::from_secs(flush_interval.into());
        }
        ConfigChange::TraceOptionsFlag(keys, change) => {
            apply_trace_options(instance, keys.name, change)?;
        }
        ConfigChange::Interface(keys, change) => {
            apply_interface(instance, keys.interface, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_trace_options<V>(instance: &mut Instance<V>, trace_opt: TraceOption, change: TraceOptionsFlagChange) -> Result<(), ApplyError>
where
    V: Version,
{
    let trace_opts = &mut instance.config.trace_opts;
    match change {
        TraceOptionsFlagChange::Create => match trace_opt {
            TraceOption::Events => trace_opts.events = true,
            TraceOption::InternalBus => trace_opts.ibus = true,
            TraceOption::Packets => {
                trace_opts.packets_tx = true;
                trace_opts.packets_rx = true;
            }
            TraceOption::Route => trace_opts.route = true,
        },
        TraceOptionsFlagChange::Delete => match trace_opt {
            TraceOption::Events => trace_opts.events = false,
            TraceOption::InternalBus => trace_opts.ibus = false,
            TraceOption::Packets => {
                trace_opts.packets_tx = false;
                trace_opts.packets_rx = false;
            }
            TraceOption::Route => trace_opts.route = false,
        },
        TraceOptionsFlagChange::Entry(TraceOptionsFlagEntryChange::Send(enable)) => {
            if trace_opt == TraceOption::Packets {
                trace_opts.packets_tx = enable;
            }
        }
        TraceOptionsFlagChange::Entry(TraceOptionsFlagEntryChange::Receive(enable)) => {
            if trace_opt == TraceOption::Packets {
                trace_opts.packets_rx = enable;
            }
        }
    }

    Ok(())
}

fn apply_interface<V>(instance: &mut Instance<V>, ifname: String, change: InterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        InterfaceChange::Create => {
            let (iface_idx, _) = instance.interfaces.add(&ifname);
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        }
        InterfaceChange::Delete => {
            let (iface_idx, _) = instance.interfaces.get_mut_by_name(&ifname).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::InterfaceDelete(iface_idx));
        }
        InterfaceChange::Entry(change) => {
            let (iface_idx, iface) = instance.interfaces.get_mut_by_name(&ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                InterfaceEntryChange::Cost(cost) => {
                    iface.config.cost = Metric::from(cost);
                    event_queue.insert(Event::InterfaceCostUpdate(iface_idx));
                }
                InterfaceEntryChange::Neighbor(keys, change) => {
                    let Some(addr) = V::IpAddr::get(keys.address) else {
                        return Ok(());
                    };
                    apply_interface_neighbor(iface, addr, change)?;
                }
                InterfaceEntryChange::NoListen(op) => {
                    let no_listen = op == ConfigOp::Create;
                    iface.config.no_listen = no_listen;
                    if no_listen {
                        event_queue.insert(Event::LeaveMulticast(iface_idx));
                    } else {
                        event_queue.insert(Event::JoinMulticast(iface_idx));
                    }
                }
                InterfaceEntryChange::Passive(op) => {
                    iface.config.passive = op == ConfigOp::Create;
                }
                InterfaceEntryChange::SplitHorizon(split_horizon) => {
                    iface.config.split_horizon = split_horizon;
                }
                InterfaceEntryChange::TimersInvalidInterval(invalid_interval) => {
                    iface.config.invalid_interval = Duration::from_secs(invalid_interval.into());
                }
                InterfaceEntryChange::TimersFlushInterval(flush_interval) => {
                    iface.config.flush_interval = Duration::from_secs(flush_interval.into());
                }
                InterfaceEntryChange::AuthenticationKey(auth_key) => {
                    iface.config.auth_key = auth_key;
                    event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
                }
                InterfaceEntryChange::AuthenticationCryptoAlgorithm(auth_algo) => {
                    iface.config.auth_algo = auth_algo;
                    event_queue.insert(Event::InterfaceRestartNetTasks(iface_idx));
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_neighbor<V>(iface: &mut Interface<V>, addr: V::IpAddr, change: InterfaceNeighborChange) -> Result<(), ApplyError>
where
    V: Version,
{
    match change {
        InterfaceNeighborChange::Create => {
            iface.config.explicit_neighbors.insert(addr);
        }
        InterfaceNeighborChange::Delete => {
            iface.config.explicit_neighbors.remove(&addr);
        }
    }

    Ok(())
}

fn process_event<V>(instance: &mut Instance<V>, event: Event)
where
    V: Version,
{
    match event {
        Event::InterfaceUpdate(iface_idx) => {
            let Some((mut instance, interfaces)) = instance.as_up() else {
                return;
            };

            let iface = &mut interfaces[iface_idx];
            iface.update(&mut instance);
        }
        Event::InterfaceDelete(iface_idx) => {
            if let Some((mut instance, interfaces)) = instance.as_up() {
                let iface = &mut interfaces[iface_idx];

                // Stop interface if it's active.
                let reason = InterfaceInactiveReason::AdminDown;
                iface.stop(&mut instance, reason);
            }

            // Cancel ibus subscription.
            let iface = &mut instance.interfaces[iface_idx];
            instance.tx.ibus.interface_unsub(Some(iface.name.clone()));

            instance.interfaces.delete(iface_idx);
        }
        Event::InterfaceCostUpdate(iface_idx) => {
            let Some((instance, interfaces)) = instance.as_up() else {
                return;
            };

            let iface = &interfaces[iface_idx];
            if !iface.state.active {
                return;
            }

            let distance = instance.config.distance;
            for route in instance.state.routes.values_mut().filter(|route| !route.metric.is_infinite()) {
                // Calculate new route metric.
                let mut metric = iface.config.cost;
                if let Some(rcvd_metric) = route.rcvd_metric {
                    metric.add(rcvd_metric);
                }

                if instance.config.trace_opts.route {
                    Debug::<V>::RouteUpdate(&route.prefix, &route.source, &metric).log();
                }

                // Update route.
                route.metric = metric;
                route.flags.insert(RouteFlags::CHANGED);

                // Signal the output process to trigger an update.
                instance.tx.protocol_input.trigger_update();

                if !metric.is_infinite() {
                    // Reinstall route.
                    ibus::tx::route_install(&instance.tx.ibus, route, distance);
                } else {
                    // Uninstall route.
                    ibus::tx::route_uninstall(&instance.tx.ibus, route);
                    route.garbage_collection_start(iface.config.flush_interval, &instance.tx.protocol_input.route_gc_timeout);
                }
            }
        }
        Event::InterfaceRestartNetTasks(iface_idx) => {
            let Some((instance, interfaces)) = instance.as_up() else {
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
            instance.tx.ibus.interface_sub(Some(ifname), Some(V::ADDRESS_FAMILY));
        }
        Event::JoinMulticast(iface_idx) => {
            let iface = &mut instance.interfaces[iface_idx];
            if let Some(net) = &iface.state.net {
                iface.system.join_multicast(&net.socket);
            }
        }
        Event::LeaveMulticast(iface_idx) => {
            let iface = &mut instance.interfaces[iface_idx];
            if let Some(net) = &iface.state.net {
                iface.system.leave_multicast(&net.socket);
            }
        }
        Event::ReinstallRoutes => {
            let Some((instance, _)) = instance.as_up() else {
                return;
            };

            for route in instance.state.routes.values() {
                let distance = instance.config.distance;
                ibus::tx::route_install(&instance.tx.ibus, route, distance);
            }
        }
        Event::ResetUpdateInterval => {
            let Some((instance, _)) = instance.as_up() else {
                return;
            };

            instance.state.update_interval_task.reset(Some(instance.config.update_interval));
        }
    }
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_instance(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let default_metric = Metric::from(rip::default_metric::DFLT);
        let distance = rip::distance::DFLT;
        let triggered_update_threshold = rip::triggered_update_threshold::DFLT;
        let update_interval = Duration::from_secs(rip::timers::update_interval::DFLT.into());
        let invalid_interval = Duration::from_secs(rip::timers::invalid_interval::DFLT.into());
        let flush_interval = Duration::from_secs(rip::timers::flush_interval::DFLT.into());

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
        let invalid_interval = Duration::from_secs(rip::interfaces::interface::timers::invalid_interval::DFLT.into());
        let flush_interval = Duration::from_secs(rip::interfaces::interface::timers::flush_interval::DFLT.into());

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

// ===== global functions =====

pub fn validate(config: &DataTree<'static>) -> Result<(), ValidationError> {
    // Ensure explicit neighbor addresses match the RIP version.
    for dnode in config.iter_path(rip::interfaces::interface::neighbors::neighbor::address::PATH) {
        let Some(ptype) = dnode.ancestor(control_plane_protocol::PATH).and_then(|dnode| dnode.get_typed_relative::<Protocol>("./type")) else {
            let message = "failed to retrieve data node";
            return Err(ValidationError::new(&dnode, message));
        };
        let Some(addr) = dnode.get_typed::<IpAddr>() else {
            let message = "failed to parse data node value";
            return Err(ValidationError::new(&dnode, message));
        };
        match ptype {
            Protocol::RIPV2 if addr.is_ipv6() => {
                let message = "unexpected IPv6 address";
                return Err(ValidationError::new(&dnode, message));
            }
            Protocol::RIPNG if addr.is_ipv4() => {
                let message = "unexpected IPv4 address";
                return Err(ValidationError::new(&dnode, message));
            }
            _ => (),
        }
    }

    Ok(())
}
