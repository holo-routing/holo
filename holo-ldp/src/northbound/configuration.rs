//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use holo_northbound::configuration::{ConfigOp, Provider, YangConfigOps};
use holo_northbound::error::ApplyError;
use holo_utils::ip::AddressFamily;

use crate::collections::{InterfaceIndex, TargetedNbrIndex};
use crate::debug::InterfaceInactiveReason;
use crate::discovery::TargetedNbr;
use crate::instance::Instance;
use crate::northbound::yang_gen::config::{
    self, ConfigChange, DiscoveryInterfacesInterfaceChange, DiscoveryInterfacesInterfaceEntryChange, DiscoveryTargetedAddressFamiliesIpv4TargetChange, DiscoveryTargetedAddressFamiliesIpv4TargetEntryChange, PeersPeerChange,
    PeersPeerEntryChange,
};
use crate::northbound::yang_gen::mpls_ldp;
use crate::{neighbor, network};

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceUpdate,
    InterfaceUpdate(InterfaceIndex),
    InterfaceDelete(InterfaceIndex),
    InterfaceIbusSub(String),
    TargetedNbrUpdate(TargetedNbrIndex),
    TargetedNbrRemoveCheck(TargetedNbrIndex),
    TargetedNbrRemoveDynamic,
    StopInitBackoff,
    ResetNeighbors,
    ResetNeighbor(Ipv4Addr),
    UpdateNeighborsAuth,
    UpdateNeighborAuth(Ipv4Addr),
    CfgSeqNumberUpdate,
}

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub router_id: Option<Ipv4Addr>,
    pub session_ka_holdtime: u16,
    pub session_ka_interval: Duration,
    pub password: Option<String>,
    pub interface_hello_holdtime: u16,
    pub interface_hello_interval: Duration,
    pub targeted_hello_holdtime: u16,
    pub targeted_hello_interval: Duration,
    pub targeted_hello_accept: bool,
    pub ipv4: Option<InstanceIpv4Cfg>,
    pub neighbors: HashMap<Ipv4Addr, NeighborCfg>,
}

#[derive(Debug)]
pub struct InstanceIpv4Cfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub hello_holdtime: u16,
    pub hello_interval: Duration,
    pub ipv4: Option<InterfaceIpv4Cfg>,
}

#[derive(Debug)]
pub struct InterfaceIpv4Cfg {
    pub enabled: bool,
}

#[derive(Debug, Default)]
pub struct NeighborCfg {
    pub password: Option<String>,
}

#[derive(Debug)]
pub struct TargetedNbrCfg {
    pub enabled: bool,
    pub hello_holdtime: u16,
    pub hello_interval: Duration,
}

// ===== helper functions =====

fn apply_instance(instance: &mut Instance, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        ConfigChange::GlobalLsrId(router_id) => {
            instance.config.router_id = router_id;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::GlobalAddressFamiliesIpv4(op) => {
            match op {
                ConfigOp::Create => {
                    instance.config.ipv4 = Some(InstanceIpv4Cfg::default());
                    event_queue.insert(Event::CfgSeqNumberUpdate);
                }
                ConfigOp::Delete => {
                    instance.config.ipv4 = None;
                }
            }
            event_queue.insert(Event::InstanceUpdate);
        }
        ConfigChange::GlobalAddressFamiliesIpv4Enabled(enabled) => {
            if let Some(ipv4) = &mut instance.config.ipv4 {
                ipv4.enabled = enabled;
            }
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryInterfacesHelloHoldtime(hello_holdtime) => {
            instance.config.interface_hello_holdtime = hello_holdtime;
            for iface in instance.interfaces.iter_mut() {
                iface.config.hello_holdtime = hello_holdtime;
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryInterfacesHelloInterval(hello_interval) => {
            let hello_interval = Duration::from_secs(hello_interval.into());
            instance.config.interface_hello_interval = hello_interval;
            for iface in instance.interfaces.iter_mut() {
                iface.config.hello_interval = hello_interval;
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryInterfacesInterface(keys, change) => {
            apply_interface(instance, keys.name, change, event_queue)?;
        }
        ConfigChange::DiscoveryTargetedHelloHoldtime(hello_holdtime) => {
            instance.config.targeted_hello_holdtime = hello_holdtime;
            for tnbr in instance.tneighbors.iter_mut() {
                tnbr.config.hello_holdtime = hello_holdtime;
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryTargetedHelloInterval(hello_interval) => {
            let hello_interval = Duration::from_secs(hello_interval.into());
            instance.config.targeted_hello_interval = hello_interval;
            for tnbr in instance.tneighbors.iter_mut() {
                tnbr.config.hello_interval = hello_interval;
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryTargetedHelloAcceptEnabled(enabled) => {
            instance.config.targeted_hello_accept = enabled;
            if !enabled {
                event_queue.insert(Event::TargetedNbrRemoveDynamic);
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::DiscoveryTargetedAddressFamiliesIpv4(op) => {
            if op == ConfigOp::Delete {
                // The nested target entries don't receive individual delete
                // changes, so unmark them as configured here.
                for tnbr in instance.tneighbors.iter_mut() {
                    tnbr.config.enabled = false;
                    tnbr.configured = false;
                }
                for tnbr_idx in instance.tneighbors.indexes() {
                    event_queue.insert(Event::TargetedNbrRemoveCheck(tnbr_idx));
                }
                event_queue.insert(Event::CfgSeqNumberUpdate);
            }
        }
        ConfigChange::DiscoveryTargetedAddressFamiliesIpv4Target(keys, change) => {
            let addr = IpAddr::V4(keys.adjacent_address);
            apply_target(instance, addr, change, event_queue)?;
        }
        ConfigChange::PeersAuthenticationKey(password) => {
            instance.config.password = password;
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::UpdateNeighborsAuth);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::PeersAuthenticationCryptoAlgorithm(_algo) => {
            // Nothing to do (only TCP MD5 is supported at the moment).
        }
        ConfigChange::PeersSessionKaHoldtime(holdtime) => {
            instance.config.session_ka_holdtime = holdtime;
            event_queue.insert(Event::StopInitBackoff);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::PeersSessionKaInterval(interval) => {
            instance.config.session_ka_interval = Duration::from_secs(interval.into());
            event_queue.insert(Event::CfgSeqNumberUpdate);
        }
        ConfigChange::PeersPeer(keys, change) => {
            apply_peer(instance, keys.lsr_id, change, event_queue)?;
        }
    }

    Ok(())
}

fn apply_interface(instance: &mut Instance, ifname: String, change: DiscoveryInterfacesInterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DiscoveryInterfacesInterfaceChange::Create => {
            let (iface_idx, _) = instance.interfaces.insert(&ifname);
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        }
        DiscoveryInterfacesInterfaceChange::Delete => {
            let (iface_idx, _) = instance.interfaces.get_mut_by_name(&ifname).ok_or(ApplyError::EntryNotFound)?;
            event_queue.insert(Event::InterfaceDelete(iface_idx));
        }
        DiscoveryInterfacesInterfaceChange::Entry(change) => {
            let (iface_idx, iface) = instance.interfaces.get_mut_by_name(&ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DiscoveryInterfacesInterfaceEntryChange::AddressFamiliesIpv4(op) => {
                    iface.config.ipv4 = match op {
                        ConfigOp::Create => Some(InterfaceIpv4Cfg::default()),
                        ConfigOp::Delete => None,
                    };
                    event_queue.insert(Event::InterfaceUpdate(iface_idx));
                }
                DiscoveryInterfacesInterfaceEntryChange::AddressFamiliesIpv4Enabled(enabled) => {
                    if let Some(ipv4) = &mut iface.config.ipv4 {
                        ipv4.enabled = enabled;
                    }
                    event_queue.insert(Event::InterfaceUpdate(iface_idx));
                }
            }
        }
    }
    event_queue.insert(Event::CfgSeqNumberUpdate);

    Ok(())
}

fn apply_target(instance: &mut Instance, addr: IpAddr, change: DiscoveryTargetedAddressFamiliesIpv4TargetChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        DiscoveryTargetedAddressFamiliesIpv4TargetChange::Create => {
            let (tnbr_idx, tnbr) = instance.tneighbors.insert(addr);
            tnbr.configured = true;
            event_queue.insert(Event::TargetedNbrUpdate(tnbr_idx));
        }
        DiscoveryTargetedAddressFamiliesIpv4TargetChange::Delete => {
            let (tnbr_idx, tnbr) = instance.tneighbors.get_mut_by_addr(&addr).ok_or(ApplyError::EntryNotFound)?;
            tnbr.configured = false;
            event_queue.insert(Event::TargetedNbrRemoveCheck(tnbr_idx));
        }
        DiscoveryTargetedAddressFamiliesIpv4TargetChange::Entry(change) => {
            let (tnbr_idx, tnbr) = instance.tneighbors.get_mut_by_addr(&addr).ok_or(ApplyError::EntryNotFound)?;
            match change {
                DiscoveryTargetedAddressFamiliesIpv4TargetEntryChange::Enabled(enabled) => {
                    tnbr.config.enabled = enabled;
                    event_queue.insert(Event::TargetedNbrUpdate(tnbr_idx));
                }
            }
        }
    }
    event_queue.insert(Event::CfgSeqNumberUpdate);

    Ok(())
}

fn apply_peer(instance: &mut Instance, lsr_id: Ipv4Addr, change: PeersPeerChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        PeersPeerChange::Create => {
            instance.config.neighbors.insert(lsr_id, Default::default());
        }
        PeersPeerChange::Delete => {
            instance.config.neighbors.remove(&lsr_id);
        }
        PeersPeerChange::Entry(change) => {
            let nbr_cfg = instance.config.neighbors.get_mut(&lsr_id).ok_or(ApplyError::EntryNotFound)?;
            match change {
                PeersPeerEntryChange::AuthenticationKey(password) => {
                    nbr_cfg.password = password;
                    event_queue.insert(Event::ResetNeighbor(lsr_id));
                    event_queue.insert(Event::UpdateNeighborAuth(lsr_id));
                    event_queue.insert(Event::CfgSeqNumberUpdate);
                }
                PeersPeerEntryChange::AuthenticationCryptoAlgorithm(_algo) => {
                    // Nothing to do (only TCP MD5 is supported at the moment).
                }
                PeersPeerEntryChange::AddressFamiliesIpv4(_op) => {
                    // Nothing to do.
                }
            }
        }
    }

    Ok(())
}

fn process_event(instance: &mut Instance, event: Event) {
    match event {
        Event::InstanceUpdate => instance.update(),
        Event::InterfaceUpdate(iface_idx) => {
            if let Some((mut instance, interfaces, _)) = instance.as_up() {
                let iface = &mut interfaces[iface_idx];
                iface.update(&mut instance);
            }
        }
        Event::InterfaceDelete(iface_idx) => {
            if let Some((mut instance, interfaces, _)) = instance.as_up() {
                let iface = &mut interfaces[iface_idx];

                // Cancel ibus subscription.
                instance.tx.ibus.interface_unsub(Some(iface.name.clone()));

                // Stop interface if it's active.
                if iface.is_active() {
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.stop(&mut instance, reason);
                }
            }

            instance.interfaces.delete(iface_idx);
        }
        Event::InterfaceIbusSub(ifname) => {
            if let Some((instance, _, _)) = instance.as_up() {
                instance.tx.ibus.interface_sub(Some(ifname), Some(AddressFamily::Ipv4));
            }
        }
        Event::TargetedNbrUpdate(tnbr_idx) => {
            if let Some((mut instance, _, tneighbors)) = instance.as_up() {
                TargetedNbr::update(&mut instance, tneighbors, tnbr_idx);
            }
        }
        Event::TargetedNbrRemoveCheck(tnbr_idx) => {
            let tnbr = &instance.tneighbors[tnbr_idx];
            if !tnbr.remove_check() {
                return;
            }

            // Stop targeted neighbor if it's active.
            if let Some((mut instance, _, tneighbors)) = instance.as_up() {
                let tnbr = &mut tneighbors[tnbr_idx];
                if tnbr.is_active() {
                    tnbr.stop(&mut instance, true);
                }
            }

            instance.tneighbors.delete(tnbr_idx);
        }
        Event::TargetedNbrRemoveDynamic => {
            if let Some((mut instance, _, tneighbors)) = instance.as_up() {
                for tnbr_idx in tneighbors.indexes().collect::<Vec<_>>() {
                    let tnbr = &mut tneighbors[tnbr_idx];
                    tnbr.dynamic = false;
                    TargetedNbr::update(&mut instance, tneighbors, tnbr_idx);
                }
            }
        }
        Event::StopInitBackoff => {
            if let Some((instance, _, _)) = instance.as_up() {
                for nbr in instance.state.neighbors.iter_mut() {
                    nbr.stop_backoff_timeout();
                }
            }
        }
        Event::ResetNeighbors => {
            if let Some((instance, _, _)) = instance.as_up() {
                for nbr in instance.state.neighbors.iter_mut() {
                    // Send Shutdown notification.
                    if nbr.state != neighbor::fsm::State::NonExistent {
                        nbr.send_shutdown(&instance.state.msg_id, None);
                    }

                    // Stop the connection task.
                    nbr.tasks.connect = None;
                }
            }
        }
        Event::ResetNeighbor(lsr_id) => {
            if let Some((instance, _, _)) = instance.as_up()
                && let Some((_, nbr)) = instance.state.neighbors.get_mut_by_lsr_id(&lsr_id)
            {
                // Send Shutdown notification.
                if nbr.state != neighbor::fsm::State::NonExistent {
                    nbr.send_shutdown(&instance.state.msg_id, None);
                }

                // Stop the connection task.
                nbr.tasks.connect = None;
            }
        }
        Event::UpdateNeighborsAuth => {
            if let Some((instance, _, _)) = instance.as_up() {
                for nbr in instance.state.neighbors.iter_mut() {
                    let password = instance.config.get_neighbor_password(nbr.lsr_id);
                    network::tcp::listen_socket_md5sig_update(&instance.state.ipv4.session_socket, &nbr.trans_addr, password);
                }
            }
        }
        Event::UpdateNeighborAuth(lsr_id) => {
            if let Some((instance, _, _)) = instance.as_up()
                && let Some((_, nbr)) = instance.state.neighbors.get_by_lsr_id(&lsr_id)
            {
                let password = instance.config.get_neighbor_password(nbr.lsr_id);
                network::tcp::listen_socket_md5sig_update(&instance.state.ipv4.session_socket, &nbr.trans_addr, password);
            }
        }
        Event::CfgSeqNumberUpdate => {
            if let Some((instance, interfaces, tneighbors)) = instance.as_up() {
                instance.state.cfg_seqno += 1;

                // Synchronize interfaces.
                for iface in interfaces.iter_mut().filter(|iface| iface.is_active()) {
                    iface.sync_hello_tx(instance.state);
                }

                // Synchronize targeted neighbors.
                for tnbr in tneighbors.iter_mut().filter(|tnbr| tnbr.is_active()) {
                    tnbr.sync_hello_tx(instance.state);
                }
            }
        }
    }
}

// ===== impl Instance =====

impl Provider for Instance {
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
        let session_ka_holdtime = mpls_ldp::peers::session_ka_holdtime::DFLT;
        let session_ka_interval = Duration::from_secs(mpls_ldp::peers::session_ka_interval::DFLT.into());
        let interface_hello_holdtime = mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let interface_hello_interval = Duration::from_secs(mpls_ldp::discovery::interfaces::hello_interval::DFLT.into());
        let targeted_hello_holdtime = mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let targeted_hello_interval = Duration::from_secs(mpls_ldp::discovery::targeted::hello_interval::DFLT.into());
        let targeted_hello_accept = mpls_ldp::discovery::targeted::hello_accept::enabled::DFLT;

        InstanceCfg {
            router_id: None,
            session_ka_holdtime,
            session_ka_interval,
            password: None,
            interface_hello_holdtime,
            interface_hello_interval,
            targeted_hello_holdtime,
            targeted_hello_interval,
            targeted_hello_accept,
            ipv4: None,
            neighbors: Default::default(),
        }
    }
}

impl Default for InstanceIpv4Cfg {
    fn default() -> InstanceIpv4Cfg {
        let enabled = mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;

        InstanceIpv4Cfg {
            enabled,
        }
    }
}

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let hello_holdtime = mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let hello_interval = Duration::from_secs(mpls_ldp::discovery::interfaces::hello_interval::DFLT.into());

        InterfaceCfg {
            hello_holdtime,
            hello_interval,
            ipv4: None,
        }
    }
}

impl Default for InterfaceIpv4Cfg {
    fn default() -> InterfaceIpv4Cfg {
        let enabled = mpls_ldp::discovery::interfaces::interface::address_families::ipv4::enabled::DFLT;

        InterfaceIpv4Cfg {
            enabled,
        }
    }
}

impl Default for TargetedNbrCfg {
    fn default() -> TargetedNbrCfg {
        let enabled = mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;
        let hello_holdtime = mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let hello_interval = Duration::from_secs(mpls_ldp::discovery::targeted::hello_interval::DFLT.into());

        TargetedNbrCfg {
            enabled,
            hello_holdtime,
            hello_interval,
        }
    }
}
