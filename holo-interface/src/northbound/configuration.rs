//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use holo_northbound::NbDaemonSender;
use holo_northbound::configuration::{ConfigChanges, Provider, YangConfigOps};
use holo_northbound::error::{ApplyError, PrepareError};
use ipnetwork::IpNetwork;

use crate::Master;
use crate::dataplane::Dataplane;
use crate::interface::{Interface, Owner};
use crate::northbound::REGEX_VRRP;
use crate::northbound::yang_gen::config::{self, ConfigChange, InterfaceChange, InterfaceEntryChange, InterfaceIpv4AddressChange, InterfaceIpv4AddressEntryChange, InterfaceIpv6AddressChange, InterfaceIpv6AddressEntryChange};
use crate::northbound::yang_gen::interfaces;

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
    #[cfg(feature = "vrrp")]
    VrrpStart(String),
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

// ===== helper functions =====

#[cfg_attr(not(feature = "vrrp"), allow(unused_variables))]
fn prepare_master(master: &mut Master, change: &ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), PrepareError> {
    // Interfaces are created during the Prepare phase so that VRRP instance
    // configuration can be relayed to the spawned VRRP tasks within the same
    // commit.
    if let ConfigChange::Interface(keys, InterfaceChange::Create) = change {
        master.interfaces.add(keys.name.clone());

        #[cfg(feature = "vrrp")]
        event_queue.insert(Event::VrrpStart(keys.name.clone()));
    }

    Ok(())
}

fn apply_master(master: &mut Master, change: ConfigChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    let ConfigChange::Interface(keys, change) = change;
    apply_interface(master, keys.name, change, event_queue)?;

    Ok(())
}

fn apply_interface(master: &mut Master, ifname: String, change: InterfaceChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // Handled during the Prepare phase.
        InterfaceChange::Create => (),
        InterfaceChange::Delete => {
            event_queue.insert(Event::InterfaceDelete(ifname));
        }
        InterfaceChange::Entry(change) => {
            let iface = master.interfaces.get_mut_by_name(&ifname).ok_or(ApplyError::EntryNotFound)?;
            match change {
                InterfaceEntryChange::Description(_description) => {
                    // Nothing to do.
                }
                // TODO: implement the remaining ietf-ip nodes.
                InterfaceEntryChange::Type(..) | InterfaceEntryChange::Ipv4(..) | InterfaceEntryChange::Ipv4Enabled(..) | InterfaceEntryChange::Ipv6(..) | InterfaceEntryChange::Ipv6Enabled(..) => {}
                InterfaceEntryChange::Enabled(enabled) => {
                    iface.config.enabled = enabled;

                    event_queue.insert(Event::AdminStatusChange(ifname, enabled));
                }
                InterfaceEntryChange::ParentInterface(parent) => {
                    iface.config.parent = parent;
                }
                InterfaceEntryChange::EncapsulationDot1qVlanOuterTagVlanId(vlan_id) => {
                    iface.config.vlan_id = Some(vlan_id);

                    event_queue.insert(Event::VlanCreate(ifname, vlan_id));
                }
                InterfaceEntryChange::Ipv4Mtu(mtu) => {
                    iface.config.mtu = mtu.map(u32::from);

                    if let Some(mtu) = iface.config.mtu {
                        event_queue.insert(Event::MtuChange(ifname, mtu));
                    }
                }
                InterfaceEntryChange::Ipv6Mtu(mtu) => {
                    iface.config.mtu = mtu;

                    if let Some(mtu) = mtu {
                        event_queue.insert(Event::MtuChange(ifname, mtu));
                    }
                }
                InterfaceEntryChange::Ipv4Address(keys, change) => {
                    apply_interface_ipv4_address(iface, ifname, keys.ip.into(), change, event_queue)?;
                }
                InterfaceEntryChange::Ipv6Address(keys, change) => {
                    apply_interface_ipv6_address(iface, ifname, keys.ip.into(), change, event_queue)?;
                }
            }
        }
    }

    Ok(())
}

fn apply_interface_ipv4_address(iface: &mut Interface, ifname: String, addr: IpAddr, change: InterfaceIpv4AddressChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // The address is added to the configuration once its prefix length
        // is known.
        InterfaceIpv4AddressChange::Create => (),
        InterfaceIpv4AddressChange::Delete => {
            if let Some(plen) = iface.config.addr_list.remove(&addr) {
                event_queue.insert(Event::AddressUninstall(ifname, addr, plen));
            }
        }
        InterfaceIpv4AddressChange::Entry(InterfaceIpv4AddressEntryChange::PrefixLength(plen)) => {
            let Some(plen) = plen else {
                return Ok(());
            };
            let old_plen = iface.config.addr_list.insert(addr, plen);

            if let Some(old_plen) = old_plen
                && old_plen != plen
            {
                event_queue.insert(Event::AddressUninstall(ifname.clone(), addr, old_plen));
            }
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
        }
    }

    Ok(())
}

fn apply_interface_ipv6_address(iface: &mut Interface, ifname: String, addr: IpAddr, change: InterfaceIpv6AddressChange, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
    match change {
        // The address is added to the configuration once its prefix length
        // is known.
        InterfaceIpv6AddressChange::Create => (),
        InterfaceIpv6AddressChange::Delete => {
            if let Some(plen) = iface.config.addr_list.remove(&addr) {
                event_queue.insert(Event::AddressUninstall(ifname, addr, plen));
            }
        }
        InterfaceIpv6AddressChange::Entry(InterfaceIpv6AddressEntryChange::PrefixLength(plen)) => {
            let old_plen = iface.config.addr_list.insert(addr, plen);

            if let Some(old_plen) = old_plen
                && old_plen != plen
            {
                event_queue.insert(Event::AddressUninstall(ifname.clone(), addr, old_plen));
            }
            event_queue.insert(Event::AddressInstall(ifname, addr, plen));
        }
    }

    Ok(())
}

fn process_event(master: &mut Master, event: Event) {
    match event {
        Event::InterfaceDelete(ifname) => {
            master.interfaces.remove(&ifname, Owner::CONFIG, &master.dataplane);
        }
        Event::AdminStatusChange(ifname, enabled) => {
            // If the interface is active, change its administrative status
            // in the dataplane.
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                master.dataplane.admin_status_change(ifindex, enabled);
            }
        }
        Event::MtuChange(ifname, mtu) => {
            // If the interface is active, change its MTU in the dataplane.
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                master.dataplane.mtu_change(ifindex, mtu);
            }
        }
        Event::VlanCreate(ifname, vlan_id) => {
            // If the parent interface is active, create VLAN subinterface
            // in the dataplane.
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && iface.ifindex.is_none()
                && let Some(parent) = &iface.config.parent
                && let Some(parent) = master.interfaces.get_by_name(parent)
                && let Some(parent_ifindex) = parent.ifindex
            {
                master.dataplane.vlan_create(iface.name.clone(), parent_ifindex, vlan_id);
            }
        }
        Event::AddressInstall(ifname, addr, plen) => {
            // If the interface is active, install the address in the
            // dataplane.
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                let addr = IpNetwork::new(addr, plen).unwrap();
                master.dataplane.addr_install(ifindex, &addr);
            }
        }
        Event::AddressUninstall(ifname, addr, plen) => {
            // If the interface is active, uninstall the address from the
            // dataplane.
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                let addr = IpNetwork::new(addr, plen).unwrap();
                master.dataplane.addr_uninstall(ifindex, &addr);
            }
        }
        #[cfg(feature = "vrrp")]
        Event::VrrpStart(ifname) => {
            use holo_protocol::spawn_protocol_task;
            use tokio::sync::mpsc;

            use crate::interface::VrrpHandle;

            if let Some(iface) = master.interfaces.get_mut_by_name(&ifname) {
                let (ibus_instance_tx, ibus_instance_rx) = mpsc::unbounded_channel();
                let nb_daemon_tx = spawn_protocol_task::<holo_vrrp::interface::Interface>(ifname, &master.nb_tx, &master.ibus_tx, ibus_instance_tx.clone(), ibus_instance_rx, Default::default(), master.shared.clone());
                let vrrp = VrrpHandle::new(nb_daemon_tx, ibus_instance_tx);
                iface.vrrp = Some(vrrp);
            }
        }
    }
}

// ===== impl Master =====

impl Provider for Master {
    type Event = Event;
    type Resource = Resource;
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> = config::YANG_OPS_CONFIG;

    fn prepare(&mut self, change: &ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), PrepareError> {
        prepare_master(self, change, event_queue)
    }

    fn apply(&mut self, change: ConfigChange, _resource: &mut Option<Resource>, event_queue: &mut BTreeSet<Event>) -> Result<(), ApplyError> {
        apply_master(self, change, event_queue)
    }

    fn process_event(&mut self, event: Event) {
        process_event(self, event);
    }

    fn relay_changes(&self, changes: ConfigChanges) -> Vec<(ConfigChanges, NbDaemonSender)> {
        // Create hash table that maps changes to the appropriate child
        // instances.
        let mut changes_map: HashMap<String, ConfigChanges> = HashMap::new();
        for change in changes {
            // HACK: parse interface name from VRRP configuration changes.
            let Some(caps) = REGEX_VRRP.captures(&change.1) else {
                continue;
            };
            let ifname = caps.get(1).unwrap().as_str().to_owned();

            // Move configuration change to the appropriate interface bucket.
            changes_map.entry(ifname).or_default().push(change);
        }
        changes_map
            .into_iter()
            .filter_map(|(ifname, changes)| self.interfaces.get_by_name(&ifname).and_then(|iface| iface.vrrp.as_ref().map(|vrrp| vrrp.nb_tx.clone())).map(|nb_tx| (changes, nb_tx)))
            .collect::<Vec<_>>()
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
