//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::mpls_ldp;
use holo_utils::ip::AddressFamily;
use holo_utils::yang::DataNodeRefExt;

use crate::collections::{InterfaceIndex, TargetedNbrIndex};
use crate::debug::InterfaceInactiveReason;
use crate::discovery::TargetedNbr;
use crate::instance::Instance;
use crate::{neighbor, network};

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Interface(InterfaceIndex),
    TargetedNbr(TargetedNbrIndex),
    Neighbor(Ipv4Addr),
}

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

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub router_id: Option<Ipv4Addr>,
    pub session_ka_holdtime: u16,
    pub session_ka_interval: u16,
    pub password: Option<String>,
    pub interface_hello_holdtime: u16,
    pub interface_hello_interval: u16,
    pub targeted_hello_holdtime: u16,
    pub targeted_hello_interval: u16,
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
    pub hello_interval: u16,
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
    pub hello_interval: u16,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(mpls_ldp::global::lsr_id::PATH)
        .modify_apply(|instance, args| {
            let router_id = args.dnode.get_ipv4();
            instance.config.router_id = Some(router_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|instance, args| {
            instance.config.router_id = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::global::address_families::ipv4::PATH)
        .create_apply(|instance, args| {
            instance.config.ipv4 = Some(InstanceIpv4Cfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|instance, args| {
            instance.config.ipv4 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(mpls_ldp::global::address_families::ipv4::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.ipv4.as_mut().unwrap().enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::interfaces::hello_holdtime::PATH)
        .modify_apply(|instance, args| {
            let hello_holdtime = args.dnode.get_u16();
            instance.config.interface_hello_holdtime =
                hello_holdtime;
            for iface in instance.interfaces.iter_mut() {
                iface.config.hello_holdtime = hello_holdtime;
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::interfaces::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let hello_interval = args.dnode.get_u16();
            instance.config.interface_hello_interval =
                hello_interval;
            for iface in instance.interfaces.iter_mut() {
                iface.config.hello_interval = hello_interval;
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let ifname = args.dnode.get_string_relative("name").unwrap();
            let (iface_idx, _) = instance.interfaces.insert(&ifname);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|_instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceDelete(iface_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .lookup(|instance, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("./name").unwrap();
            instance
                .interfaces
                .get_mut_by_name(&ifname)
                .map(|(iface_idx, _)| ListEntry::Interface(iface_idx))
                .expect("could not find LDP interface")
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::PATH)
        .create_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.ipv4 = Some(InterfaceIpv4Cfg::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            iface.config.ipv4 = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::enabled::PATH)
        .modify_apply(|instance, args| {
            let iface_idx = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.ipv4.as_mut().unwrap().enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(iface_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::targeted::hello_holdtime::PATH)
        .modify_apply(|instance, args| {
            let hello_holdtime = args.dnode.get_u16();
            instance.config.targeted_hello_holdtime = hello_holdtime;
            for tnbr in instance.tneighbors.iter_mut() {
                tnbr.config.hello_holdtime = hello_holdtime;
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::targeted::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let hello_interval = args.dnode.get_u16();
            instance.config.targeted_hello_interval = hello_interval;
            for tnbr in instance.tneighbors.iter_mut() {
                tnbr.config.hello_interval = hello_interval;
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::targeted::hello_accept::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.targeted_hello_accept = enabled;

            let event_queue = args.event_queue;
            if !enabled {
                event_queue.insert(Event::TargetedNbrRemoveDynamic);
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::PATH)
        .create_apply(|_instance, _args| {
            // Nothing to do.
        })
        .delete_apply(|instance, args| {
            for tnbr in instance.tneighbors.iter_mut() {
                tnbr.config.enabled = false;
            }

            let event_queue = args.event_queue;
            for tnbr_idx in instance.tneighbors.indexes() {
                event_queue.insert(Event::TargetedNbrRemoveCheck(tnbr_idx));
            }
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::target::PATH)
        .create_apply(|instance, args| {
            let addr = args.dnode.get_ip_relative("adjacent-address").unwrap();
            let (tnbr_index, tnbr) =
                instance.tneighbors.insert(addr);
            tnbr.configured = true;

            let event_queue = args.event_queue;
            event_queue.insert(Event::TargetedNbrUpdate(tnbr_index));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|instance, args| {
            let tnbr_idx = args.list_entry.into_targeted_nbr().unwrap();
            let tnbr = &mut instance.tneighbors[tnbr_idx];

            tnbr.configured = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::TargetedNbrRemoveCheck(tnbr_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .lookup(|instance, _list_entry, dnode| {
            let addr = dnode.get_ip_relative("./adjacent-address").unwrap();
            instance
                .tneighbors
                .get_mut_by_addr(&addr)
                .map(|(tnbr_idx, _)| ListEntry::TargetedNbr(tnbr_idx))
                .expect("could not find LDP targeted neighbor")
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::PATH)
        .modify_apply(|instance, args| {
            let tnbr_idx = args.list_entry.into_targeted_nbr().unwrap();
            let tnbr = &mut instance.tneighbors[tnbr_idx];

            let enabled = args.dnode.get_bool();
            tnbr.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::TargetedNbrUpdate(tnbr_idx));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::peers::authentication::key::PATH)
        .modify_apply(|instance, args| {
            let password = args.dnode.get_string();
            instance.config.password = Some(password);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::UpdateNeighborsAuth);
            event_queue.insert(Event::CfgSeqNumberUpdate);

        })
        .delete_apply(|instance, args| {
            instance.config.password = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetNeighbors);
            event_queue.insert(Event::UpdateNeighborsAuth);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::peers::authentication::crypto_algorithm::PATH)
        .modify_apply(|_context, _args| {
            // Nothing to do (only TCP MD5 is supported at the moment).
        })
        .delete_apply(|_context, _args| {
            // Nothing to do (only TCP MD5 is supported at the moment).
        })
        .path(mpls_ldp::peers::session_ka_holdtime::PATH)
        .modify_apply(|instance, args| {
            let holdtime = args.dnode.get_u16();
            instance.config.session_ka_holdtime = holdtime;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StopInitBackoff);
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::peers::session_ka_interval::PATH)
        .modify_apply(|instance, args| {
            let interval = args.dnode.get_u16();
            instance.config.session_ka_interval = interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::peers::peer::PATH)
        .create_apply(|instance, args| {
            let lsr_id = args.dnode.get_ipv4_relative("lsr-id").unwrap();
            instance.config.neighbors.insert(lsr_id, Default::default());
        })
        .delete_apply(|instance, args| {
            let lsr_id = args.list_entry.into_neighbor().unwrap();
            instance.config.neighbors.remove(&lsr_id);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let lsr_id = dnode.get_ipv4_relative("lsr-id").unwrap();
            ListEntry::Neighbor(lsr_id)
        })
        .path(mpls_ldp::peers::peer::authentication::key::PATH)
        .modify_apply(|instance, args| {
            let lsr_id = args.list_entry.into_neighbor().unwrap();
            let nbr_cfg = instance.config.neighbors.get_mut(&lsr_id).unwrap();

            let password = args.dnode.get_string();
            nbr_cfg.password = Some(password);

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetNeighbor(lsr_id));
            event_queue.insert(Event::UpdateNeighborAuth(lsr_id));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .delete_apply(|instance, args| {
            let lsr_id = args.list_entry.into_neighbor().unwrap();
            let nbr_cfg = instance.config.neighbors.get_mut(&lsr_id).unwrap();

            nbr_cfg.password = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ResetNeighbor(lsr_id));
            event_queue.insert(Event::UpdateNeighborAuth(lsr_id));
            event_queue.insert(Event::CfgSeqNumberUpdate);
        })
        .path(mpls_ldp::peers::peer::authentication::crypto_algorithm::PATH)
        .modify_apply(|_instance, _args| {
            // Nothing to do (only TCP MD5 is supported at the moment).
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do (only TCP MD5 is supported at the moment).
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::PATH)
        .create_apply(|_instance, _args| {
            // Nothing to do.
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(mpls_ldp::peers::peer::authentication::crypto_algorithm::PATH)
        .validate(|args| {
            let algo = args.dnode.get_string();
            validate_crypto_algo(&algo)
        })
        .path(mpls_ldp::peers::authentication::crypto_algorithm::PATH)
        .validate(|args| {
            let algo = args.dnode.get_string();
            validate_crypto_algo(&algo)
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceUpdate => self.update(),
            Event::InterfaceUpdate(iface_idx) => {
                if let Some((mut instance, interfaces, _)) = self.as_up() {
                    let iface = &mut interfaces[iface_idx];
                    iface.update(&mut instance);
                }
            }
            Event::InterfaceDelete(iface_idx) => {
                if let Some((mut instance, interfaces, _)) = self.as_up() {
                    let iface = &mut interfaces[iface_idx];

                    // Cancel ibus subscription.
                    instance.tx.ibus.interface_unsub(Some(iface.name.clone()));

                    // Stop interface if it's active.
                    if iface.is_active() {
                        let reason = InterfaceInactiveReason::AdminDown;
                        iface.stop(&mut instance, reason);
                    }
                }

                self.interfaces.delete(iface_idx);
            }
            Event::InterfaceIbusSub(ifname) => {
                if let Some((instance, _, _)) = self.as_up() {
                    instance
                        .tx
                        .ibus
                        .interface_sub(Some(ifname), Some(AddressFamily::Ipv4));
                }
            }
            Event::TargetedNbrUpdate(tnbr_idx) => {
                if let Some((mut instance, _, tneighbors)) = self.as_up() {
                    TargetedNbr::update(&mut instance, tneighbors, tnbr_idx);
                }
            }
            Event::TargetedNbrRemoveCheck(tnbr_idx) => {
                let tnbr = &self.tneighbors[tnbr_idx];
                if !tnbr.remove_check() {
                    return;
                }

                // Stop targeted neighbor if it's active.
                if let Some((mut instance, _, tneighbors)) = self.as_up() {
                    let tnbr = &mut tneighbors[tnbr_idx];
                    if tnbr.is_active() {
                        tnbr.stop(&mut instance, true);
                    }
                }

                self.tneighbors.delete(tnbr_idx);
            }
            Event::TargetedNbrRemoveDynamic => {
                if let Some((mut instance, _, tneighbors)) = self.as_up() {
                    for tnbr_idx in tneighbors.indexes().collect::<Vec<_>>() {
                        let tnbr = &mut tneighbors[tnbr_idx];
                        tnbr.dynamic = false;
                        TargetedNbr::update(
                            &mut instance,
                            tneighbors,
                            tnbr_idx,
                        );
                    }
                }
            }
            Event::StopInitBackoff => {
                if let Some((instance, _, _)) = self.as_up() {
                    for nbr in instance.state.neighbors.iter_mut() {
                        nbr.stop_backoff_timeout();
                    }
                }
            }
            Event::ResetNeighbors => {
                if let Some((instance, _, _)) = self.as_up() {
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
                if let Some((instance, _, _)) = self.as_up()
                    && let Some((_, nbr)) =
                        instance.state.neighbors.get_mut_by_lsr_id(&lsr_id)
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
                if let Some((instance, _, _)) = self.as_up() {
                    for nbr in instance.state.neighbors.iter_mut() {
                        let password =
                            instance.config.get_neighbor_password(nbr.lsr_id);
                        network::tcp::listen_socket_md5sig_update(
                            &instance.state.ipv4.session_socket,
                            &nbr.trans_addr,
                            password,
                        );
                    }
                }
            }
            Event::UpdateNeighborAuth(lsr_id) => {
                if let Some((instance, _, _)) = self.as_up()
                    && let Some((_, nbr)) =
                        instance.state.neighbors.get_by_lsr_id(&lsr_id)
                {
                    let password =
                        instance.config.get_neighbor_password(nbr.lsr_id);
                    network::tcp::listen_socket_md5sig_update(
                        &instance.state.ipv4.session_socket,
                        &nbr.trans_addr,
                        password,
                    );
                }
            }
            Event::CfgSeqNumberUpdate => {
                if let Some((instance, interfaces, tneighbors)) = self.as_up() {
                    instance.state.cfg_seqno += 1;

                    // Synchronize interfaces.
                    for iface in
                        interfaces.iter_mut().filter(|iface| iface.is_active())
                    {
                        iface.sync_hello_tx(instance.state);
                    }

                    // Synchronize targeted neighbors.
                    for tnbr in
                        tneighbors.iter_mut().filter(|tnbr| tnbr.is_active())
                    {
                        tnbr.sync_hello_tx(instance.state);
                    }
                }
            }
        }
    }
}

// ===== helper functions =====

fn validate_crypto_algo(algo: &str) -> Result<(), String> {
    if algo != "ietf-key-chain:md5" {
        return Err("unsupported cryptographic algorithm (valid options: \"ietf-key-chain:md5\")"
            .to_string());
    }

    Ok(())
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let session_ka_holdtime = mpls_ldp::peers::session_ka_holdtime::DFLT;
        let session_ka_interval = mpls_ldp::peers::session_ka_interval::DFLT;
        let interface_hello_holdtime =
            mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let interface_hello_interval =
            mpls_ldp::discovery::interfaces::hello_interval::DFLT;
        let targeted_hello_holdtime =
            mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let targeted_hello_interval =
            mpls_ldp::discovery::targeted::hello_interval::DFLT;
        let targeted_hello_accept =
            mpls_ldp::discovery::targeted::hello_accept::enabled::DFLT;

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
        let enabled =
            mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;

        InstanceIpv4Cfg { enabled }
    }
}

impl Default for InterfaceCfg {
    fn default() -> InterfaceCfg {
        let hello_holdtime =
            mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let hello_interval =
            mpls_ldp::discovery::interfaces::hello_interval::DFLT;

        InterfaceCfg {
            hello_holdtime,
            hello_interval,
            ipv4: None,
        }
    }
}

impl Default for InterfaceIpv4Cfg {
    fn default() -> InterfaceIpv4Cfg {
        let enabled =
            mpls_ldp::discovery::interfaces::interface::address_families::ipv4::enabled::DFLT;

        InterfaceIpv4Cfg { enabled }
    }
}

impl Default for TargetedNbrCfg {
    fn default() -> TargetedNbrCfg {
        let enabled =
            mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;
        let hello_holdtime =
            mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let hello_interval =
            mpls_ldp::discovery::targeted::hello_interval::DFLT;

        TargetedNbrCfg {
            enabled,
            hello_holdtime,
            hello_interval,
        }
    }
}
