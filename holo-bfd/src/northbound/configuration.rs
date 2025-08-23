//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, Provider, ValidationCallbacks,
    ValidationCallbacksBuilder,
};
use holo_northbound::yang::control_plane_protocol::bfd;
use holo_utils::bfd::{SessionKey, State};
use holo_utils::socket::TTL_MAX;
use holo_utils::yang::DataNodeRefExt;

use crate::master::Master;
use crate::network;
use crate::packet::DiagnosticCode;
use crate::session::SessionIndex;

// Minimum supported Tx/Rx interval in milliseconds.
const MIN_SUPPORTED_INTERVAL: u32 = 50000;

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    Session(SessionIndex),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    SessionDeleteCheck(SessionIndex),
    AdminDownChange(SessionIndex),
    StartPollSequence(SessionIndex),
    UpdateRxSockets,
    UpdateTxSocket(SessionIndex),
    UpdateTxInterval(SessionIndex),
}

pub static VALIDATION_CALLBACKS: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks);
pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

// ===== configuration structs =====

#[derive(Debug)]
pub struct SessionCfg {
    // Common parameters.
    pub local_multiplier: u8,
    pub min_tx: u32,
    pub min_rx: u32,
    pub admin_down: bool,
    // IP single-hop parameters.
    pub src: Option<IpAddr>,
    // IP multihop parameters.
    pub tx_ttl: Option<u8>,
    pub rx_ttl: Option<u8>,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(bfd::ip_sh::sessions::session::PATH)
        .create_apply(|master, args| {
            let ifname = args.dnode.get_string_relative("interface").unwrap();
            let dst = args.dnode.get_ip_relative("dest-addr").unwrap();

            // Get existing session or create a new one.
            let sess_key = SessionKey::new_ip_single_hop(ifname.clone(), dst);
            let (sess_idx, sess) = master.sessions.insert(sess_key);
            sess.config_enabled = true;

            // Single-hop sessions can only be active as long as their
            // associated interface is present.
            if let Some(iface) = master.interfaces.get(&ifname) {
                master.sessions.update_ifindex(sess_idx, iface.ifindex);
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        })
        .delete_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            sess.config_enabled = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SessionDeleteCheck(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        })
        .lookup(|master, _list_entry, dnode| {
            let ifname = dnode.get_string_relative("interface").unwrap();
            let dst = dnode.get_ip_relative("dest-addr").unwrap();
            let key = SessionKey::new_ip_single_hop(ifname, dst);
            master
                .sessions
                .get_mut_by_key(&key)
                .map(|(sess_idx, _)| ListEntry::Session(sess_idx))
                .expect("could not find BFD session")
        })
        .path(bfd::ip_sh::sessions::session::source_addr::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let src = args.dnode.get_ip();
            sess.config.src = Some(src);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            sess.config.src = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .path(bfd::ip_sh::sessions::session::local_multiplier::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let local_multiplier = args.dnode.get_u8();
            sess.config.local_multiplier = local_multiplier;

            // NOTE: the use of a Poll Sequence isn't necessary for this change.
        })
        .path(bfd::ip_sh::sessions::session::desired_min_tx_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_tx = args.dnode.get_u32();
            sess.config.min_tx = min_tx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_sh::sessions::session::required_min_rx_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_rx = args.dnode.get_u32();
            sess.config.min_rx = min_rx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_sh::sessions::session::min_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_interval = args.dnode.get_u32();
            sess.config.min_tx = min_interval;
            sess.config.min_rx = min_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_sh::sessions::session::admin_down::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let admin_down = args.dnode.get_bool();
            sess.config.admin_down = admin_down;

            let event_queue = args.event_queue;
            event_queue.insert(Event::AdminDownChange(sess_idx));
        })
        .path(bfd::ip_sh::interfaces::PATH)
        .create_apply(|_master, _args| {
            // Nothing to do for now.
        })
        .delete_apply(|_master, _args| {
            // Nothing to do for now.
        })
        .lookup(|_master, _list_entry, _dnode| ListEntry::None)
        .path(bfd::ip_mh::session_groups::session_group::PATH)
        .create_apply(|master, args| {
            let src = args.dnode.get_ip_relative("source-addr").unwrap();
            let dst = args.dnode.get_ip_relative("dest-addr").unwrap();

            // Get existing session or create a new one.
            let sess_key = SessionKey::new_ip_multihop(src, dst);
            let (sess_idx, sess) = master.sessions.insert(sess_key);
            sess.config.tx_ttl = Some(TTL_MAX);
            sess.config.rx_ttl = Some(TTL_MAX);
            sess.config_enabled = true;

            // Initialize session's socket address.
            sess.state.sockaddr =
                Some(SocketAddr::new(dst, network::PORT_DST_MULTIHOP));

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateRxSockets);
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            sess.config_enabled = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SessionDeleteCheck(sess_idx));
            event_queue.insert(Event::UpdateRxSockets);
        })
        .lookup(|master, _list_entry, dnode| {
            let src = dnode.get_ip_relative("source-addr").unwrap();
            let dst = dnode.get_ip_relative("dest-addr").unwrap();
            let key = SessionKey::new_ip_multihop(src, dst);
            master
                .sessions
                .get_mut_by_key(&key)
                .map(|(sess_idx, _)| ListEntry::Session(sess_idx))
                .expect("could not find BFD session")
        })
        .path(bfd::ip_mh::session_groups::session_group::local_multiplier::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let local_multiplier = args.dnode.get_u8();
            sess.config.local_multiplier = local_multiplier;

            // NOTE: the use of a Poll Sequence isn't necessary for this change.
        })
        .path(bfd::ip_mh::session_groups::session_group::desired_min_tx_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_tx = args.dnode.get_u32();
            sess.config.min_tx = min_tx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_mh::session_groups::session_group::required_min_rx_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_rx = args.dnode.get_u32();
            sess.config.min_rx = min_rx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_mh::session_groups::session_group::min_interval::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let min_interval = args.dnode.get_u32();
            sess.config.min_tx = min_interval;
            sess.config.min_rx = min_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StartPollSequence(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .delete_apply(|_master, _args| {
            // Nothing to do.
        })
        .path(bfd::ip_mh::session_groups::session_group::admin_down::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let admin_down = args.dnode.get_bool();
            sess.config.admin_down = admin_down;

            let event_queue = args.event_queue;
            event_queue.insert(Event::AdminDownChange(sess_idx));
        })
        .path(bfd::ip_mh::session_groups::session_group::tx_ttl::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let ttl = args.dnode.get_u8();
            sess.config.tx_ttl = Some(ttl);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTxSocket(sess_idx));
            event_queue.insert(Event::UpdateTxInterval(sess_idx));
        })
        .path(bfd::ip_mh::session_groups::session_group::rx_ttl::PATH)
        .modify_apply(|master, args| {
            let sess_idx = args.list_entry.into_session().unwrap();
            let sess = &mut master.sessions[sess_idx];

            let ttl = args.dnode.get_u8();
            sess.config.rx_ttl = Some(ttl);
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(bfd::ip_sh::sessions::session::desired_min_tx_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .path(bfd::ip_sh::sessions::session::required_min_rx_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .path(bfd::ip_sh::sessions::session::min_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .path(bfd::ip_mh::session_groups::session_group::desired_min_tx_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .path(bfd::ip_mh::session_groups::session_group::required_min_rx_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .path(bfd::ip_mh::session_groups::session_group::min_interval::PATH)
        .validate(|args| {
            let interval = args.dnode.get_u32();
            validate_interval(interval)
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn validation_callbacks() -> Option<&'static ValidationCallbacks> {
        Some(&VALIDATION_CALLBACKS)
    }

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::SessionDeleteCheck(sess_idx) => {
                self.sessions.delete_check(sess_idx);
            }
            Event::AdminDownChange(sess_idx) => {
                let sess = &mut self.sessions[sess_idx];
                let (state, diag) = match sess.config.admin_down {
                    true => (State::AdminDown, DiagnosticCode::AdminDown),
                    false => (State::Down, DiagnosticCode::Nothing),
                };
                sess.state_update(state, diag, &self.tx);

                // Should we stop sending packets after one Detection Time?
            }
            Event::StartPollSequence(sess_idx) => {
                let sess = &mut self.sessions[sess_idx];
                sess.poll_sequence_start();
            }
            Event::UpdateRxSockets => {
                // Start or stop UDP Rx tasks if necessary.
                self.update_udp_rx_tasks();
            }
            Event::UpdateTxSocket(sess_idx) => {
                let sess = &mut self.sessions[sess_idx];
                sess.update_socket_tx();
            }
            Event::UpdateTxInterval(sess_idx) => {
                let sess = &mut self.sessions[sess_idx];
                sess.update_tx_interval();
            }
        }
    }
}

// ===== helper functions =====

fn validate_interval(interval: u32) -> Result<(), String> {
    if interval < MIN_SUPPORTED_INTERVAL {
        return Err("unsupported interval (min: 50ms)".to_string());
    }

    Ok(())
}

// ===== configuration defaults =====

impl Default for SessionCfg {
    fn default() -> SessionCfg {
        let local_multiplier =
            bfd::ip_sh::sessions::session::local_multiplier::DFLT;
        let min_tx =
            bfd::ip_sh::sessions::session::desired_min_tx_interval::DFLT;
        let min_rx =
            bfd::ip_sh::sessions::session::required_min_rx_interval::DFLT;
        let admin_down = bfd::ip_sh::sessions::session::admin_down::DFLT;

        SessionCfg {
            local_multiplier,
            min_tx,
            min_rx,
            admin_down,
            src: None,
            tx_ttl: None,
            rx_ttl: None,
        }
    }
}
