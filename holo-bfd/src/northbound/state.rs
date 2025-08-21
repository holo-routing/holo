//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::{LazyLock as Lazy, atomic};

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::bfd;
use holo_utils::bfd::{PathType, State};
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;
use num_traits::FromPrimitive;

use crate::master::Master;
use crate::network;
use crate::packet::DiagnosticCode;
use crate::session::Session;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Session(&'a Session),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(bfd::summary::PATH)
        .get_object(|master, _args| {
            use bfd::summary::Summary;
            Box::new(Summary {
                number_of_sessions: Some(master.sessions_count(None, None).saturating_into()),
                number_of_sessions_up: Some(master.sessions_count(None, Some(State::Up)).saturating_into()),
                number_of_sessions_down: Some(master.sessions_count(None, Some(State::Down)).saturating_into()),
                number_of_sessions_admin_down: Some(master.sessions_count(None, Some(State::AdminDown)).saturating_into()),
            })
        })
        .path(bfd::ip_mh::summary::PATH)
        .get_object(|master, _args| {
            use bfd::ip_mh::summary::Summary;
            let path_type = Some(PathType::IpMultihop);
            Box::new(Summary {
                number_of_sessions: Some(master.sessions_count(path_type, None).saturating_into()),
                number_of_sessions_up: Some(master.sessions_count(path_type, Some(State::Up)).saturating_into()),
                number_of_sessions_down: Some(master.sessions_count(path_type, Some(State::Down)).saturating_into()),
                number_of_sessions_admin_down: Some(master.sessions_count(path_type, Some(State::AdminDown)).saturating_into()),
            })
        })
        .path(bfd::ip_mh::session_groups::session_group::PATH)
        .get_iterate(|master, _args| {
            let iter = master.sessions.iter().filter(|sess| sess.key.is_ip_multihop()).map(ListEntry::Session);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use bfd::ip_mh::session_groups::session_group::SessionGroup;
            let sess = args.list_entry.as_session().unwrap();
            let (src, dst) = sess.key.as_ip_multihop().unwrap();
            Box::new(SessionGroup {
                source_addr: Cow::Borrowed(src),
                dest_addr: Cow::Borrowed(dst),
            })
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::PATH)
        .get_iterate(|_master, args| {
            let sess = args.parent_list_entry.as_session().unwrap();
            Some(Box::new(std::iter::once(ListEntry::Session(sess))))
        })
        .get_object(|_master, args| {
            use bfd::ip_mh::session_groups::session_group::sessions::Sessions;
            let sess = args.list_entry.as_session().unwrap();
            Box::new(Sessions {
                path_type: Some(sess.key.path_type().to_yang()),
                ip_encapsulation: Some(true),
                local_discriminator: Some(sess.state.local_discr),
                remote_discriminator: sess.state.remote.as_ref().map(|remote| remote.discr),
                remote_multiplier: sess.state.remote.as_ref().map(|remote| remote.multiplier),
                source_port: Some(*network::PORT_SRC_RANGE.start()).ignore_in_testing(),
                dest_port: Some(network::PORT_DST_MULTIHOP).ignore_in_testing(),
            })
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::PATH)
        .get_object(|_master, args| {
            use bfd::ip_mh::session_groups::session_group::sessions::session_running::SessionRunning;
            let sess = args.list_entry.as_session().unwrap();
            Box::new(SessionRunning {
                session_index: Some(sess.id as u32),
                local_state: Some(sess.state.local_state.to_yang()),
                remote_state: sess.state.remote.as_ref().map(|remote| remote.state.to_yang()),
                local_diagnostic: Some(sess.state.local_diag.to_yang()),
                remote_diagnostic: sess.state.remote.as_ref().map(|remote| remote.diag).and_then(DiagnosticCode::from_u8).map(|diag| diag.to_yang()),
                remote_authenticated: Some(false),
                detection_mode: Some("async-without-echo".into()),
                negotiated_tx_interval: sess.negotiated_tx_interval(),
                negotiated_rx_interval: sess.negotiated_rx_interval(),
                detection_time: sess.detection_time(),
            })
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::PATH)
        .get_object(|_master, args| {
            use bfd::ip_mh::session_groups::session_group::sessions::session_statistics::SessionStatistics;
            let sess = args.list_entry.as_session().unwrap();
            Box::new(SessionStatistics {
                create_time: Some(Cow::Borrowed(&sess.statistics.create_time)).ignore_in_testing(),
                last_down_time: sess.statistics.last_down_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                last_up_time: sess.statistics.last_up_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                down_count: Some(sess.statistics.down_count).ignore_in_testing(),
                admin_down_count: Some(sess.statistics.admin_down_count).ignore_in_testing(),
                receive_packet_count: Some(sess.statistics.rx_packet_count).ignore_in_testing(),
                send_packet_count: Some(sess.statistics.tx_packet_count.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                receive_invalid_packet_count: Some(sess.statistics.rx_error_count).ignore_in_testing(),
                send_failed_packet_count: Some(sess.statistics.tx_error_count.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
            })
        })
        .path(bfd::ip_sh::summary::PATH)
        .get_object(|master, _args| {
            use bfd::ip_sh::summary::Summary;
            let path_type = Some(PathType::IpSingleHop);
            Box::new(Summary {
                number_of_sessions: Some(master.sessions_count(path_type, None).saturating_into()),
                number_of_sessions_up: Some(master.sessions_count(path_type, Some(State::Up)).saturating_into()),
                number_of_sessions_down: Some(master.sessions_count(path_type, Some(State::Down)).saturating_into()),
                number_of_sessions_admin_down: Some(master.sessions_count(path_type, Some(State::AdminDown)).saturating_into()),
            })
        })
        .path(bfd::ip_sh::sessions::session::PATH)
        .get_iterate(|master, _args| {
            let iter = master.sessions.iter().filter(|sess| sess.key.is_ip_single_hop()).map(ListEntry::Session);
            Some(Box::new(iter))
        })
        .get_object(|_master, args| {
            use bfd::ip_sh::sessions::session::Session;
            let sess = args.list_entry.as_session().unwrap();
            let (ifname, dst) = sess.key.as_ip_single_hop().unwrap();
            Box::new(Session {
                interface: ifname.into(),
                dest_addr: Cow::Borrowed(dst),
                path_type: Some(sess.key.path_type().to_yang()),
                ip_encapsulation: Some(true),
                local_discriminator: Some(sess.state.local_discr),
                remote_discriminator: sess.state.remote.as_ref().map(|remote| remote.discr),
                remote_multiplier: sess.state.remote.as_ref().map(|remote| remote.multiplier),
                source_port: Some(*network::PORT_SRC_RANGE.start()).ignore_in_testing(),
                dest_port: Some(network::PORT_DST_SINGLE_HOP).ignore_in_testing(),
            })
        })
        .path(bfd::ip_sh::sessions::session::session_running::PATH)
        .get_object(|_master, args| {
            use bfd::ip_sh::sessions::session::session_running::SessionRunning;
            let sess = args.list_entry.as_session().unwrap();
            Box::new(SessionRunning {
                session_index: Some(sess.id as u32),
                local_state: Some(sess.state.local_state.to_yang()),
                remote_state: sess.state.remote.as_ref().map(|remote| remote.state.to_yang()),
                local_diagnostic: Some(sess.state.local_diag.to_yang()),
                remote_diagnostic: sess.state.remote.as_ref().map(|remote| remote.diag).and_then(DiagnosticCode::from_u8).map(|diag| diag.to_yang()),
                remote_authenticated: Some(false),
                detection_mode: Some("async-without-echo".into()),
                negotiated_tx_interval: sess.negotiated_tx_interval(),
                negotiated_rx_interval: sess.negotiated_rx_interval(),
                detection_time: sess.detection_time(),
            })
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::PATH)
        .get_object(|_master, args| {
            use bfd::ip_sh::sessions::session::session_statistics::SessionStatistics;
            let sess = args.list_entry.as_session().unwrap();
            Box::new(SessionStatistics {
                create_time: Some(Cow::Borrowed(&sess.statistics.create_time)).ignore_in_testing(),
                last_down_time: sess.statistics.last_down_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                last_up_time: sess.statistics.last_up_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                down_count: Some(sess.statistics.down_count).ignore_in_testing(),
                admin_down_count: Some(sess.statistics.admin_down_count).ignore_in_testing(),
                receive_packet_count: Some(sess.statistics.rx_packet_count).ignore_in_testing(),
                send_packet_count: Some(sess.statistics.tx_packet_count.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                receive_invalid_packet_count: Some(sess.statistics.rx_error_count).ignore_in_testing(),
                send_failed_packet_count: Some(sess.statistics.tx_error_count.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
            })
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Master> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}
