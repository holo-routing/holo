//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::{atomic, LazyLock as Lazy};

use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::bfd;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, NodeAttributes, Provider,
};
use holo_utils::bfd::{SessionKey, State};
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
    CallbacksBuilder::default()
        .path(bfd::summary::number_of_sessions::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master.sessions.iter().count();
            Some(count as u32)
        })
        .path(bfd::summary::number_of_sessions_up::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.state.local_state == State::Up)
                .count();
            Some(count as u32)
        })
        .path(bfd::summary::number_of_sessions_down::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.state.local_state == State::Down)
                .count();
            Some(count as u32)
        })
        .path(bfd::summary::number_of_sessions_admin_down::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.state.local_state == State::AdminDown)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_sh::summary::number_of_sessions::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_single_hop())
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_sh::summary::number_of_sessions_up::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_single_hop())
                .filter(|sess| sess.state.local_state == State::Up)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_sh::summary::number_of_sessions_down::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_single_hop())
                .filter(|sess| sess.state.local_state == State::Down)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_sh::summary::number_of_sessions_admin_down::PATH)
        .get_element_u32(|master: &Master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_single_hop())
                .filter(|sess| sess.state.local_state == State::AdminDown)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_sh::sessions::session::PATH)
        .get_iterate(|master, _args| {
            let iter = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_single_hop())
                .map(ListEntry::Session);
            Some(Box::new(iter))
        })
        .path(bfd::ip_sh::sessions::session::path_type::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.key.path_type().to_yang())
        })
        .path(bfd::ip_sh::sessions::session::ip_encapsulation::PATH)
        .get_element_bool(|_master, _args| {
            Some(true)
        })
        .path(bfd::ip_sh::sessions::session::local_discriminator::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_discr)
        })
        .path(bfd::ip_sh::sessions::session::remote_discriminator::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.discr)
        })
        .path(bfd::ip_sh::sessions::session::remote_multiplier::PATH)
        .get_element_u8(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.multiplier)
        })
        .path(bfd::ip_sh::sessions::session::source_port::PATH)
        .get_element_u16(|_master, _args| {
            Some(*network::PORT_SRC_RANGE.start())
        })
        .path(bfd::ip_sh::sessions::session::dest_port::PATH)
        .get_element_u16(|_master, _args| {
            Some(network::PORT_DST_SINGLE_HOP)
        })
        .path(bfd::ip_sh::sessions::session::session_running::session_index::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.id as u32)
        })
        .path(bfd::ip_sh::sessions::session::session_running::local_state::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_state.to_yang())
        })
        .path(bfd::ip_sh::sessions::session::session_running::remote_state::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.state.to_yang())
        })
        .path(bfd::ip_sh::sessions::session::session_running::local_diagnostic::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_diag.to_yang())
        })
        .path(bfd::ip_sh::sessions::session::session_running::remote_diagnostic::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref()
                .map(|remote| remote.diag)
                .and_then(DiagnosticCode::from_u8)
                .map(|diag| diag.to_yang())
        })
        .path(bfd::ip_sh::sessions::session::session_running::remote_authenticated::PATH)
        .get_element_bool(|_master, _args| {
            // TODO: BFD authentication isn't supported yet.
            Some(false)
        })
        .path(bfd::ip_sh::sessions::session::session_running::detection_mode::PATH)
        .get_element_string(|_master, _args| {
            // Use hardcoded value for now.
            Some("async-without-echo".to_owned())
        })
        .path(bfd::ip_sh::sessions::session::session_running::negotiated_tx_interval::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.negotiated_tx_interval()
        })
        .path(bfd::ip_sh::sessions::session::session_running::negotiated_rx_interval::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.negotiated_rx_interval()
        })
        .path(bfd::ip_sh::sessions::session::session_running::detection_time::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.detection_time()
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::create_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.create_time)
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::last_down_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.statistics.last_down_time
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::last_up_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.statistics.last_up_time
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::down_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.down_count)
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::admin_down_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.admin_down_count)
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::receive_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.rx_packet_count)
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::send_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.tx_packet_count.load(atomic::Ordering::Relaxed))
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::receive_invalid_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.rx_error_count)
        })
        .path(bfd::ip_sh::sessions::session::session_statistics::send_failed_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.tx_error_count.load(atomic::Ordering::Relaxed))
        })
        .path(bfd::ip_sh::interfaces::PATH)
        .get_iterate(|_master, _args| None)
        .path(bfd::ip_mh::summary::number_of_sessions::PATH)
        .get_element_u32(|master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_multihop())
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_mh::summary::number_of_sessions_up::PATH)
        .get_element_u32(|master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_multihop())
                .filter(|sess| sess.state.local_state == State::Up)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_mh::summary::number_of_sessions_down::PATH)
        .get_element_u32(|master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_multihop())
                .filter(|sess| sess.state.local_state == State::Down)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_mh::summary::number_of_sessions_admin_down::PATH)
        .get_element_u32(|master, _args| {
            let count = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_multihop())
                .filter(|sess| sess.state.local_state == State::AdminDown)
                .count();
            Some(count as u32)
        })
        .path(bfd::ip_mh::session_groups::session_group::PATH)
        .get_iterate(|master, _args| {
            let iter = master
                .sessions
                .iter()
                .filter(|sess| sess.key.is_ip_multihop())
                .map(ListEntry::Session);
            Some(Box::new(iter))
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::PATH)
        .get_iterate(|_master, args| {
            let sess = args.parent_list_entry.as_session().unwrap();
            Some(Box::new(std::iter::once(ListEntry::Session(sess))))
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::path_type::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.key.path_type().to_yang())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::ip_encapsulation::PATH)
        .get_element_bool(|_master, _args| {
            Some(true)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::local_discriminator::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_discr)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::remote_discriminator::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.discr)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::remote_multiplier::PATH)
        .get_element_u8(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.multiplier)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::source_port::PATH)
        .get_element_u16(|_master, _args| {
            Some(*network::PORT_SRC_RANGE.start())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::dest_port::PATH)
        .get_element_u16(|_master, _args| {
            Some(network::PORT_DST_MULTIHOP)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::session_index::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.id as u32)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::local_state::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_state.to_yang())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::remote_state::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref().map(|remote| remote.state.to_yang())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::local_diagnostic::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.state.local_diag.to_yang())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::remote_diagnostic::PATH)
        .get_element_string(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.state.remote.as_ref()
                .map(|remote| remote.diag)
                .and_then(DiagnosticCode::from_u8)
                .map(|diag| diag.to_yang())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::remote_authenticated::PATH)
        .get_element_bool(|_master, _args| {
            // TODO: BFD authentication isn't supported yet.
            Some(false)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::detection_mode::PATH)
        .get_element_string(|_master, _args| {
            // Use hardcoded value for now.
            Some("async-without-echo".to_owned())
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::negotiated_tx_interval::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.negotiated_tx_interval()
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::negotiated_rx_interval::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.negotiated_rx_interval()
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_running::detection_time::PATH)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.detection_time()
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::create_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.create_time)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::last_down_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.statistics.last_down_time
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::last_up_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            sess.statistics.last_up_time
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::down_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.down_count)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::admin_down_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u32(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.admin_down_count)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::receive_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.rx_packet_count)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::send_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.tx_packet_count.load(atomic::Ordering::Relaxed))
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::receive_invalid_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.rx_error_count)
        })
        .path(bfd::ip_mh::session_groups::session_group::sessions::session_statistics::send_failed_packet_count::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_master, args| {
            let sess = args.list_entry.as_session().unwrap();
            Some(sess.statistics.tx_error_count.load(atomic::Ordering::Relaxed))
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-bfd-types:bfdv1'][name='main']/ietf-bfd:bfd";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::Session(sess) => match &sess.key {
                SessionKey::IpSingleHop { ifname, dst } => {
                    use bfd::ip_sh::sessions::session::list_keys;
                    let keys = list_keys(ifname, dst);
                    Some(keys)
                }
                SessionKey::IpMultihop { src, dst } => {
                    use bfd::ip_mh::session_groups::session_group::list_keys;
                    let keys = list_keys(src, dst);
                    Some(keys)
                }
            },
        }
    }
}
