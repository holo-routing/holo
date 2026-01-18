//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::sync::atomic;

use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
use holo_utils::bfd::{PathType, State};
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;
use num_traits::FromPrimitive;

use crate::master::Master;
use crate::network;
use crate::northbound::yang_gen::{self, bfd};
use crate::packet::DiagnosticCode;
use crate::session::Session;

impl Provider for Master {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

#[derive(Debug, Default)]
#[derive(EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    Session(&'a Session),
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Master> for bfd::summary::Summary {
    fn new(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<Self> {
        Some(Self {
            number_of_sessions: Some(master.sessions_count(None, None).saturating_into()),
            number_of_sessions_up: Some(master.sessions_count(None, Some(State::Up)).saturating_into()),
            number_of_sessions_down: Some(master.sessions_count(None, Some(State::Down)).saturating_into()),
            number_of_sessions_admin_down: Some(master.sessions_count(None, Some(State::AdminDown)).saturating_into()),
        })
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_mh::summary::Summary {
    fn new(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let path_type = Some(PathType::IpMultihop);
        Some(Self {
            number_of_sessions: Some(master.sessions_count(path_type, None).saturating_into()),
            number_of_sessions_up: Some(master.sessions_count(path_type, Some(State::Up)).saturating_into()),
            number_of_sessions_down: Some(master.sessions_count(path_type, Some(State::Down)).saturating_into()),
            number_of_sessions_admin_down: Some(master.sessions_count(path_type, Some(State::AdminDown)).saturating_into()),
        })
    }
}

impl<'a> YangList<'a, Master> for bfd::ip_mh::session_groups::session_group::SessionGroup<'a> {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.sessions.iter().filter(|sess| sess.key.is_ip_multihop()).map(ListEntry::Session);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let sess = list_entry.as_session().unwrap();
        let (src, dst) = sess.key.as_ip_multihop().unwrap();
        Self {
            source_addr: Cow::Borrowed(src),
            dest_addr: Cow::Borrowed(dst),
        }
    }
}

impl<'a> YangList<'a, Master> for bfd::ip_mh::session_groups::session_group::sessions::Sessions<'a> {
    fn iter(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let sess = list_entry.as_session().unwrap();
        Some(Box::new(std::iter::once(ListEntry::Session(sess))))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let sess = list_entry.as_session().unwrap();
        Self {
            path_type: Some(sess.key.path_type().to_yang()),
            ip_encapsulation: Some(true),
            local_discriminator: Some(sess.state.local_discr),
            remote_discriminator: sess.state.remote.as_ref().map(|remote| remote.discr),
            remote_multiplier: sess.state.remote.as_ref().map(|remote| remote.multiplier),
            source_port: Some(*network::PORT_SRC_RANGE.start()).ignore_in_testing(),
            dest_port: Some(network::PORT_DST_MULTIHOP).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_mh::session_groups::session_group::sessions::session_running::SessionRunning<'a> {
    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<Self> {
        let sess = list_entry.as_session().unwrap();
        Some(Self {
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
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_mh::session_groups::session_group::sessions::session_statistics::SessionStatistics<'a> {
    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<Self> {
        let sess = list_entry.as_session().unwrap();
        Some(Self {
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
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_sh::summary::Summary {
    fn new(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<Self> {
        let path_type = Some(PathType::IpSingleHop);
        Some(Self {
            number_of_sessions: Some(master.sessions_count(path_type, None).saturating_into()),
            number_of_sessions_up: Some(master.sessions_count(path_type, Some(State::Up)).saturating_into()),
            number_of_sessions_down: Some(master.sessions_count(path_type, Some(State::Down)).saturating_into()),
            number_of_sessions_admin_down: Some(master.sessions_count(path_type, Some(State::AdminDown)).saturating_into()),
        })
    }
}

impl<'a> YangList<'a, Master> for bfd::ip_sh::sessions::session::Session<'a> {
    fn iter(master: &'a Master, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iter = master.sessions.iter().filter(|sess| sess.key.is_ip_single_hop()).map(ListEntry::Session);
        Some(Box::new(iter))
    }

    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Self {
        let sess = list_entry.as_session().unwrap();
        let (ifname, dst) = sess.key.as_ip_single_hop().unwrap();
        Self {
            interface: Cow::Borrowed(ifname),
            dest_addr: Cow::Borrowed(dst),
            path_type: Some(sess.key.path_type().to_yang()),
            ip_encapsulation: Some(true),
            local_discriminator: Some(sess.state.local_discr),
            remote_discriminator: sess.state.remote.as_ref().map(|remote| remote.discr),
            remote_multiplier: sess.state.remote.as_ref().map(|remote| remote.multiplier),
            source_port: Some(*network::PORT_SRC_RANGE.start()).ignore_in_testing(),
            dest_port: Some(network::PORT_DST_SINGLE_HOP).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_sh::sessions::session::session_running::SessionRunning<'a> {
    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<Self> {
        let sess = list_entry.as_session().unwrap();
        Some(Self {
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
    }
}

impl<'a> YangContainer<'a, Master> for bfd::ip_sh::sessions::session::session_statistics::SessionStatistics<'a> {
    fn new(_master: &'a Master, list_entry: &ListEntry<'a>) -> Option<Self> {
        let sess = list_entry.as_session().unwrap();
        Some(Self {
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
    }
}
