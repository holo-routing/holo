//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;

use holo_northbound::{notification, yang, NbProviderSender};
use holo_utils::bfd::SessionKey;
use holo_yang::ToYang;

use crate::session::Session;

// ===== global functions =====

pub(crate) fn state_change(nb_tx: &NbProviderSender, sess: &Session) {
    match &sess.key {
        SessionKey::IpSingleHop { ifname, dst } => {
            state_change_singlehop(ifname, dst, nb_tx, sess);
        }
        SessionKey::IpMultihop { src, dst } => {
            state_change_multihop(src, dst, nb_tx, sess);
        }
    }
}

// ===== helper functions =====

fn state_change_singlehop(
    ifname: &str,
    dst: &IpAddr,
    nb_tx: &NbProviderSender,
    sess: &Session,
) {
    use yang::singlehop_notification::{self, SinglehopNotification};

    let data = SinglehopNotification {
        local_discr: Some(sess.state.local_discr),
        remote_discr: sess.state.remote.as_ref().map(|remote| remote.discr),
        new_state: Some(sess.state.local_state.to_yang()),
        state_change_reason: Some(sess.state.local_diag.to_yang()),
        time_of_last_state_change: sess
            .statistics
            .last_state_change_time
            .as_ref()
            .map(Cow::Borrowed),
        dest_addr: Some(Cow::Borrowed(dst)),
        source_addr: sess.config.src.as_ref().map(Cow::Borrowed),
        session_index: Some(sess.id as u32),
        path_type: Some(sess.key.path_type().to_yang()),
        interface: Some(ifname.into()),
        echo_enabled: Some(false),
    };
    notification::send(nb_tx, singlehop_notification::PATH, data);
}

fn state_change_multihop(
    src: &IpAddr,
    dst: &IpAddr,
    nb_tx: &NbProviderSender,
    sess: &Session,
) {
    use yang::multihop_notification::{self, MultihopNotification};

    let data = MultihopNotification {
        local_discr: Some(sess.state.local_discr),
        remote_discr: sess.state.remote.as_ref().map(|remote| remote.discr),
        new_state: Some(sess.state.local_state.to_yang()),
        state_change_reason: Some(sess.state.local_diag.to_yang()),
        time_of_last_state_change: sess
            .statistics
            .last_state_change_time
            .as_ref()
            .map(Cow::Borrowed),
        dest_addr: Some(Cow::Borrowed(dst)),
        source_addr: Some(Cow::Borrowed(src)),
        session_index: Some(sess.id as u32),
        path_type: Some(sess.key.path_type().to_yang()),
    };
    notification::send(nb_tx, multihop_notification::PATH, data);
}
