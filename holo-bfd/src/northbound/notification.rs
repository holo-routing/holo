//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use holo_northbound::{notification, paths, NbProviderSender};
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
    use paths::singlehop_notification as base;

    let local_discr = sess.state.local_discr.to_string();
    let remote_discr;
    let diag = sess.state.local_diag.to_yang();
    let last_state_change_time;
    let new_state = sess.state.local_state.to_yang();
    let dst = dst.to_string();
    let src_addr;
    let sess_index = sess.id.to_string();
    let path_type = sess.key.path_type().to_yang();

    let mut args = vec![];
    args.push((base::local_discr::PATH, Some(local_discr.as_str())));
    if let Some(remote) = &sess.state.remote {
        remote_discr = remote.discr.to_string();
        args.push((base::remote_discr::PATH, Some(remote_discr.as_str())));
    }
    args.push((base::new_state::PATH, Some(new_state.as_ref())));
    args.push((base::state_change_reason::PATH, Some(diag.as_ref())));
    if let Some(time) = &sess.statistics.last_state_change_time {
        last_state_change_time = time.to_rfc3339();
        args.push((
            base::time_of_last_state_change::PATH,
            Some(last_state_change_time.as_str()),
        ));
    }
    args.push((base::dest_addr::PATH, Some(dst.as_str())));
    if let Some(addr) = &sess.config.src {
        src_addr = addr.to_string();
        args.push((base::source_addr::PATH, Some(src_addr.as_str())));
    }
    args.push((base::session_index::PATH, Some(sess_index.as_str())));
    args.push((base::path_type::PATH, Some(path_type.as_ref())));
    args.push((base::interface::PATH, Some(ifname)));
    args.push((base::echo_enabled::PATH, Some("false")));
    notification::send(nb_tx, base::PATH, &args);
}

fn state_change_multihop(
    src: &IpAddr,
    dst: &IpAddr,
    nb_tx: &NbProviderSender,
    sess: &Session,
) {
    use paths::multihop_notification as base;

    let local_discr = sess.state.local_discr.to_string();
    let remote_discr;
    let diag = sess.state.local_diag.to_yang();
    let last_state_change_time;
    let new_state = sess.state.local_state.to_yang();
    let dst = dst.to_string();
    let src_addr = src.to_string();
    let sess_index = sess.id.to_string();
    let path_type = sess.key.path_type().to_yang();

    let mut args = vec![];
    args.push((base::local_discr::PATH, Some(local_discr.as_str())));
    if let Some(remote) = &sess.state.remote {
        remote_discr = remote.discr.to_string();
        args.push((base::remote_discr::PATH, Some(remote_discr.as_str())));
    }
    args.push((base::new_state::PATH, Some(new_state.as_ref())));
    args.push((base::state_change_reason::PATH, Some(diag.as_ref())));
    if let Some(time) = &sess.statistics.last_state_change_time {
        last_state_change_time = time.to_rfc3339();
        args.push((
            base::time_of_last_state_change::PATH,
            Some(last_state_change_time.as_str()),
        ));
    }
    args.push((base::dest_addr::PATH, Some(dst.as_str())));
    args.push((base::source_addr::PATH, Some(src_addr.as_str())));
    args.push((base::session_index::PATH, Some(sess_index.as_str())));
    args.push((base::path_type::PATH, Some(path_type.as_ref())));
    notification::send(nb_tx, base::PATH, &args);
}
