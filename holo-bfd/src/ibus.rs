//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::hash_map;
use std::net::SocketAddr;

use holo_utils::bfd::{ClientCfg, ClientId, SessionKey};
use holo_utils::ibus::IbusSubscriber;
use holo_utils::southbound::InterfaceUpdateMsg;

use crate::debug::Debug;
use crate::error::Error;
use crate::master::{Interface, Master};
use crate::network;
use crate::session::SessionClient;

// ===== global functions =====

pub(crate) fn process_iface_update(
    master: &mut Master,
    msg: InterfaceUpdateMsg,
) {
    // Update interface's ifindex.
    match master.interfaces.entry(msg.ifname.clone()) {
        hash_map::Entry::Occupied(mut o) => {
            let iface = o.get_mut();
            // Return earlier if the ifindex hasn't changed.
            if iface.ifindex == Some(msg.ifindex) {
                return;
            }
            iface.ifindex = Some(msg.ifindex);
        }
        hash_map::Entry::Vacant(v) => {
            let iface = Interface::new(msg.ifname.clone(), Some(msg.ifindex));
            v.insert(iface);
        }
    }

    // Update the ifindex of all single-hop sessions attached to this
    // interface.
    for sess_idx in master
        .sessions
        .iter_by_ifname(&msg.ifname)
        .collect::<Vec<_>>()
    {
        master.sessions.update_ifindex(sess_idx, Some(msg.ifindex));
    }
}

pub(crate) fn process_client_peer_reg(
    master: &mut Master,
    subscriber: IbusSubscriber,
    sess_key: SessionKey,
    client_id: ClientId,
    client_config: Option<ClientCfg>,
) -> Result<(), Error> {
    Debug::SessionClientReg(&sess_key, &client_id).log();

    let (sess_idx, sess) = master.sessions.insert(sess_key);
    let client = SessionClient::new(client_id, client_config, subscriber.tx);
    sess.clients.insert(subscriber.id, client);

    // Start Poll Sequence as the configuration parameters might have changed.
    sess.poll_sequence_start();

    // Try to initialize session if possible.
    sess.update_socket_tx();
    match &sess.key {
        SessionKey::IpSingleHop { ifname, .. } => {
            if let Some(iface) = master.interfaces.get(ifname) {
                master.sessions.update_ifindex(sess_idx, iface.ifindex);
            }
        }
        SessionKey::IpMultihop { dst, .. } => {
            sess.state.sockaddr =
                Some(SocketAddr::new(*dst, network::PORT_DST_MULTIHOP));
            sess.update_tx_interval();
        }
    }

    // Start UDP Rx tasks if necessary.
    master.update_udp_rx_tasks();

    Ok(())
}

pub(crate) fn process_client_peer_unreg(
    master: &mut Master,
    subscriber: IbusSubscriber,
    sess_key: SessionKey,
) -> Result<(), Error> {
    let Some((sess_idx, sess)) = master.sessions.get_mut_by_key(&sess_key)
    else {
        return Ok(());
    };

    // Remove BFD client.
    let Some(client) = sess.clients.remove(&subscriber.id) else {
        return Ok(());
    };

    Debug::SessionClientUnreg(&sess_key, &client.id).log();

    // Check if the BFD session can be deleted.
    master.sessions.delete_check(sess_idx);

    // Stop UDP Rx tasks if necessary.
    master.update_udp_rx_tasks();

    Ok(())
}
