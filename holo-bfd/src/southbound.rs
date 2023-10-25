//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::hash_map;

use holo_utils::southbound::InterfaceUpdateMsg;

use crate::master::{Interface, Master};

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
