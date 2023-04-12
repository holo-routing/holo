//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::hash_map;

use async_trait::async_trait;
use derive_new::new;
use holo_protocol::MessageReceiver;
use holo_southbound::rx::{SouthboundRx, SouthboundRxCallbacks};
use holo_southbound::zclient::messages::{ZapiRxIfaceInfo, ZapiRxMsg};

use crate::master::{Interface, Master};

#[derive(Debug, new)]
pub struct InstanceSouthboundRx(pub SouthboundRx);

// ===== impl Master =====

#[async_trait]
impl SouthboundRxCallbacks for Master {
    async fn process_iface_upd(&mut self, msg: ZapiRxIfaceInfo) {
        // Update interface's ifindex.
        match self.interfaces.entry(msg.ifname.clone()) {
            hash_map::Entry::Occupied(mut o) => {
                let iface = o.get_mut();
                // Return earlier if the ifindex hasn't changed.
                if iface.ifindex == msg.ifindex {
                    return;
                }
                iface.ifindex = msg.ifindex;
            }
            hash_map::Entry::Vacant(v) => {
                let iface = Interface::new(msg.ifname.clone(), msg.ifindex);
                v.insert(iface);
            }
        }

        // Update the ifindex of all single-hop sessions attached to this
        // interface.
        for sess_idx in self
            .sessions
            .iter_by_ifname(&msg.ifname)
            .collect::<Vec<_>>()
        {
            self.sessions.update_ifindex(sess_idx, msg.ifindex);
        }
    }
}

// ===== impl InstanceSouthboundRx =====

#[async_trait]
impl MessageReceiver<ZapiRxMsg> for InstanceSouthboundRx {
    async fn recv(&mut self) -> Option<ZapiRxMsg> {
        self.0.recv().await
    }
}
