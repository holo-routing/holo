//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{btree_map, BTreeMap};
use std::time::Duration;

use chrono::{DateTime, Utc};
use holo_utils::task::TimeoutTask;
use holo_utils::Sender;

use crate::debug::Debug;
use crate::tasks;
use crate::tasks::messages::input::NbrTimeoutMsg;
use crate::version::Version;

// Unlike most other routing protocols, the RIP protocol doesn't have a defined
// notion of neighbors. There are no hello packets or sessions to maintain.
// Nevertheless, it's beneficial to keep track of all sources of RIP packets, as
// this information can be valuable for network monitoring and troubleshooting.
#[derive(Debug)]
pub struct Neighbor<V: Version> {
    // Neighbor's source address.
    pub addr: V::IpAddr,
    // Time when the most recent RIP update was received from this neighbor.
    pub last_update: DateTime<Utc>,
    // Number of RIP invalid packets received from this neighbor.
    pub bad_packets_rcvd: u32,
    // Number of valid routes received from this neighbor.
    pub bad_routes_rcvd: u32,
    // Last received authentication sequence number.
    pub auth_seqno: u32,
    // Neighbor's timeout (refreshed whenever a RIP update is received).
    pub timeout_task: TimeoutTask,
}

// ===== impl Neighbor =====

impl<V> Neighbor<V>
where
    V: Version,
{
    fn new(
        addr: V::IpAddr,
        timeout: u16,
        nbr_timeoutp: &Sender<NbrTimeoutMsg<V>>,
    ) -> Neighbor<V> {
        Debug::<V>::NbrCreate(&addr).log();

        let timeout = Duration::from_secs(timeout.into());
        let timeout_task = tasks::nbr_timeout::<V>(addr, timeout, nbr_timeoutp);

        Neighbor {
            addr,
            last_update: Utc::now(),
            bad_packets_rcvd: 0,
            bad_routes_rcvd: 0,
            auth_seqno: 0,
            timeout_task,
        }
    }

    fn timeout_reset(&mut self, timeout: u16) {
        let timeout = Duration::from_secs(timeout.into());
        self.timeout_task.reset(Some(timeout));
    }
}

// ===== global functions =====

pub(crate) fn update<'a, V>(
    neighbors: &'a mut BTreeMap<V::IpAddr, Neighbor<V>>,
    addr: V::IpAddr,
    timeout: u16,
    nbr_timeoutp: &Sender<NbrTimeoutMsg<V>>,
) -> &'a mut Neighbor<V>
where
    V: Version,
{
    match neighbors.entry(addr) {
        btree_map::Entry::Occupied(o) => {
            let nbr = o.into_mut();

            // Update last update.
            nbr.last_update = Utc::now();
            // Reset timeout.
            nbr.timeout_reset(timeout);

            nbr
        }
        btree_map::Entry::Vacant(v) => {
            // Add new neighbor.
            let nbr = Neighbor::new(addr, timeout, nbr_timeoutp);
            v.insert(nbr)
        }
    }
}
