//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use chrono::Utc;
use holo_utils::task::TimeoutTask;

use crate::collections::AdjacencyId;
use crate::debug::Debug;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, InterfaceType};
use crate::northbound::notification;
use crate::packet::{AreaAddr, LanId, LevelType, SystemId};
use crate::tasks;

#[derive(Debug)]
pub struct Adjacency {
    pub id: AdjacencyId,
    pub snpa: [u8; 6],
    pub system_id: SystemId,
    pub level_capability: LevelType,
    pub level_usage: LevelType,
    pub state: AdjacencyState,
    pub priority: Option<u8>,
    pub lan_id: Option<LanId>,
    pub area_addrs: BTreeSet<AreaAddr>,
    pub neighbors: BTreeSet<[u8; 6]>,
    pub ipv4_addrs: BTreeSet<Ipv4Addr>,
    pub ipv6_addrs: BTreeSet<Ipv6Addr>,
    pub last_uptime: Option<Instant>,
    pub holdtimer: Option<TimeoutTask>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjacencyState {
    Down,
    Initializing,
    Up,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjacencyEvent {
    HelloOneWayRcvd,
    HelloTwoWayRcvd,
    HoldtimeExpired,
    LinkDown,
    Kill,
}

// ===== impl Adjacency =====

impl Adjacency {
    // Creates new adjacency.
    pub(crate) fn new(
        id: AdjacencyId,
        snpa: [u8; 6],
        system_id: SystemId,
        level_capability: LevelType,
        level_usage: LevelType,
    ) -> Adjacency {
        let adj = Adjacency {
            id,
            snpa,
            system_id,
            level_capability,
            level_usage,
            state: AdjacencyState::Down,
            priority: None,
            lan_id: None,
            area_addrs: Default::default(),
            neighbors: Default::default(),
            ipv4_addrs: Default::default(),
            ipv6_addrs: Default::default(),
            last_uptime: None,
            holdtimer: None,
        };
        Debug::AdjacencyCreate(&adj).log();
        adj
    }

    // Transitions the adjacency state if different from the current one.
    pub(crate) fn state_change(
        &mut self,
        iface: &mut Interface,
        instance: &mut InstanceUpView<'_>,
        event: AdjacencyEvent,
        new_state: AdjacencyState,
    ) {
        if self.state == new_state {
            return;
        }

        // Log the state transition.
        Debug::AdjacencyStateChange(self, new_state, event).log();

        // Send YANG notification.
        notification::adjacency_state_change(
            instance, iface, self, new_state, event,
        );

        // Update counters.
        if new_state == AdjacencyState::Up {
            iface.state.event_counters.adjacency_number += 1;
            self.last_uptime = Some(Instant::now());
        } else if self.state == AdjacencyState::Up {
            iface.state.event_counters.adjacency_number -= 1;
        }
        iface.state.event_counters.adjacency_changes += 1;
        iface.state.discontinuity_time = Utc::now();

        // ISO 10589 does not require periodic CSNP transmission on
        // point-to-point interfaces. However, sending them helps prevent
        // synchronization issues, especially in mesh-group setups.
        if iface.config.interface_type == InterfaceType::PointToPoint {
            if new_state == AdjacencyState::Up {
                // Start CSNP interval task(s).
                iface.csnp_interval_start(instance);
            } else if self.state == AdjacencyState::Up {
                // Stop CSNP interval task(s).
                iface.csnp_interval_stop();
            }
        }

        // If no adjacencies remain in the Up state, clear SRM and SSN lists.
        if iface.state.event_counters.adjacency_number == 0 {
            for level in iface.config.levels() {
                iface.state.srm_list.get_mut(level).clear();
                iface.state.ssn_list.get_mut(level).clear();
            }
        }

        // Effectively transition to the new state.
        self.state = new_state;

        // Schedule LSP reorigination.
        instance.schedule_lsp_origination(self.level_usage);
    }

    // Starts or resets the holdtime timer.
    pub(crate) fn holdtimer_reset(
        &mut self,
        iface: &Interface,
        instance: &InstanceUpView<'_>,
        holdtime: u16,
    ) {
        if let Some(holdtimer) = self.holdtimer.as_mut() {
            holdtimer.reset(None);
        } else {
            let task =
                tasks::adjacency_holdtimer(self, iface, instance, holdtime);
            self.holdtimer = Some(task);
        }
    }
}

impl Drop for Adjacency {
    fn drop(&mut self) {
        Debug::AdjacencyDelete(self).log();
    }
}
