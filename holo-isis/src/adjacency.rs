//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use chrono::Utc;
use derive_new::new;
use holo_utils::bfd;
use holo_utils::ip::{AddressFamilies, AddressFamily};
use holo_utils::mac_addr::MacAddr;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::sr::Sid;
use holo_utils::task::TimeoutTask;

use crate::collections::AdjacencyId;
use crate::debug::Debug;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, InterfaceType};
use crate::northbound::notification;
use crate::packet::consts::PduType;
use crate::packet::subtlvs::neighbor::{AdjSidFlags, AdjSidStlv};
use crate::packet::tlv::{ExtendedSeqNum, ThreeWayAdjState};
use crate::packet::{AreaAddr, LanId, LevelType, SystemId};
use crate::{sr, tasks};

#[derive(Debug)]
pub struct Adjacency {
    pub id: AdjacencyId,
    pub snpa: MacAddr,
    pub system_id: SystemId,
    pub level_capability: LevelType,
    pub level_usage: LevelType,
    pub state: AdjacencyState,
    pub priority: Option<u8>,
    pub lan_id: Option<LanId>,
    pub three_way_state: ThreeWayAdjState,
    pub ext_circuit_id: Option<u32>,
    pub ext_seqnum: HashMap<PduType, ExtendedSeqNum>,
    pub protocols_supported: Vec<u8>,
    pub area_addrs: BTreeSet<AreaAddr>,
    pub topologies: BTreeSet<u16>,
    pub neighbors: BTreeSet<MacAddr>,
    pub ipv4_addrs: BTreeSet<Ipv4Addr>,
    pub ipv6_addrs: BTreeSet<Ipv6Addr>,
    pub bfd: AddressFamilies<Option<AdjacencyBfd>>,
    pub adj_sids: Vec<AdjacencySid>,
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
    BfdDown,
    LinkDown,
    Kill,
}

#[derive(Debug)]
pub struct AdjacencyBfd {
    pub sess_key: bfd::SessionKey,
    pub state: Option<bfd::State>,
}

#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
pub struct AdjacencySid {
    pub af: AddressFamily,
    pub label: Label,
    pub nbr_system_id: Option<SystemId>,
}

// ===== impl Adjacency =====

impl Adjacency {
    // Creates new adjacency.
    pub(crate) fn new(
        id: AdjacencyId,
        snpa: MacAddr,
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
            three_way_state: ThreeWayAdjState::Down,
            ext_circuit_id: None,
            ext_seqnum: Default::default(),
            protocols_supported: Default::default(),
            area_addrs: Default::default(),
            topologies: Default::default(),
            neighbors: Default::default(),
            ipv4_addrs: Default::default(),
            ipv6_addrs: Default::default(),
            bfd: Default::default(),
            adj_sids: Default::default(),
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

        if iface.config.interface_type == InterfaceType::Broadcast {
            // On broadcast interfaces, we maintain a cache of active
            // adjacencies (Init or Up, but not Down). Any time this set
            // changes, we restart the Hello Tx task so the neighbors TLV
            // is updated.
            let level = self.level_usage;
            let adjacencies = iface.state.lan_adjacencies.get_mut(level);
            if self.state == AdjacencyState::Down {
                adjacencies.active_mut().insert(self.snpa);
                iface.hello_interval_start(instance, level);
            } else if new_state == AdjacencyState::Down {
                adjacencies.active_mut().remove(&self.snpa);
                iface.hello_interval_start(instance, level);
            }

            // Trigger DIS election.
            instance
                .tx
                .protocol_input
                .dis_election(iface.id, level.into());
        }

        // Update Adj-SID(s) associated to this adjacency.
        if instance.config.sr.enabled {
            if new_state == AdjacencyState::Up {
                sr::adj_sids_add(instance, iface, self);
            } else if self.state == AdjacencyState::Up {
                sr::adj_sids_del(instance, self);
            }
        }

        // Removes BFD peers if the adjacency transitions to Down.
        if new_state == AdjacencyState::Down {
            self.bfd_clear_sessions(instance);
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

        // Schedule LSP reorigination for all levels where the adjacency exists.
        //
        // If this is an L2 adjacency in an L1/L2 router, the L1 LSP must also
        // be reoriginated. This is necessary because the connection to the
        // backbone may have changed (e.g., broken or become available), which
        // affects the setting of the ATT bit in L1 LSPs.
        let mut level_type = self.level_usage;
        if level_type == LevelType::L2
            && instance.config.level_type == LevelType::All
        {
            level_type = level_type.union(LevelType::L1);
        }
        instance.schedule_lsp_origination(level_type);
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

    // Registers or updates BFD sessions for this adjacency based on the current
    // set of IPv4 and IPv6 addresses.
    //
    // For each address family, if a local address is present, a BFD session is
    // registered if one is missing or if `force` is `true`. If no address is
    // available for a given family, any existing session for that family is
    // unregistered.
    pub(crate) fn bfd_update_sessions(
        &mut self,
        iface: &Interface,
        instance: &InstanceUpView<'_>,
        force: bool,
    ) {
        let mut bfd = std::mem::take(&mut self.bfd);
        for (af, bfd) in bfd.iter_mut() {
            let addr = match af {
                AddressFamily::Ipv4 => {
                    self.ipv4_addrs.first().copied().map(Into::into)
                }
                AddressFamily::Ipv6 => {
                    self.ipv6_addrs.first().copied().map(Into::into)
                }
            };

            if iface.config.is_af_enabled(af, instance.config)
                && let Some(addr) = addr
            {
                if bfd.is_none() || force {
                    let sess_key = bfd::SessionKey::new_ip_single_hop(
                        iface.name.clone(),
                        addr,
                    );
                    self.bfd_register(sess_key.clone(), iface, instance);
                    *bfd = Some(AdjacencyBfd::new(sess_key));
                }
            } else if let Some(bfd) = bfd.take() {
                self.bfd_unregister(bfd.sess_key, instance);
            }
        }
        self.bfd = bfd;
    }

    // Unregisters and removes all BFD sessions associated with this adjacency.
    pub(crate) fn bfd_clear_sessions(&mut self, instance: &InstanceUpView<'_>) {
        if let Some(bfd) = self.bfd.ipv4.take() {
            self.bfd_unregister(bfd.sess_key, instance);
        }
        if let Some(bfd) = self.bfd.ipv6.take() {
            self.bfd_unregister(bfd.sess_key, instance);
        }
    }

    // Registers a BFD session for this adjacency with the given session key.
    fn bfd_register(
        &self,
        sess_key: bfd::SessionKey,
        iface: &Interface,
        instance: &InstanceUpView<'_>,
    ) {
        Debug::AdjacencyBfdReg(self, sess_key.dst()).log();

        let client_id =
            bfd::ClientId::new(Protocol::ISIS, instance.name.to_owned());
        instance.tx.ibus.bfd_session_reg(
            sess_key.clone(),
            client_id,
            Some(iface.config.bfd_params),
        );
    }

    // Unregisters the BFD session associated with the given session key.
    fn bfd_unregister(
        &self,
        sess_key: bfd::SessionKey,
        instance: &InstanceUpView<'_>,
    ) {
        Debug::AdjacencyBfdUnreg(self, sess_key.dst()).log();

        instance.tx.ibus.bfd_session_unreg(sess_key);
    }

    // Returns whether the adjacency should be operational based on BFD state.
    //
    // The adjacency is considered up if any associated IPv4 or IPv6 BFD session
    // is up.
    pub(crate) fn is_bfd_healthy(&self) -> bool {
        self.bfd
            .iter()
            .filter_map(|(_, bfd)| bfd.as_ref())
            .any(|bfd| bfd.is_up())
    }
}

impl Drop for Adjacency {
    fn drop(&mut self) {
        Debug::AdjacencyDelete(self).log();
    }
}

// ===== impl AdjacencyBfd =====

impl AdjacencyBfd {
    fn new(sess_key: bfd::SessionKey) -> AdjacencyBfd {
        AdjacencyBfd {
            sess_key,
            state: None,
        }
    }

    pub(crate) fn is_up(&self) -> bool {
        self.state
            .as_ref()
            .map(|state| *state == bfd::State::Up)
            .unwrap_or(true)
    }
}

// ===== impl AdjacencySid =====

impl AdjacencySid {
    pub(crate) fn to_stlv(&self) -> AdjSidStlv {
        let mut flags = AdjSidFlags::V | AdjSidFlags::L;
        if self.af == AddressFamily::Ipv6 {
            flags.insert(AdjSidFlags::F);
        }
        let sid = Sid::Label(self.label);
        AdjSidStlv::new(flags, 0, self.nbr_system_id, sid)
    }
}

// ===== global functions =====

// Computes the next three-way adjacency state based on the current adjacency
// state and the state received in the neighbor's Hello PDU.
pub(crate) fn three_way_handshake(
    adj_state: ThreeWayAdjState,
    hello_state: ThreeWayAdjState,
) -> Option<ThreeWayAdjState> {
    use ThreeWayAdjState::{Down, Initializing, Up};

    match hello_state {
        Down => Some(Initializing),

        Initializing => match adj_state {
            Down | Initializing => Some(Up),
            Up => None,
        },

        Up => match adj_state {
            Down => Some(Down),
            Initializing => Some(Up),
            Up => None,
        },
    }
}
