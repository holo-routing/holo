//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU32};

use chrono::{DateTime, Utc};
use holo_utils::ip::{AddressFamily, JointPrefixSetExt};
use holo_utils::mac_addr::MacAddr;
use holo_utils::socket::{AsyncFd, Socket, SocketExt};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::sr::MsdType;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use ipnetwork::IpNetwork;
use prefix_trie::joint::set::JointPrefixSet;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

use crate::adjacency::{Adjacency, AdjacencyEvent, AdjacencyState};
use crate::collections::{Adjacencies, Arena, InterfaceId, InterfaceIndex};
use crate::debug::{Debug, InterfaceInactiveReason};
use crate::error::{Error, IoError};
use crate::instance::InstanceUpView;
use crate::network::{LLC_HDR, MulticastAddr};
use crate::northbound::configuration::InterfaceCfg;
use crate::northbound::notification;
use crate::packet::consts::{MtId, Nlpid, PduType};
use crate::packet::pdu::{Hello, HelloTlvs, HelloVariant, Lsp, Pdu};
use crate::packet::tlv::{
    ExtendedSeqNum, LspEntry, MtFlags, MultiTopologyEntry, ThreeWayAdjState,
    ThreeWayAdjTlv,
};
use crate::packet::{LanId, LevelNumber, LevelType, Levels, LspId, SystemId};
use crate::tasks::messages::output::NetTxPduMsg;
use crate::{network, tasks};

#[derive(Debug)]
pub struct Interface {
    pub index: InterfaceIndex,
    pub id: InterfaceId,
    pub name: String,
    pub system: InterfaceSys,
    pub config: InterfaceCfg,
    pub state: InterfaceState,
}

#[derive(Debug, Default)]
pub struct InterfaceSys {
    pub flags: InterfaceFlags,
    pub ifindex: Option<u32>,
    pub mtu: Option<u32>,
    pub msd: BTreeMap<MsdType, u8>,
    pub mac_addr: Option<MacAddr>,
    pub addr_list: JointPrefixSet<IpNetwork>,
}

#[derive(Debug, Default)]
pub struct InterfaceState {
    pub active: bool,
    pub net: Option<InterfaceNet>,
    pub circuit_id: u8,
    pub lan_adjacencies: Levels<Adjacencies>,
    pub p2p_adjacency: Option<Adjacency>,
    pub dis: Levels<Option<DisCandidate>>,
    pub srm_list: Levels<BTreeMap<LspId, IntervalTask>>,
    pub ssn_list: Levels<BTreeMap<LspId, LspEntry>>,
    pub ext_seqnum: (u64, Arc<AtomicU32>),
    pub event_counters: InterfaceEventCounters,
    pub packet_counters: Levels<InterfacePacketCounters>,
    pub discontinuity_time: DateTime<Utc>,
    pub tasks: InterfaceTasks,
}

#[derive(Debug)]
pub struct InterfaceNet {
    pub socket: Arc<AsyncFd<Socket>>,
    _net_tx_task: Task<()>,
    _net_rx_task: Task<()>,
    pub net_tx_pdup: UnboundedSender<NetTxPduMsg>,
}

#[derive(Debug, Default)]
pub struct InterfaceTasks {
    pub hello_interval_p2p: Option<IntervalTask>,
    pub hello_interval_broadcast: Levels<Option<IntervalTask>>,
    pub dis_initial_election: Levels<Option<TimeoutTask>>,
    pub psnp_interval: Levels<Option<IntervalTask>>,
    pub csnp_interval: Levels<Option<IntervalTask>>,
}

#[derive(Debug, Default)]
pub struct InterfaceEventCounters {
    pub adjacency_changes: u32,
    pub adjacency_number: u32,
    pub init_fails: u32,
    pub adjacency_rejects: u32,
    pub version_skew: u32,
    pub id_len_mismatch: u32,
    pub max_area_addr_mismatch: u32,
    pub area_mismatch: u32,
    pub auth_type_fails: u32,
    pub auth_fails: u32,
    pub lan_dis_changes: u32,
}

#[derive(Debug, Default)]
pub struct InterfacePacketCounters {
    pub iih_in: u32,
    pub iih_out: Arc<AtomicU32>,
    pub lsp_in: u32,
    pub lsp_out: u32,
    pub psnp_in: u32,
    pub psnp_out: u32,
    pub csnp_in: u32,
    pub csnp_out: u32,
    pub unknown_in: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceType {
    Broadcast,
    PointToPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisCandidate {
    pub priority: u8,
    pub snpa: MacAddr,
    pub system_id: SystemId,
    pub lan_id: LanId,
    pub myself: bool,
}

#[derive(Debug)]
pub struct CircuitIdAllocator {
    allocated_ids: BTreeSet<u8>,
    next_id: u8,
}

// ===== impl Interface =====

impl Interface {
    pub(crate) fn new(
        index: InterfaceIndex,
        id: InterfaceId,
        name: String,
    ) -> Interface {
        Debug::InterfaceCreate(&name).log();

        Interface {
            index,
            id,
            name,
            system: InterfaceSys::default(),
            config: InterfaceCfg::default(),
            state: InterfaceState::default(),
        }
    }

    // Checks if the interface needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        adjacencies: &mut Arena<Adjacency>,
    ) -> Result<(), Error> {
        match self.is_ready() {
            Ok(()) if !self.state.active => {
                self.start(instance).map_err(|error| {
                    Error::InterfaceStartError(
                        self.name.clone(),
                        Box::new(error),
                    )
                })?
            }
            Err(reason) if self.state.active => {
                self.stop(instance, adjacencies, reason)
            }
            _ => (),
        }

        Ok(())
    }

    fn start(
        &mut self,
        instance: &mut InstanceUpView<'_>,
    ) -> Result<(), Error> {
        Debug::InterfaceStart(&self.name).log();
        notification::if_state_change(instance, self, true);

        if !self.is_passive() {
            if self.config.interface_type == InterfaceType::Broadcast {
                // Allocate Circuit ID.
                //
                // For interfaces operating in the point-to-point mode, there's
                // no need to allocate a Circuit ID since it's used purely for
                // informational purposes.
                self.state.circuit_id =
                    instance.state.circuit_id_allocator.allocate()?;

                // Schedule initial DIS election.
                self.dis_initial_election_start(instance);
            }

            // Create raw socket.
            let socket = network::socket(self.system.ifindex.unwrap())
                .map_err(IoError::SocketError)?;
            if self.system.flags.contains(InterfaceFlags::BROADCAST) {
                self.system.join_multicast(&socket, MulticastAddr::AllIss);
                self.system.join_multicast(&socket, MulticastAddr::AllL1Iss);
                self.system.join_multicast(&socket, MulticastAddr::AllL2Iss);
            }
            let socket = AsyncFd::new(socket).map_err(IoError::SocketError)?;
            let socket = Arc::new(socket);

            // Start network Tx/Rx tasks.
            self.state.net = Some(InterfaceNet::new(socket, self, instance));

            // Start Hello Tx task(s).
            self.hello_interval_start(instance, LevelType::All);

            // Start PSNP interval task(s).
            self.psnp_interval_start(instance);

            // Initialize the extended sequence number used for PDU transmission.
            self.state.ext_seqnum =
                (instance.state.boot_count, Arc::new(AtomicU32::new(0)));
        }

        // Mark interface as active.
        self.state.active = true;

        // Schedule LSP reorigination.
        instance.schedule_lsp_origination(self.config.level_type.resolved);

        Ok(())
    }

    pub(crate) fn stop(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        arena_adjacencies: &mut Arena<Adjacency>,
        reason: InterfaceInactiveReason,
    ) {
        if !self.state.active {
            return;
        }

        Debug::InterfaceStop(&self.name, reason).log();
        notification::if_state_change(instance, self, false);

        // Resign from being the DIS.
        if self.config.interface_type == InterfaceType::Broadcast {
            for level in self.config.levels() {
                if !self.is_dis(level) {
                    continue;
                }
                self.dis_stop(instance);
                *self.state.dis.get_mut(level) = None;
            }
        }

        // Remove all adjacencies.
        let event = if reason == InterfaceInactiveReason::OperationalDown {
            AdjacencyEvent::LinkDown
        } else {
            AdjacencyEvent::Kill
        };
        self.clear_adjacencies(instance, arena_adjacencies, event);

        // Release Circuit ID back to the pool.
        if self.config.interface_type == InterfaceType::Broadcast {
            instance
                .state
                .circuit_id_allocator
                .release(self.state.circuit_id);
            self.state.circuit_id = 0;
        }

        // Reset interface state.
        self.state.active = false;
        self.state.net = None;
        self.state.dis = Default::default();
        self.state.srm_list = Default::default();
        self.state.ssn_list = Default::default();
        self.hello_interval_stop();
        self.dis_initial_election_stop();
        self.psnp_interval_stop();
        self.csnp_interval_stop();

        // Schedule LSP reorigination.
        instance.schedule_lsp_origination(self.config.level_type.resolved);
    }

    pub(crate) fn reset(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        adjacencies: &mut Arena<Adjacency>,
    ) -> Result<(), Error> {
        if self.state.active {
            self.stop(
                instance,
                adjacencies,
                InterfaceInactiveReason::Resetting,
            );
            self.start(instance)?;
        }

        Ok(())
    }

    pub(crate) fn restart_network_tasks(
        &mut self,
        instance: &mut InstanceUpView<'_>,
    ) {
        if let Some(net) = self.state.net.take() {
            self.state.net =
                Some(InterfaceNet::new(net.socket, self, instance));
            self.hello_interval_start(instance, LevelType::All);
        }
    }

    pub(crate) const fn is_loopback(&self) -> bool {
        self.system.flags.contains(InterfaceFlags::LOOPBACK)
    }

    pub(crate) const fn is_passive(&self) -> bool {
        self.is_loopback() || self.config.passive
    }

    fn is_ready(&self) -> Result<(), InterfaceInactiveReason> {
        if !self.config.enabled {
            return Err(InterfaceInactiveReason::AdminDown);
        }

        if !self.system.flags.contains(InterfaceFlags::OPERATIVE) {
            return Err(InterfaceInactiveReason::OperationalDown);
        }

        if self.system.ifindex.is_none() {
            return Err(InterfaceInactiveReason::MissingIfindex);
        }

        if self.system.mtu.is_none() {
            return Err(InterfaceInactiveReason::MissingMtu);
        }

        if self.system.flags.contains(InterfaceFlags::BROADCAST)
            && self.system.mac_addr.is_none()
        {
            return Err(InterfaceInactiveReason::MissingMacAddr);
        }

        if self.config.interface_type == InterfaceType::Broadcast
            && !self.system.flags.contains(InterfaceFlags::BROADCAST)
            && !self.system.flags.contains(InterfaceFlags::LOOPBACK)
        {
            return Err(InterfaceInactiveReason::BroadcastUnsupported);
        }

        Ok(())
    }

    pub(crate) fn adjacencies<'a>(
        &'a self,
        adjacencies: &'a Arena<Adjacency>,
    ) -> impl Iterator<Item = &'a Adjacency> {
        let lan_l1 = self.state.lan_adjacencies.l1.iter(adjacencies);
        let lan_l2 = self.state.lan_adjacencies.l2.iter(adjacencies);
        let p2p = self.state.p2p_adjacency.as_ref();
        lan_l1.chain(lan_l2).chain(p2p)
    }

    // Runs the provided closure on each adjacency of the interface, abstracting
    // over whether the interface is broadcast or point-to-point.
    pub(crate) fn with_adjacencies<F>(
        &mut self,
        arena_adjacencies: &mut Arena<Adjacency>,
        mut f: F,
    ) where
        F: FnMut(&mut Interface, &mut Adjacency),
    {
        match self.config.interface_type {
            InterfaceType::Broadcast => {
                let mut adjacencies =
                    std::mem::take(&mut self.state.lan_adjacencies);
                for level in self.config.levels() {
                    for adj_idx in adjacencies.get_mut(level).indexes() {
                        let adj = &mut arena_adjacencies[adj_idx];
                        f(self, adj);
                    }
                }
                self.state.lan_adjacencies = adjacencies;
            }
            InterfaceType::PointToPoint => {
                if let Some(mut adj) = self.state.p2p_adjacency.take() {
                    f(self, &mut adj);
                    self.state.p2p_adjacency = Some(adj);
                }
            }
        }
    }

    pub(crate) fn clear_adjacencies(
        &mut self,
        instance: &mut InstanceUpView<'_>,
        arena_adjacencies: &mut Arena<Adjacency>,
        event: AdjacencyEvent,
    ) {
        // Transition each adjacency to the Down state.
        self.with_adjacencies(arena_adjacencies, |iface, adj| {
            adj.state_change(iface, instance, event, AdjacencyState::Down);
        });

        // Remove adjacencies based on the interface type.
        match self.config.interface_type {
            InterfaceType::Broadcast => {
                self.state.lan_adjacencies.l1.clear(arena_adjacencies);
                self.state.lan_adjacencies.l2.clear(arena_adjacencies);
            }
            InterfaceType::PointToPoint => {
                self.state.p2p_adjacency = None;
            }
        }
    }

    // Returns the MTU size available for sending IS-IS PDUs.
    fn iso_mtu(&self) -> u32 {
        let mut l2_mtu = self.system.mtu.unwrap();

        // On broadcast networks, we need to account for the 3-byte LLC header.
        //
        // For historical reasons, many vendors adopt a maximum PDU length of
        // 1492, which also accounts for the 5-byte SNAP header. However, since
        // IS-IS over SNAP is not implemented in practice, the effective maximum
        // MTU can be considered 1497 bytes, accounting only for the LLC header.
        if self.system.flags.contains(InterfaceFlags::BROADCAST) {
            l2_mtu -= LLC_HDR.len() as u32;
        }

        l2_mtu
    }

    pub(crate) fn dis_election(
        &mut self,
        instance: &InstanceUpView<'_>,
        adjacencies: &Arena<Adjacency>,
        level: LevelNumber,
    ) -> Option<DisCandidate> {
        // Select adjacencies that are eligible for DIS election.
        let mut adjs = self
            .state
            .lan_adjacencies
            .get(level)
            .iter(adjacencies)
            .filter(|adj| adj.state == AdjacencyState::Up)
            .map(|adj| DisCandidate {
                priority: adj.priority.unwrap(),
                snpa: adj.snpa,
                system_id: adj.system_id,
                lan_id: adj.lan_id.unwrap(),
                myself: false,
            })
            .peekable();

        // No DIS should be elected when there are no eligible adjacencies.
        adjs.peek()?;

        // Add ourselves as a DIS candidate.
        let system_id = instance.config.system_id.unwrap();
        let myself = DisCandidate {
            priority: self.config.priority.get(level),
            snpa: self.system.mac_addr.unwrap(),
            system_id,
            lan_id: LanId::from((system_id, self.state.circuit_id)),
            myself: true,
        };

        // Elect the DIS by comparing priorities, using SNPA as a tie-breaker.
        std::iter::once(myself)
            .chain(adjs)
            .max_by_key(|rtr| (rtr.priority, rtr.snpa))
    }

    pub(crate) fn is_dis(&self, level: LevelNumber) -> bool {
        self.state.dis.get(level).is_some_and(|dis| dis.myself)
    }

    pub(crate) fn dis_start(&mut self, instance: &mut InstanceUpView<'_>) {
        self.csnp_interval_start(instance);
    }

    pub(crate) fn dis_stop(&mut self, _instance: &mut InstanceUpView<'_>) {
        self.csnp_interval_stop();
    }

    pub(crate) fn ext_seqnum_next(
        &self,
        level_type: impl Into<LevelType>,
    ) -> Option<ExtendedSeqNum> {
        self.config.ext_seqnum_mode.get(level_type)?;
        Some(ExtendedSeqNum::new(
            self.state.ext_seqnum.0,
            self.state
                .ext_seqnum
                .1
                .fetch_add(1, atomic::Ordering::Relaxed),
        ))
    }

    fn generate_hello(
        &self,
        level: impl Into<LevelType>,
        instance: &InstanceUpView<'_>,
    ) -> Hello {
        let level = level.into();

        // Fixed fields.
        let circuit_type = self.config.level_type.resolved;
        let source = instance.config.system_id.unwrap();
        let holdtime = self.config.hello_holdtime(level);
        let variant = match self.config.interface_type {
            InterfaceType::Broadcast => HelloVariant::Lan {
                priority: self.config.priority.get(level),
                lan_id: self
                    .state
                    .dis
                    .get(level)
                    .map(|dis| dis.lan_id)
                    // Use the current DIS, or default to ourselves if none is
                    // elected (see IS-IS 8.4.1.a).
                    .unwrap_or(LanId::from((source, self.state.circuit_id))),
            },
            InterfaceType::PointToPoint => HelloVariant::P2P {
                local_circuit_id: self.state.circuit_id,
            },
        };

        // Set area addresses.
        let area_addrs = instance.config.area_addrs.clone();

        // Set topologies.
        let mut multi_topology = vec![];
        let topologies = self.config.topologies(instance.config);
        if topologies != [MtId::Standard].into() {
            multi_topology = topologies
                .into_iter()
                .map(|mt_id| MultiTopologyEntry {
                    flags: MtFlags::empty(),
                    mt_id: mt_id as u16,
                })
                .collect::<Vec<_>>();
        }

        // Set LAN neighbors.
        let mut neighbors = vec![];
        if self.config.interface_type == InterfaceType::Broadcast {
            let adjacencies = self.state.lan_adjacencies.get(level);
            neighbors.extend(adjacencies.active().clone());
        }

        // Set P2P Adjacency Three-Way State.
        let mut three_way_adj = None;
        if self.config.interface_type == InterfaceType::PointToPoint {
            let mut state = ThreeWayAdjState::Down;
            let local_circuit_id = self.system.ifindex.unwrap();
            let mut neighbor = None;

            if let Some(adj) = &self.state.p2p_adjacency {
                state = adj.three_way_state;
                if let Some(adj_ext_circuit_id) = adj.ext_circuit_id {
                    neighbor = Some((adj.system_id, adj_ext_circuit_id));
                }
            }
            three_way_adj = Some(ThreeWayAdjTlv {
                state,
                local_circuit_id: Some(local_circuit_id),
                neighbor,
            });
        }

        // Set IP information.
        let mut protocols_supported = vec![];
        let mut ipv4_addrs = vec![];
        let mut ipv6_addrs = vec![];
        if self
            .config
            .is_af_enabled(AddressFamily::Ipv4, instance.config)
        {
            protocols_supported.push(Nlpid::Ipv4 as u8);
            ipv4_addrs.extend(
                self.system.addr_list.ipv4().iter().map(|addr| addr.ip()),
            );
        }
        if self
            .config
            .is_af_enabled(AddressFamily::Ipv6, instance.config)
        {
            protocols_supported.push(Nlpid::Ipv6 as u8);
            ipv6_addrs.extend(
                self.system
                    .addr_list
                    .ipv6()
                    .iter()
                    .filter(|addr| addr.ip().is_unicast_link_local())
                    .map(|addr| addr.ip()),
            );
        }

        // Generate Hello PDU.
        let ext_seqnum = self.ext_seqnum_next(level);
        Hello::new(
            level,
            circuit_type,
            source,
            holdtime,
            variant,
            HelloTlvs::new(
                protocols_supported,
                area_addrs,
                multi_topology,
                neighbors,
                three_way_adj,
                ipv4_addrs,
                ipv6_addrs,
                ext_seqnum,
            ),
        )
    }

    pub(crate) fn hello_interval_start(
        &mut self,
        instance: &InstanceUpView<'_>,
        level_filter: impl Into<LevelType>,
    ) {
        let level_filter = level_filter.into();
        match self.config.interface_type {
            // For broadcast interfaces, send separate Hello PDUs for each level
            // (L1 and/or L2), depending on the configuration.
            InterfaceType::Broadcast => {
                for level in self
                    .config
                    .levels()
                    .filter(|level| level_filter.intersects(level))
                {
                    let hello = self.generate_hello(level, instance);
                    let task = tasks::hello_interval(self, level, hello);
                    *self.state.tasks.hello_interval_broadcast.get_mut(level) =
                        Some(task);
                }
            }
            // For point-to-point interfaces, send a single Hello PDU,
            // regardless of whether IS-IS is enabled for L1, L2, or both.
            InterfaceType::PointToPoint => {
                let level = LevelType::All;
                let hello = self.generate_hello(level, instance);
                let task = tasks::hello_interval(self, level, hello);
                self.state.tasks.hello_interval_p2p = Some(task);
            }
        }
    }

    fn hello_interval_stop(&mut self) {
        self.state.tasks.hello_interval_broadcast = Default::default();
        self.state.tasks.hello_interval_p2p = Default::default();
    }

    fn dis_initial_election_start(&mut self, instance: &InstanceUpView<'_>) {
        for level in self.config.levels() {
            let task = tasks::dis_initial_election(self, level, instance);
            *self.state.tasks.dis_initial_election.get_mut(level) = Some(task);
        }
    }

    fn dis_initial_election_stop(&mut self) {
        self.state.tasks.dis_initial_election = Default::default();
    }

    fn psnp_interval_start(&mut self, instance: &InstanceUpView<'_>) {
        for level in self.config.levels() {
            let task = tasks::psnp_interval(self, level, instance);
            *self.state.tasks.psnp_interval.get_mut(level) = Some(task);
        }
    }

    fn psnp_interval_stop(&mut self) {
        self.state.tasks.psnp_interval = Default::default();
    }

    pub(crate) fn csnp_interval_start(
        &mut self,
        instance: &InstanceUpView<'_>,
    ) {
        for level in self.config.levels() {
            let task = tasks::csnp_interval(self, level, instance);
            *self.state.tasks.csnp_interval.get_mut(level) = Some(task);
        }
    }

    pub(crate) fn csnp_interval_reset(
        &mut self,
        instance: &InstanceUpView<'_>,
    ) {
        for level in self.config.levels() {
            if self.state.tasks.csnp_interval.get(level).is_none() {
                continue;
            }
            let task = tasks::csnp_interval(self, level, instance);
            *self.state.tasks.csnp_interval.get_mut(level) = Some(task);
        }
    }

    pub(crate) fn csnp_interval_stop(&mut self) {
        self.state.tasks.csnp_interval = Default::default();
    }

    pub(crate) fn srm_list_add(
        &mut self,
        instance: &InstanceUpView<'_>,
        level: LevelNumber,
        mut lsp: Lsp,
    ) {
        // Proceed only if the interface is active and enabled for this level.
        if !self.state.active
            || !self.config.level_type.resolved.intersects(level)
        {
            return;
        }

        // Skip adding the LSP if there are no active adjacencies or the LSP's
        // sequence number is zero.
        if self.state.event_counters.adjacency_number == 0 || lsp.seqno == 0 {
            return;
        }

        // Check if the LSP is too large to be sent on this interface.
        if lsp.raw.len() as u32 > self.iso_mtu() {
            Debug::LspTooLarge(self, level, &lsp).log();
            notification::lsp_too_large(instance, self, &lsp);
            return;
        }

        // ISO 10589 - Section 7.3.16.3:
        // "A system shall decrement the Remaining Lifetime in the PDU being
        // transmitted by at least one".
        lsp.set_rem_lifetime(lsp.rem_lifetime().saturating_sub(1));

        // For point-to-point interfaces, all LSPs require acknowledgment.
        // Retransmissions will occur until an acknowledgment is received.
        if self.config.interface_type == InterfaceType::PointToPoint {
            if let Some(adj) = &self.state.p2p_adjacency
                && adj.level_usage.intersects(level)
            {
                let rxmt_interval = self.config.lsp_rxmt_interval;
                let dst = self.config.interface_type.multicast_addr(level);
                let task = tasks::lsp_rxmt_interval(
                    self,
                    lsp.clone(),
                    dst,
                    rxmt_interval,
                );
                self.state.srm_list.get_mut(level).insert(lsp.lsp_id, task);
            } else {
                return;
            }
        }

        // Enqueue LSP for transmission.
        //
        // TODO: Implement LSP pacing.
        self.enqueue_pdu(Pdu::Lsp(lsp), level);
    }

    pub(crate) fn srm_list_del(&mut self, level: LevelNumber, lsp_id: &LspId) {
        if self.config.interface_type == InterfaceType::PointToPoint {
            self.state.srm_list.get_mut(level).remove(lsp_id);
        }
    }

    pub(crate) fn ssn_list_add(&mut self, level: LevelNumber, entry: LspEntry) {
        self.state
            .ssn_list
            .get_mut(level)
            .insert(entry.lsp_id, entry);
    }

    pub(crate) fn ssn_list_del(&mut self, level: LevelNumber, lsp_id: &LspId) {
        self.state.ssn_list.get_mut(level).remove(lsp_id);
    }

    pub(crate) fn enqueue_pdu(&mut self, pdu: Pdu, level: LevelNumber) {
        // Update packet counters.
        match pdu.pdu_type() {
            PduType::HelloP2P | PduType::HelloLanL1 | PduType::HelloLanL2 => {
                // Updated separately on the hello_interval task.
            }
            PduType::LspL1 => {
                self.state.packet_counters.l1.lsp_out += 1;
            }
            PduType::LspL2 => {
                self.state.packet_counters.l2.lsp_out += 1;
            }
            PduType::CsnpL1 => {
                self.state.packet_counters.l1.csnp_out += 1;
            }
            PduType::CsnpL2 => {
                self.state.packet_counters.l2.csnp_out += 1;
            }
            PduType::PsnpL1 => {
                self.state.packet_counters.l1.psnp_out += 1;
            }
            PduType::PsnpL2 => {
                self.state.packet_counters.l2.psnp_out += 1;
            }
        }
        self.state.discontinuity_time = Utc::now();

        // Enqueue PDU for transmission.
        let dst = self.config.interface_type.multicast_addr(level);
        let msg = NetTxPduMsg {
            pdu,
            #[cfg(feature = "testing")]
            ifname: self.name.clone(),
            dst,
        };
        let _ = self.state.net.as_ref().unwrap().net_tx_pdup.send(msg);
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        Debug::InterfaceDelete(&self.name).log();
    }
}

// ===== impl InterfaceSys =====

impl InterfaceSys {
    fn join_multicast(&self, socket: &Socket, addr: MulticastAddr) {
        #[cfg(not(feature = "testing"))]
        {
            let ifindex = self.ifindex.unwrap();
            if let Err(error) =
                socket.join_packet_multicast(addr.as_bytes(), ifindex)
            {
                IoError::MulticastJoinError(addr, error).log();
            }
        }
    }

    #[expect(unused)]
    fn leave_multicast(&self, socket: &Socket, addr: MulticastAddr) {
        #[cfg(not(feature = "testing"))]
        {
            let ifindex = self.ifindex.unwrap();
            if let Err(error) =
                socket.leave_packet_multicast(addr.as_bytes(), ifindex)
            {
                IoError::MulticastJoinError(addr, error).log();
            }
        }
    }
}

// ===== impl InterfaceNet =====

impl InterfaceNet {
    pub(crate) fn new(
        socket: Arc<AsyncFd<Socket>>,
        iface: &Interface,
        instance: &mut InstanceUpView<'_>,
    ) -> Self {
        let broadcast = iface.system.flags.contains(InterfaceFlags::BROADCAST);
        let hello_padding = iface.config.hello_padding.then_some(
            std::cmp::max(iface.iso_mtu() as u16, instance.config.lsp_mtu),
        );
        let keychains = &instance.shared.keychains;
        let hello_auth = iface.config.hello_auth.all.method(keychains);
        let global_auth = instance.config.auth.all.method(keychains);
        let trace_opts = iface.config.trace_opts.packets_resolved.clone();
        let (net_tx_pdup, net_tx_pduc) = mpsc::unbounded_channel();
        let mut net_tx_task = tasks::net_tx(
            socket.clone(),
            broadcast,
            iface.name.clone(),
            iface.system.ifindex.unwrap(),
            hello_padding,
            hello_auth.clone(),
            global_auth.clone(),
            trace_opts,
            net_tx_pduc,
            #[cfg(feature = "testing")]
            &instance.tx.protocol_output,
        );
        let net_rx_task = tasks::net_rx(
            socket.clone(),
            broadcast,
            hello_auth,
            global_auth,
            iface,
            &instance.tx.protocol_input.net_pdu_rx,
        );
        net_tx_task.detach();

        InterfaceNet {
            socket,
            _net_tx_task: net_tx_task,
            _net_rx_task: net_rx_task,
            net_tx_pdup,
        }
    }
}

// ===== impl InterfaceType =====

impl InterfaceType {
    // Returns the multicast address used for transmitting PDUs based on the
    // interface type and IS-IS level.
    pub(crate) fn multicast_addr(
        &self,
        level_type: impl Into<LevelNumber>,
    ) -> MulticastAddr {
        match self {
            InterfaceType::Broadcast => match level_type.into() {
                LevelNumber::L1 => MulticastAddr::AllL1Iss,
                LevelNumber::L2 => MulticastAddr::AllL2Iss,
            },
            InterfaceType::PointToPoint => MulticastAddr::AllIss,
        }
    }
}

// ===== impl CircuitIdAllocator =====

impl CircuitIdAllocator {
    // Allocates a new circuit ID from 1 to 255. If all IDs are allocated,
    // returns an error.
    fn allocate(&mut self) -> Result<u8, Error> {
        if self.allocated_ids.len() == 255 {
            return Err(Error::CircuitIdAllocationFailed);
        }

        // Try to allocate the current next_id
        let mut id = self.next_id;

        // Find the next available ID
        while self.allocated_ids.contains(&id) {
            id = if id == 255 { 1 } else { id + 1 };
        }

        // Store the allocated ID and update next_id
        self.allocated_ids.insert(id);
        self.next_id = if id == 255 { 1 } else { id + 1 };

        Ok(id)
    }

    // Releases a circuit ID back to the pool.
    fn release(&mut self, id: u8) {
        self.allocated_ids.remove(&id);
    }
}

impl Default for CircuitIdAllocator {
    fn default() -> Self {
        CircuitIdAllocator {
            allocated_ids: BTreeSet::new(),
            next_id: 1,
        }
    }
}
