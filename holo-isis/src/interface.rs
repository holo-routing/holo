//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use holo_protocol::InstanceChannelsTx;
use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::ip::AddressFamily;
use holo_utils::socket::{AsyncFd, Socket, SocketExt};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use holo_utils::UnboundedSender;
use ipnetwork::{Ipv4Network, Ipv6Network};
use tokio::sync::mpsc;

use crate::adjacency::{Adjacency, AdjacencyEvent, AdjacencyState};
use crate::collections::{Adjacencies, Arena, InterfaceId};
use crate::debug::{Debug, InterfaceInactiveReason};
use crate::error::{Error, IoError};
use crate::instance::{Instance, InstanceUpView};
use crate::network::{MulticastAddr, LLC_HDR};
use crate::northbound::configuration::InterfaceCfg;
use crate::northbound::notification;
use crate::packet::consts::PduType;
use crate::packet::pdu::{Hello, HelloTlvs, HelloVariant, Lsp, Pdu};
use crate::packet::tlv::{LspEntry, Nlpid};
use crate::packet::{LanId, LevelNumber, LevelType, Levels, LspId, SystemId};
use crate::tasks::messages::output::NetTxPduMsg;
use crate::{network, tasks};

#[derive(Debug)]
pub struct Interface {
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
    pub mac_addr: Option<[u8; 6]>,
    pub ipv4_addr_list: BTreeSet<Ipv4Network>,
    pub ipv6_addr_list: BTreeSet<Ipv6Network>,
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
    pub snpa: [u8; 6],
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
    pub(crate) fn new(id: InterfaceId, name: String) -> Interface {
        Debug::InterfaceCreate(&name).log();

        Interface {
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

            // Start network Tx/Rx tasks.
            let net =
                InterfaceNet::new(self, instance.tx).map_err(Error::IoError)?;
            self.state.net = Some(net);

            // Start Hello Tx task(s).
            self.hello_interval_start(instance, LevelType::All);

            // Start PSNP interval task(s).
            self.psnp_interval_start(instance);
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
        let new_state = AdjacencyState::Down;
        match self.config.interface_type {
            InterfaceType::Broadcast => {
                let mut adjacencies =
                    std::mem::take(&mut self.state.lan_adjacencies);
                for level in self.config.levels() {
                    let adjacencies = adjacencies.get_mut(level);
                    for adj_idx in adjacencies.indexes() {
                        let adj = &mut arena_adjacencies[adj_idx];
                        adj.state_change(self, instance, event, new_state);
                    }
                    adjacencies.clear(arena_adjacencies);
                }
                self.state.lan_adjacencies = adjacencies;
            }
            InterfaceType::PointToPoint => {
                if let Some(mut adj) = self.state.p2p_adjacency.take() {
                    adj.state_change(self, instance, event, new_state);
                }
            }
        }

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

    pub(crate) const fn is_passive(&self) -> bool {
        self.system.flags.contains(InterfaceFlags::LOOPBACK)
            || self.config.passive
    }

    fn is_ready(&self) -> Result<(), InterfaceInactiveReason> {
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

    pub(crate) fn iso_mtu(&self) -> u32 {
        let l2_mtu = self.system.mtu.unwrap();
        match self.config.interface_type {
            InterfaceType::Broadcast => l2_mtu - LLC_HDR.len() as u32,
            InterfaceType::PointToPoint => l2_mtu,
        }
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
        self.state.dis.get(level).map_or(false, |dis| dis.myself)
    }

    pub(crate) fn dis_start(&mut self, instance: &mut InstanceUpView<'_>) {
        self.csnp_interval_start(instance);
    }

    pub(crate) fn dis_stop(&mut self, _instance: &mut InstanceUpView<'_>) {
        self.csnp_interval_stop();
    }

    fn generate_hello(
        &self,
        level: impl Into<LevelType>,
        instance: &InstanceUpView<'_>,
    ) -> Pdu {
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

        // Set LAN neighbors.
        let mut neighbors = vec![];
        if self.config.interface_type == InterfaceType::Broadcast {
            neighbors.extend(self.state.lan_adjacencies.get(level).snpas());
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
                self.system.ipv4_addr_list.iter().map(|addr| addr.ip()),
            );
        }
        if self
            .config
            .is_af_enabled(AddressFamily::Ipv6, instance.config)
        {
            protocols_supported.push(Nlpid::Ipv6 as u8);
            ipv6_addrs.extend(
                self.system.ipv6_addr_list.iter().map(|addr| addr.ip()),
            );
        }

        Pdu::Hello(Hello::new(
            level,
            circuit_type,
            source,
            holdtime,
            variant,
            HelloTlvs::new(
                protocols_supported,
                area_addrs,
                neighbors,
                ipv4_addrs,
                ipv6_addrs,
            ),
        ))
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
                    .into_iter()
                    .filter(|level| level_filter.intersects(level))
                {
                    let pdu = self.generate_hello(level, instance);
                    let task = tasks::hello_interval(self, level, pdu);
                    *self.state.tasks.hello_interval_broadcast.get_mut(level) =
                        Some(task);
                }
            }
            // For point-to-point interfaces, send a single Hello PDU,
            // regardless of whether IS-IS is enabled for L1, L2, or both.
            InterfaceType::PointToPoint => {
                let level = LevelType::All;
                let pdu = self.generate_hello(level, instance);
                let task = tasks::hello_interval(self, level, pdu);
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
        for level in self.config.levels().into_iter() {
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

    pub(crate) fn srm_list_add(&mut self, level: LevelNumber, mut lsp: Lsp) {
        if !self.state.active {
            return;
        }

        // Skip adding the LSP if there are no active adjacencies or the LSP's
        // sequence number is zero.
        if self.state.event_counters.adjacency_number == 0 || lsp.seqno == 0 {
            return;
        }

        // ISO 10589 - Section 7.3.16.3:
        // "A system shall decrement the Remaining Lifetime in the PDU being
        // transmitted by at least one".
        lsp.set_rem_lifetime(lsp.rem_lifetime().saturating_sub(1));

        // For point-to-point interfaces, all LSPs require acknowledgment.
        // Retransmissions will occur until an acknowledgment is received.
        if self.config.interface_type == InterfaceType::PointToPoint {
            let rxmt_interval = self.config.lsp_rxmt_interval;
            let dst = self.config.interface_type.multicast_addr(level);
            let task =
                tasks::lsp_rxmt_interval(self, lsp.clone(), dst, rxmt_interval);
            self.state.srm_list.get_mut(level).insert(lsp.lsp_id, task);
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
        let ifindex = self.system.ifindex.unwrap();
        let dst = self.config.interface_type.multicast_addr(level);
        let msg = NetTxPduMsg { pdu, ifindex, dst };
        let _ = self.state.net.as_ref().unwrap().net_tx_pdup.send(msg);
    }

    // Sends a southbound request for interface system information, such as
    // operational status and IP addresses.
    pub(crate) fn query_southbound(&self, ibus_tx: &IbusSender) {
        let _ = ibus_tx.send(IbusMsg::InterfaceQuery {
            ifname: self.name.clone(),
            af: None,
        });
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
    fn new(
        iface: &Interface,
        instance_channels_tx: &InstanceChannelsTx<Instance>,
    ) -> Result<Self, IoError> {
        let broadcast = iface.system.flags.contains(InterfaceFlags::BROADCAST);

        // Create raw socket.
        let socket = network::socket(iface.system.ifindex.unwrap())
            .map_err(IoError::SocketError)?;

        // Join IS-IS multicast groups.
        if broadcast {
            iface.system.join_multicast(&socket, MulticastAddr::AllIss);
            iface
                .system
                .join_multicast(&socket, MulticastAddr::AllL1Iss);
            iface
                .system
                .join_multicast(&socket, MulticastAddr::AllL2Iss);
        }

        // Start network Tx/Rx tasks.
        let socket = AsyncFd::new(socket).map_err(IoError::SocketError)?;
        let socket = Arc::new(socket);
        let (net_tx_pdup, net_tx_pduc) = mpsc::unbounded_channel();
        let mut net_tx_task = tasks::net_tx(
            socket.clone(),
            broadcast,
            net_tx_pduc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let net_rx_task = tasks::net_rx(
            socket.clone(),
            broadcast,
            iface,
            &instance_channels_tx.protocol_input.net_pdu_rx,
        );
        net_tx_task.detach();

        Ok(InterfaceNet {
            socket,
            _net_tx_task: net_tx_task,
            _net_rx_task: net_rx_task,
            net_tx_pdup,
        })
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
