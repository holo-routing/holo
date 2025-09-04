//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use chrono::{DateTime, Utc};
use holo_protocol::InstanceChannelsTx;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::keychain::{Key, Keychains};
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use ipnetwork::{Ipv4Network, Ipv6Network};
use ism::{Event, State};
use smallvec::smallvec;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

use crate::area::Area;
use crate::collections::{Arena, InterfaceId, Lsdb, NeighborIndex, Neighbors};
use crate::debug::{Debug, InterfaceInactiveReason};
use crate::error::{Error, InterfaceCfgError, IoError};
use crate::instance::{Instance, InstanceUpView};
use crate::lsdb::{LsaEntry, LsaOriginateEvent};
use crate::neighbor::{Neighbor, NeighborNetId, nsm};
use crate::network::MulticastAddr;
use crate::northbound::configuration::InterfaceCfg;
use crate::northbound::notification;
use crate::packet::Packet;
use crate::packet::auth::AuthMethod;
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::tasks;
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::version::Version;

#[derive(Debug)]
pub struct Interface<V: Version> {
    pub id: InterfaceId,
    pub name: String,
    pub system: InterfaceSys<V>,
    pub config: InterfaceCfg<V>,
    pub state: InterfaceState<V>,
}

#[derive(Debug)]
pub struct InterfaceSys<V: Version> {
    // Interface flags.
    pub flags: InterfaceFlags,
    // Interface ifindex.
    pub ifindex: Option<u32>,
    // Interface MTU.
    pub mtu: Option<u16>,
    // List of addresses associated with this interface.
    pub addr_list: BTreeSet<V::IpNetwork>,
    // OSPFv2: primary address.
    pub primary_addr: Option<Ipv4Network>,
    pub unnumbered: bool,
    // OSPFv3: link-local address.
    pub linklocal_addr: Option<Ipv6Network>,
}

#[derive(Debug)]
pub struct InterfaceState<V: Version> {
    // ISM state.
    pub ism_state: State,
    // Raw socket and Tx/Rx tasks.
    pub net: Option<InterfaceNet<V>>,
    // Source address used when sending packets.
    pub src_addr: Option<V::NetIpAddr>,
    // Joined multicast groups.
    pub mcast_groups: HashSet<MulticastAddr>,
    // The network DR/BDR.
    pub dr: Option<NeighborNetId>,
    pub bdr: Option<NeighborNetId>,
    // List of neighbors attached to this interface.
    pub neighbors: Neighbors<V>,
    // List of LSAs enqueued for transmission.
    pub ls_update_list: BTreeMap<LsaKey<V::LsaType>, Arc<Lsa<V>>>,
    // List of pending delayed Acks.
    pub ls_ack_list: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
    // Statistics.
    pub event_count: u32,
    pub discontinuity_time: DateTime<Utc>,
    // LSDB of interface-scope LSAs.
    pub lsdb: Lsdb<V>,
    pub network_lsa_self: Option<LsaKey<V::LsaType>>,
    // Authentication data.
    pub auth: Option<AuthMethod>,
    // Tasks.
    pub tasks: InterfaceTasks<V>,
}

#[derive(Debug)]
pub struct InterfaceNet<V: Version> {
    // Raw socket.
    pub socket: Arc<AsyncFd<Socket>>,
    // Network Tx/Rx tasks.
    _net_tx_task: Task<()>,
    _net_rx_task: Task<()>,
    // Network Tx output channel.
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg<V>>,
}

#[derive(Debug)]
pub struct InterfaceTasks<V: Version> {
    // ISM Hello Tx interval task.
    pub hello_interval: Option<IntervalTask>,
    // NBMA poll interval tasks.
    pub nbma_poll_interval: HashMap<V::NetIpAddr, IntervalTask>,
    // ISM WaitTimer task.
    pub wait_timer: Option<TimeoutTask>,
    // LS Update timer task.
    pub ls_update_timer: Option<TimeoutTask>,
    // Delayed Ack task.
    pub ls_delayed_ack: Option<TimeoutTask>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceType {
    Broadcast,
    NonBroadcast,
    PointToMultipoint,
    PointToPoint,
}

#[derive(Clone, Copy, Debug)]
struct DrCandidate {
    router_id: Ipv4Addr,
    net_id: NeighborNetId,
    dr: Option<NeighborNetId>,
    bdr: Option<NeighborNetId>,
    priority: u8,
}

// Interface state machine.
pub mod ism {
    use serde::{Deserialize, Serialize};

    use crate::debug::InterfaceInactiveReason;

    #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
    #[derive(Deserialize, Serialize)]
    pub enum State {
        #[default]
        Down,
        Loopback,
        Waiting,
        PointToPoint,
        DrOther,
        Backup,
        Dr,
    }

    #[derive(Debug, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    pub enum Event {
        InterfaceUp,
        WaitTimer,
        BackupSeen,
        NbrChange,
        LoopInd,
        UnloopInd,
        InterfaceDown(InterfaceInactiveReason),
    }
}

// OSPF version-specific code.
pub trait InterfaceVersion<V: Version> {
    // Return whether the interface is ready for OSPF operation.
    fn is_ready(
        af: AddressFamily,
        iface: &Interface<V>,
    ) -> Result<(), InterfaceInactiveReason>;

    // Return the source address used to send OSPF packets.
    fn src_addr(iface_sys: &InterfaceSys<V>) -> V::NetIpAddr;

    // Generate an OSPF Hello message.
    fn generate_hello(
        iface: &Interface<V>,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) -> Packet<V>;

    // Validate the destination of the received packet.
    fn validate_packet_dst(
        iface: &Interface<V>,
        dst: V::NetIpAddr,
    ) -> Result<(), Error<V>>;

    // Validate the source of the received packet.
    fn validate_packet_src(
        iface: &Interface<V>,
        src: V::NetIpAddr,
    ) -> Result<(), Error<V>>;

    // Check if the interface and the received packet have matching Instance IDs
    // (OSPFv3 only).
    fn packet_instance_id_match(
        iface: &Interface<V>,
        packet_hdr: &V::PacketHdr,
    ) -> bool;

    // Validate the received Hello packet.
    fn validate_hello(
        iface: &Interface<V>,
        hello: &V::PacketHello,
    ) -> Result<(), InterfaceCfgError>;

    // Return the maximum packet size that can be sent on this interface.
    fn max_packet_size(iface: &Interface<V>) -> u16;

    // Find neighbor identified by its source address or Router-ID.
    fn get_neighbor<'a>(
        iface: &mut Interface<V>,
        src: &V::NetIpAddr,
        router_id: Ipv4Addr,
        neighbors: &'a mut Arena<Neighbor<V>>,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<V>)>;
}

// ===== impl Interface =====

impl<V> Interface<V>
where
    V: Version,
{
    pub(crate) fn new(id: InterfaceId, name: String) -> Interface<V> {
        Debug::<V>::InterfaceCreate(&name).log();

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
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &mut Arena<Neighbor<V>>,
        lsa_entries: &Arena<LsaEntry<V>>,
    ) {
        // Check next ISM event to invoke, but only if necessary.
        let event = match V::is_ready(instance.state.af, self) {
            Ok(_) => {
                let ism_state = self.state.ism_state;
                if self.system.flags.contains(InterfaceFlags::LOOPBACK) {
                    if ism_state == State::Loopback {
                        return;
                    }
                    Event::LoopInd
                } else if ism_state == State::Loopback {
                    Event::UnloopInd
                } else if ism_state == State::Down {
                    Event::InterfaceUp
                } else {
                    return;
                }
            }
            Err(reason) if !self.is_down() => Event::InterfaceDown(reason),
            _ => return,
        };

        // Invoke ISM event.
        self.fsm(area, instance, neighbors, lsa_entries, event);
    }

    fn start(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &Arena<Neighbor<V>>,
    ) -> State {
        Debug::<V>::InterfaceStart(&self.name).log();

        // Initialize source address.
        self.state.src_addr = Some(V::src_addr(&self.system));

        if !self.is_passive() {
            self.state.auth = self.auth(&instance.shared.keychains);

            // Start network Tx/Rx tasks.
            match InterfaceNet::new(
                self,
                area,
                instance.state.af,
                &instance.state.auth_seqno,
                instance.tx,
            ) {
                Ok(net) => self.state.net = Some(net),
                Err(error) => {
                    let ifname = self.name.clone();
                    Error::<V>::InterfaceStartError(ifname, error).log();
                    return State::Down;
                }
            }

            // Start Hello Tx task.
            self.hello_interval_start(area, instance);
        }

        // Get new ISM state.
        let new_ism_state = match self.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                State::PointToPoint
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                if self.config.priority == 0 {
                    State::DrOther
                } else {
                    State::Waiting
                }
            }
        };

        if new_ism_state == State::Waiting {
            // Start wait timer.
            let task = tasks::ism_wait_timer(self, area, instance);
            self.state.tasks.wait_timer = Some(task);

            if self.config.if_type == InterfaceType::NonBroadcast {
                // Examine the configured list of neighbors for this interface
                // and generate the neighbor event Start for each neighbor that
                // is also eligible to become Designated Router.
                for nbr in self
                    .config
                    .static_nbrs
                    .iter()
                    .filter(|(_, snbr)| snbr.priority != 0)
                    .filter_map(|(addr, _)| {
                        self.state
                            .neighbors
                            .iter(neighbors)
                            .find(|nbr| nbr.src == *addr)
                    })
                {
                    instance.tx.protocol_input.nsm_event(
                        area.id,
                        self.id,
                        nbr.id,
                        nsm::Event::Start,
                    );
                }
            }
        }

        new_ism_state
    }

    // Stop interface if it's active.
    fn stop(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &mut Arena<Neighbor<V>>,
        lsa_entries: &Arena<LsaEntry<V>>,
        reason: InterfaceInactiveReason,
    ) {
        if self.is_down() {
            return;
        }

        Debug::<V>::InterfaceStop(&self.name, reason).log();

        // Kill all neighbors.
        let event = match reason {
            InterfaceInactiveReason::OperationalDown
            | InterfaceInactiveReason::MissingIfindex
            | InterfaceInactiveReason::MissingMtu
            | InterfaceInactiveReason::MissingIpv4Address
            | InterfaceInactiveReason::MissingLinkLocalAddress => {
                nsm::Event::LinkDown
            }
            _ => nsm::Event::Kill,
        };
        for nbr_idx in self.state.neighbors.indexes().collect::<Vec<_>>() {
            let nbr = &mut neighbors[nbr_idx];
            nbr.fsm(self, area, instance, lsa_entries, event);
            self.state.neighbors.delete(neighbors, nbr_idx);
        }

        // Reset interface state.
        self.state.net = None;
        self.state.src_addr = None;
        self.state.mcast_groups = Default::default();
        self.state.dr = None;
        self.state.bdr = None;
        self.state.neighbors = Default::default();
        self.state.ls_update_list = Default::default();
        self.state.ls_ack_list = Default::default();
        // NOTE: the interface LSDB should be preserved.
        self.state.auth = None;
        self.state.tasks = Default::default();
    }

    // Restart the Hello Tx task.
    pub(crate) fn sync_hello_tx(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        if !self.is_passive() && self.state.ism_state >= ism::State::Waiting {
            self.hello_interval_start(area, instance);
        }
    }

    pub(crate) fn reset(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &mut Arena<Neighbor<V>>,
        lsa_entries: &Arena<LsaEntry<V>>,
    ) {
        for event in [
            ism::Event::InterfaceDown(InterfaceInactiveReason::Resetting),
            ism::Event::InterfaceUp,
        ] {
            self.fsm(area, instance, neighbors, lsa_entries, event);
        }
    }

    pub(crate) fn is_down(&self) -> bool {
        self.state.ism_state == State::Down
    }

    pub(crate) fn is_passive(&self) -> bool {
        self.system.flags.contains(InterfaceFlags::LOOPBACK)
            || self.config.passive
    }

    pub(crate) fn is_dr_or_backup(&self) -> bool {
        matches!(self.state.ism_state, State::Dr | State::Backup)
    }

    pub(crate) fn is_broadcast_or_nbma(&self) -> bool {
        matches!(
            self.config.if_type,
            InterfaceType::Broadcast | InterfaceType::NonBroadcast
        )
    }

    fn auth(&self, keychains: &Keychains) -> Option<AuthMethod> {
        if let (Some(key), Some(key_id), Some(algo)) = (
            &self.config.auth_key,
            self.config.auth_keyid,
            self.config.auth_algo,
        ) {
            let auth_key =
                Key::new(key_id as u64, algo, key.as_bytes().to_vec());
            return Some(AuthMethod::ManualKey(auth_key));
        }

        if let Some(keychain) = &self.config.auth_keychain
            && let Some(keychain) = keychains.get(keychain)
        {
            return Some(AuthMethod::Keychain(keychain.clone()));
        }

        None
    }

    pub(crate) fn auth_update(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        // Update authentication data.
        self.state.auth = self.auth(&instance.shared.keychains);

        if let Some(mut net) = self.state.net.take() {
            // Enable or disable checksum offloading.
            let cksum_enable = self.state.auth.is_none();
            if let Err(error) =
                V::set_cksum_offloading(net.socket.get_ref(), cksum_enable)
            {
                IoError::ChecksumOffloadError(cksum_enable, error).log();
            }

            // Restart network Tx/Rx tasks.
            net.restart_tasks(
                self,
                area,
                instance.state.af,
                &instance.state.auth_seqno,
                instance.tx,
            );
            self.state.net = Some(net);
            self.sync_hello_tx(area, instance);
        }
    }

    pub(crate) fn fsm(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &mut Arena<Neighbor<V>>,
        lsa_entries: &Arena<LsaEntry<V>>,
        event: Event,
    ) {
        Debug::<V>::IsmEvent(&self.name, &self.state.ism_state, &event).log();

        let new_ism_state = match (self.state.ism_state, &event) {
            (State::Down, Event::InterfaceUp) => {
                // Start interface.
                self.start(area, instance, neighbors)
            }
            (State::Waiting, Event::NbrChange) => {
                // This is an unspecified event but it can happen during normal
                // operation, so ignore it gracefully instead of logging an
                // error.
                return;
            }
            (State::Waiting, Event::BackupSeen | Event::WaitTimer) => {
                self.state.tasks.wait_timer = None;

                // Run DR election.
                self.dr_election(area, instance, neighbors)
            }
            (State::DrOther | State::Backup | State::Dr, Event::NbrChange) => {
                // Run DR election.
                self.dr_election(area, instance, neighbors)
            }
            (_, Event::InterfaceDown(reason)) => {
                // Stop interface.
                self.stop(area, instance, neighbors, lsa_entries, *reason);
                State::Down
            }
            (_, Event::LoopInd) => {
                // Stop interface.
                self.stop(
                    area,
                    instance,
                    neighbors,
                    lsa_entries,
                    InterfaceInactiveReason::LoopedBack,
                );
                State::Loopback
            }
            (State::Loopback, Event::UnloopInd) => {
                // No actions are necessary.
                State::Down
            }
            _ => {
                Error::<V>::IsmUnexpectedEvent(self.state.ism_state, event)
                    .log();
                return;
            }
        };

        // Check for FSM state change.
        if new_ism_state != self.state.ism_state {
            self.fsm_state_change(area, instance, new_ism_state);
        }
    }

    fn fsm_state_change(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        new_ism_state: State,
    ) {
        // (Re)originate LSAs that might have been affected.
        instance.tx.protocol_input.lsa_orig_event(
            LsaOriginateEvent::InterfaceStateChange {
                area_id: area.id,
                iface_id: self.id,
            },
        );
        if self.state.ism_state == ism::State::Dr {
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::InterfaceDrChange {
                    area_id: area.id,
                    iface_id: self.id,
                },
            );
        }

        // Effectively transition to the new FSM state.
        Debug::<V>::IsmTransition(
            &self.name,
            &self.state.ism_state,
            &new_ism_state,
        )
        .log();
        self.state.ism_state = new_ism_state;
        notification::if_state_change(instance, self);

        // Join or leave OSPF multicast groups as necessary.
        self.update_mcast_groups();

        // Update statistics.
        self.state.event_count += 1;
        self.state.discontinuity_time = Utc::now();
    }

    pub(crate) fn hello_interval_start(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
    ) {
        let dst = match self.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::Broadcast => {
                smallvec![*V::multicast_addr(MulticastAddr::AllSpfRtrs)]
            }
            InterfaceType::NonBroadcast | InterfaceType::PointToMultipoint => {
                self.config.static_nbrs.keys().copied().collect()
            }
        };
        let interval = self.config.hello_interval;
        let task = tasks::hello_interval(self, area, instance, dst, interval);
        self.state.tasks.hello_interval = Some(task);
    }

    pub(crate) fn nbma_poll_interval_start(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        addr: V::NetIpAddr,
        poll_interval: u16,
    ) {
        let dst = smallvec![addr];
        let task =
            tasks::hello_interval(self, area, instance, dst, poll_interval);
        self.state.tasks.nbma_poll_interval.insert(addr, task);
    }

    pub(crate) fn nbma_poll_interval_stop(&mut self, addr: V::NetIpAddr) {
        self.state.tasks.nbma_poll_interval.remove(&addr);
    }

    fn update_mcast_groups(&mut self) {
        let socket = match &self.state.net {
            Some(net) => net.socket.get_ref(),
            None => return,
        };

        // AllSPFRouters.
        if self.state.ism_state >= State::Waiting
            && !self.state.mcast_groups.contains(&MulticastAddr::AllSpfRtrs)
        {
            self.system
                .join_multicast(socket, MulticastAddr::AllSpfRtrs);
            self.state.mcast_groups.insert(MulticastAddr::AllSpfRtrs);
        } else if self.state.ism_state < State::Waiting
            && self.state.mcast_groups.contains(&MulticastAddr::AllSpfRtrs)
        {
            self.system
                .leave_multicast(socket, MulticastAddr::AllSpfRtrs);
            self.state.mcast_groups.remove(&MulticastAddr::AllSpfRtrs);
        }

        // AllDRouters.
        if self.is_dr_or_backup()
            && !self.state.mcast_groups.contains(&MulticastAddr::AllDrRtrs)
        {
            self.system.join_multicast(socket, MulticastAddr::AllDrRtrs);
            self.state.mcast_groups.insert(MulticastAddr::AllDrRtrs);
        } else if !self.is_dr_or_backup()
            && self.state.mcast_groups.contains(&MulticastAddr::AllDrRtrs)
        {
            self.system
                .leave_multicast(socket, MulticastAddr::AllDrRtrs);
            self.state.mcast_groups.remove(&MulticastAddr::AllDrRtrs);
        }
    }

    fn dr_election(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        neighbors: &Arena<Neighbor<V>>,
    ) -> State {
        let router_id = instance.state.router_id;
        let net_id = V::network_id(&self.state.src_addr.unwrap(), router_id);

        // Step 1: note the current values for the network's Designated Router
        // and Backup Designated Router.
        let old_dr = self.state.dr;
        let old_bdr = self.state.bdr;

        // Step 2: calculate the new Backup Designated Router.
        let calc_bdr = |iface: &Interface<V>| {
            iface
                .dr_eligible_routers(router_id, net_id, neighbors)
                .filter(|rtr| rtr.dr != Some(rtr.net_id))
                .filter(|rtr| rtr.bdr == Some(rtr.net_id))
                .max_by_key(|rtr| (rtr.priority, rtr.router_id))
                .or_else(|| {
                    iface
                        .dr_eligible_routers(router_id, net_id, neighbors)
                        .filter(|rtr| rtr.dr != Some(rtr.net_id))
                        .max_by_key(|rtr| (rtr.priority, rtr.router_id))
                })
                .map(|rtr| rtr.net_id)
        };
        let mut new_bdr = calc_bdr(self);

        // Step 3: calculate the new Designated Router.
        let calc_dr =
            |iface: &Interface<V>, new_bdr: &mut Option<NeighborNetId>| {
                iface
                    .dr_eligible_routers(router_id, net_id, neighbors)
                    .filter(|rtr| rtr.dr == Some(rtr.net_id))
                    .max_by_key(|rtr| (rtr.priority, rtr.router_id))
                    .map(|rtr| rtr.net_id)
                    .or(*new_bdr)
            };
        let mut new_dr = calc_dr(self, &mut new_bdr);
        self.state.dr = new_dr;
        self.state.bdr = new_bdr;

        // Step 4: check if the router is the new DR/BDR or no longer the
        // DR/BDR.
        if (new_dr == Some(net_id) || old_dr == Some(net_id))
            && new_dr != old_dr
            || (new_bdr == Some(net_id) || old_bdr == Some(net_id))
                && new_bdr != old_bdr
        {
            // Repeat steps 2 and 3.
            new_bdr = calc_bdr(self);
            new_dr = calc_dr(self, &mut new_bdr);
            self.state.dr = new_dr;
            self.state.bdr = new_bdr;
        }

        // Step 5: set the interface state accordingly.
        Debug::<V>::IsmDrElection(&self.name, old_dr, new_dr, old_bdr, new_bdr)
            .log();
        let next_state = if new_dr == Some(net_id) {
            ism::State::Dr
        } else if new_bdr == Some(net_id) {
            ism::State::Backup
        } else {
            ism::State::DrOther
        };

        // Step 6: if the attached network is an NBMA network, and the router
        // itself has just become either DR or BDR, it must start sending Hello
        // Packets to those neighbors that are not eligible to become DR. This
        // is done by invoking the neighbor event Start for each neighbor having
        // a Router Priority of 0.
        if self.config.if_type == InterfaceType::NonBroadcast
            && matches!(next_state, ism::State::Dr | ism::State::Backup)
        {
            for nbr in self
                .config
                .static_nbrs
                .iter()
                .filter(|(_, snbr)| snbr.priority == 0)
                .filter_map(|(addr, _)| {
                    self.state
                        .neighbors
                        .iter(neighbors)
                        .find(|nbr| nbr.src == *addr)
                })
            {
                instance.tx.protocol_input.nsm_event(
                    area.id,
                    self.id,
                    nbr.id,
                    nsm::Event::Start,
                );
            }
        }

        // Step 7: if the DR or BDR changes, invoke the AdjOk? event on all
        // neighbors whose state is at least 2-Way.
        if new_dr != old_dr || new_bdr != old_bdr {
            for nbr in self
                .state
                .neighbors
                .iter(neighbors)
                .filter(|nbr| nbr.state >= nsm::State::TwoWay)
            {
                instance.tx.protocol_input.nsm_event(
                    area.id,
                    self.id,
                    nbr.id,
                    nsm::Event::AdjOk,
                );
            }

            // Synchronize interface's Hello Tx task (updated DR and/or BDR).
            self.sync_hello_tx(area, instance);
        }

        // If the DR changed, reoriginate LSAs that might have been affected.
        if new_dr != old_dr {
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::InterfaceDrChange {
                    area_id: area.id,
                    iface_id: self.id,
                },
            );
        }

        next_state
    }

    fn dr_eligible_routers<'a>(
        &'a self,
        router_id: Ipv4Addr,
        net_id: NeighborNetId,
        neighbors: &'a Arena<Neighbor<V>>,
    ) -> impl Iterator<Item = DrCandidate> + 'a {
        let myself = (self.config.priority != 0).then_some(DrCandidate {
            router_id,
            net_id,
            dr: self.state.dr,
            bdr: self.state.bdr,
            priority: self.config.priority,
        });

        let nbrs = self
            .state
            .neighbors
            .iter(neighbors)
            .filter(|nbr| nbr.state >= nsm::State::TwoWay)
            .filter(|nbr| nbr.priority != 0)
            .map(|nbr| DrCandidate {
                router_id: nbr.router_id,
                net_id: nbr.network_id(),
                dr: nbr.dr,
                bdr: nbr.bdr,
                priority: nbr.priority,
            });

        myself.into_iter().chain(nbrs)
    }

    pub(crate) fn need_adjacency(&self, nbr: &Neighbor<V>) -> bool {
        match self.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                true
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                let nbr_net_id = nbr.network_id();
                self.state.ism_state == State::Dr
                    || self.state.ism_state == State::Backup
                    || self.state.dr == Some(nbr_net_id)
                    || self.state.bdr == Some(nbr_net_id)
            }
        }
    }

    pub(crate) fn enqueue_ls_update(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        lsa_key: LsaKey<V::LsaType>,
        lsa: Arc<Lsa<V>>,
    ) {
        self.state.ls_update_list.insert(lsa_key, lsa);

        // Start LS Update timeout if necessary.
        if self.state.tasks.ls_update_timer.is_none() {
            let task = tasks::ls_update_timer(self, area, instance);
            self.state.tasks.ls_update_timer = Some(task);
        }
    }

    pub(crate) fn enqueue_delayed_ack(
        &mut self,
        area: &Area<V>,
        instance: &InstanceUpView<'_, V>,
        lsa_hdr: &V::LsaHdr,
    ) {
        self.state.ls_ack_list.insert(lsa_hdr.key(), *lsa_hdr);

        // Start delayed LS Ack timeout if necessary.
        if self.state.tasks.ls_delayed_ack.is_none() {
            let task = tasks::delayed_ack_timer(self, area, instance);
            self.state.tasks.ls_delayed_ack = Some(task);
        }
    }

    pub(crate) fn send_packet(&self, msg: NetTxPacketMsg<V>) {
        let _ = self.state.net.as_ref().unwrap().net_tx_packetp.send(msg);
    }
}

impl<V> Drop for Interface<V>
where
    V: Version,
{
    fn drop(&mut self) {
        Debug::<V>::InterfaceDelete(&self.name).log();
    }
}

// ===== impl InterfaceSys =====

impl<V> InterfaceSys<V>
where
    V: Version,
{
    // Check if the interface shares a subnet with the given IP address.
    pub(crate) fn contains_addr(&self, addr: &V::IpAddr) -> bool {
        for local in &self.addr_list {
            if local.contains(*addr) {
                return true;
            }
        }

        false
    }

    fn join_multicast(&self, socket: &Socket, addr: MulticastAddr) {
        if let Err(error) =
            V::join_multicast(socket, addr, self.ifindex.unwrap())
        {
            IoError::MulticastJoinError(addr, error).log();
        }
    }

    fn leave_multicast(&self, socket: &Socket, addr: MulticastAddr) {
        if let Err(error) =
            V::leave_multicast(socket, addr, self.ifindex.unwrap())
        {
            IoError::MulticastJoinError(addr, error).log();
        }
    }
}

impl<V> Default for InterfaceSys<V>
where
    V: Version,
{
    fn default() -> InterfaceSys<V> {
        InterfaceSys {
            flags: Default::default(),
            ifindex: None,
            mtu: None,
            addr_list: Default::default(),
            primary_addr: None,
            unnumbered: false,
            linklocal_addr: None,
        }
    }
}

// ===== impl InterfaceState =====

impl<V> Default for InterfaceState<V>
where
    V: Version,
{
    fn default() -> InterfaceState<V> {
        InterfaceState {
            ism_state: Default::default(),
            net: None,
            src_addr: None,
            mcast_groups: Default::default(),
            dr: None,
            bdr: None,
            neighbors: Default::default(),
            ls_update_list: Default::default(),
            ls_ack_list: Default::default(),
            event_count: 0,
            discontinuity_time: Utc::now(),
            lsdb: Default::default(),
            network_lsa_self: None,
            auth: None,
            tasks: Default::default(),
        }
    }
}

// ===== impl InterfaceNet =====

impl<V> InterfaceNet<V>
where
    V: Version,
{
    fn new(
        iface: &Interface<V>,
        area: &Area<V>,
        af: AddressFamily,
        auth_seqno: &Arc<AtomicU64>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) -> Result<Self, IoError> {
        // Create raw socket.
        let socket = V::socket(&iface.name)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        // Enable or disable checksum offloading.
        let cksum_enable = iface.state.auth.is_none();
        V::set_cksum_offloading(socket.get_ref(), cksum_enable).map_err(
            |error| IoError::ChecksumOffloadError(cksum_enable, error),
        )?;

        // Start network Tx/Rx tasks.
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let mut net_tx_task = tasks::net_tx(
            socket.clone(),
            iface,
            auth_seqno,
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let net_rx_task = tasks::net_rx(
            socket.clone(),
            iface,
            area,
            af,
            &instance_channels_tx.protocol_input.net_packet_rx,
        );

        // The network Tx task needs to be detached to ensure flushed
        // self-originated LSAs will be sent once the instance terminates.
        net_tx_task.detach();

        Ok(InterfaceNet {
            socket,
            _net_tx_task: net_tx_task,
            _net_rx_task: net_rx_task,
            net_tx_packetp,
        })
    }

    fn restart_tasks(
        &mut self,
        iface: &Interface<V>,
        area: &Area<V>,
        af: AddressFamily,
        auth_seqno: &Arc<AtomicU64>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) {
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        self._net_tx_task = tasks::net_tx(
            self.socket.clone(),
            iface,
            auth_seqno,
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        self._net_rx_task = tasks::net_rx(
            self.socket.clone(),
            iface,
            area,
            af,
            &instance_channels_tx.protocol_input.net_packet_rx,
        );
        // The network Tx task needs to be detached to ensure flushed
        // self-originated LSAs will be sent once the instance terminates.
        self._net_tx_task.detach();
        self.net_tx_packetp = net_tx_packetp;
    }
}

// ===== impl InterfaceTasks =====

impl<V> Default for InterfaceTasks<V>
where
    V: Version,
{
    fn default() -> InterfaceTasks<V> {
        InterfaceTasks {
            hello_interval: Default::default(),
            nbma_poll_interval: Default::default(),
            wait_timer: Default::default(),
            ls_update_timer: Default::default(),
            ls_delayed_ack: Default::default(),
        }
    }
}

// ===== global functions =====

// Helper for the `is_ready` method containing code common to both OSPF
// versions.
pub(crate) fn is_ready_common<V>(
    iface: &Interface<V>,
) -> Result<(), InterfaceInactiveReason>
where
    V: Version,
{
    if !iface.config.enabled {
        return Err(InterfaceInactiveReason::AdminDown);
    }

    if !iface.system.flags.contains(InterfaceFlags::OPERATIVE) {
        return Err(InterfaceInactiveReason::OperationalDown);
    }

    if iface.system.ifindex.is_none() {
        return Err(InterfaceInactiveReason::MissingIfindex);
    }

    if iface.system.mtu.is_none() {
        return Err(InterfaceInactiveReason::MissingMtu);
    }

    Ok(())
}

pub(crate) fn validate_packet_dst_common<V>(
    iface: &Interface<V>,
    dst: V::NetIpAddr,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Check if the destination matches AllSPFRouters.
    if dst == *V::multicast_addr(MulticastAddr::AllSpfRtrs) {
        return Ok(());
    }

    // Packets whose IP destination is AllDRouters should only be accepted
    // if the state of the receiving interface is DR or Backup.
    if dst == *V::multicast_addr(MulticastAddr::AllDrRtrs)
        && iface.is_dr_or_backup()
    {
        return Ok(());
    }

    Err(Error::InvalidDstAddr(dst))
}

pub(crate) fn validate_packet_src_common<V>(
    _iface: &Interface<V>,
    src: V::NetIpAddr,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if !src.is_usable() {
        return Err(Error::InvalidSrcAddr(src));
    }

    Ok(())
}
