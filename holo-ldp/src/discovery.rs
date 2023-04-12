//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use holo_northbound::paths::control_plane_protocol::mpls_ldp;
use holo_utils::socket::UdpSocket;
use holo_utils::task::{IntervalTask, TimeoutTask};
use holo_utils::Sender;

use crate::collections::{
    AdjacencyId, AdjacencyIndex, InterfaceId, Neighbors, TargetedNbrIndex,
};
use crate::debug::Debug;
use crate::error::IoError;
use crate::instance::{InstanceState, InstanceUp};
use crate::northbound::notification;
use crate::packet::messages::hello::{
    HelloFlags, HelloMsg, TlvCommonHelloParams, TlvConfigSeqNo,
    TlvIpv4TransAddr,
};
use crate::packet::messages::notification::StatusCode;
use crate::packet::Pdu;
use crate::tasks::messages::input::AdjTimeoutMsg;
use crate::{network, tasks};

#[derive(Debug)]
pub struct Adjacency {
    // Adjacency ID (used for inter-task communication).
    pub id: AdjacencyId,
    // Local address of the Hello adjacency.
    pub local_addr: IpAddr,
    // Adjacency source address.
    pub source: AdjacencySource,
    // Adjacency transport address (either implicit or explicit).
    pub trans_addr: IpAddr,
    // Adjacency LSR-ID.
    pub lsr_id: Ipv4Addr,
    // The holdtime value learned from the adjacent LSR (in seconds).
    pub holdtime_adjacent: u16,
    // The holdtime negotiated between this LSR and the adjacent LSR (in
    // seconds).
    pub holdtime_negotiated: u16,
    // Statistics.
    pub hello_rcvd: u64,
    pub hello_dropped: u64,
    pub discontinuity_time: DateTime<Utc>,
    // Adjacency timeout task.
    pub timeout_task: Option<TimeoutTask>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdjacencySource {
    // Optional interface index (None for targeted adjacencies).
    pub iface_id: Option<InterfaceId>,
    // Source IP address.
    pub addr: IpAddr,
}

#[derive(Debug)]
pub struct TargetedNbr {
    // Targeted neighbor LSR-ID address.
    pub addr: IpAddr,
    // Targeted neighbor configuration.
    pub config: TargetedNbrCfg,
    // Indicates whether this targeted neighbor was explicitly configured.
    pub configured: bool,
    // Indicates whether this is a dynamic targeted neighbor.
    pub dynamic: bool,
    // Hello Tx interval task.
    pub hello_interval_task: Option<IntervalTask>,
}

#[derive(Debug)]
pub struct TargetedNbrCfg {
    pub enabled: bool,
    pub hello_holdtime: u16,
    pub hello_interval: u16,
}

// ===== impl Adjacency =====

impl Adjacency {
    pub(crate) fn new(
        id: AdjacencyId,
        source: AdjacencySource,
        local_addr: IpAddr,
        trans_addr: IpAddr,
        lsr_id: Ipv4Addr,
        holdtime_adjacent: u16,
        holdtime_negotiated: u16,
    ) -> Adjacency {
        Debug::AdjacencyCreate(&source, &lsr_id).log();

        Adjacency {
            id,
            local_addr,
            source,
            trans_addr,
            lsr_id,
            holdtime_adjacent,
            holdtime_negotiated,
            hello_rcvd: 1,
            hello_dropped: 0,
            discontinuity_time: Utc::now(),
            timeout_task: None,
        }
    }

    pub(crate) fn reset(
        &mut self,
        holdtime: u16,
        adj_timeoutp: &Sender<AdjTimeoutMsg>,
    ) {
        // Disable the timeout task if the negotiated hold time is 0xffff
        // (infinite).
        if holdtime == HelloMsg::INFINITE_HOLDTIME {
            self.timeout_task = None;
            return;
        }

        let holdtime = Duration::from_secs(holdtime.into());

        if let Some(timeout_task) = &mut self.timeout_task {
            // Reset existing timeout task.
            timeout_task.reset(Some(holdtime));
        } else {
            // Create new timeout task.
            let timeout_task =
                tasks::adj_timeout(self.id, holdtime, adj_timeoutp);
            self.timeout_task = Some(timeout_task);
        }
    }

    pub(crate) fn holdtime_remaining(&self) -> Option<Duration> {
        self.timeout_task.as_ref().map(TimeoutTask::remaining)
    }

    pub(crate) fn next_hello(&self, instance: &InstanceUp) -> Duration {
        match self.source.iface_id {
            Some(iface_id) => {
                let (_, iface) =
                    instance.core.interfaces.get_by_id(iface_id).unwrap();
                iface.next_hello().unwrap()
            }
            None => {
                let (_, tnbr) = instance
                    .core
                    .tneighbors
                    .get_by_addr(&self.source.addr)
                    .unwrap();
                tnbr.next_hello().unwrap()
            }
        }
    }
}

impl Drop for Adjacency {
    fn drop(&mut self) {
        Debug::AdjacencyDelete(&self.source, &self.lsr_id).log();
    }
}

// ===== impl AdjacencySource =====

impl AdjacencySource {
    pub(crate) fn new(
        iface_id: Option<InterfaceId>,
        addr: IpAddr,
    ) -> AdjacencySource {
        AdjacencySource { iface_id, addr }
    }
}

impl std::fmt::Display for AdjacencySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

// ===== impl TargetedNbr =====

impl TargetedNbr {
    const DFLT_ADJ_HOLDTIME: u16 = 45;

    pub(crate) fn new(addr: IpAddr) -> TargetedNbr {
        Debug::TargetedNbrCreate(&addr).log();

        TargetedNbr {
            addr,
            config: TargetedNbrCfg::default(),
            configured: false,
            dynamic: false,
            hello_interval_task: None,
        }
    }

    pub(crate) fn start(&mut self, instance_state: &mut InstanceState) {
        Debug::TargetedNbrStart(&self.addr).log();

        let task = tasks::tnbr_hello_interval(self, instance_state);
        self.hello_interval_task = Some(task);
    }

    pub(crate) fn stop(
        instance: &mut InstanceUp,
        tnbr_idx: TargetedNbrIndex,
        delete_adjacency: bool,
    ) {
        let tnbr = &mut instance.core.tneighbors[tnbr_idx];

        Debug::TargetedNbrStop(&tnbr.addr).log();

        // Stop hello tx.
        tnbr.hello_interval_task = None;

        // Delete adjacency (if any).
        if delete_adjacency {
            let source = AdjacencySource {
                iface_id: None,
                addr: tnbr.addr,
            };
            if let Some((adj_idx, _)) =
                instance.state.ipv4.adjacencies.get_by_source(&source)
            {
                adjacency_delete(instance, adj_idx, StatusCode::Shutdown);
            }
        }
    }

    pub(crate) fn update(
        instance: &mut InstanceUp,
        tnbr_idx: TargetedNbrIndex,
    ) {
        let tnbr = &mut instance.core.tneighbors[tnbr_idx];

        let is_ready = tnbr.is_ready();
        let remove = tnbr.remove_check();

        if !tnbr.is_active() && is_ready {
            tnbr.start(&mut instance.state);
        } else if tnbr.is_active() && !is_ready {
            TargetedNbr::stop(instance, tnbr_idx, true);
        }

        if remove {
            instance.core.tneighbors.delete(tnbr_idx);
        }
    }

    pub(crate) fn sync_hello_tx(&mut self, instance_state: &mut InstanceState) {
        let task = tasks::tnbr_hello_interval(self, instance_state);
        self.hello_interval_task = Some(task);
    }

    pub(crate) fn is_active(&self) -> bool {
        self.hello_interval_task.is_some()
    }

    fn is_ready(&self) -> bool {
        self.dynamic || (self.configured && self.config.enabled)
    }

    pub(crate) fn remove_check(&self) -> bool {
        !self.dynamic && !self.configured
    }

    pub(crate) fn generate_hello(
        &self,
        instance_state: &mut InstanceState,
    ) -> HelloMsg {
        // NOTE: do not attempt GTSM negotiation in multi-hop peering sessions.
        let mut flags = HelloFlags::TARGETED;
        if self.config.enabled {
            flags |= HelloFlags::REQ_TARGETED;
        }

        HelloMsg {
            // The message ID will be overwritten later.
            msg_id: 0,
            params: TlvCommonHelloParams {
                holdtime: self.config.hello_holdtime,
                flags,
            },
            ipv4_addr: Some(TlvIpv4TransAddr(instance_state.ipv4.trans_addr)),
            ipv6_addr: None,
            cfg_seqno: Some(TlvConfigSeqNo(instance_state.cfg_seqno)),
            dual_stack: None,
        }
    }

    pub(crate) async fn send_hello(
        edisc_socket: Arc<UdpSocket>,
        addr: IpAddr,
        router_id: Ipv4Addr,
        msg_id: Arc<AtomicU32>,
        mut hello: HelloMsg,
    ) {
        // Update hello message ID.
        hello.msg_id = InstanceState::get_next_msg_id(&msg_id);
        Debug::AdjacencyHelloTx(&hello).log();

        // Prepare hello PDU.
        let mut pdu = Pdu::new(router_id, 0);
        pdu.messages.push_back(hello.into());

        // Send unicast packet.
        if let Err(error) =
            network::udp::send_packet_unicast(&edisc_socket, pdu, &addr).await
        {
            IoError::UdpSendError(error).log();
        }
    }

    pub(crate) fn calculate_adj_holdtime(
        &self,
        mut hello_holdtime: u16,
    ) -> u16 {
        if hello_holdtime == 0 {
            hello_holdtime = Self::DFLT_ADJ_HOLDTIME;
        }

        std::cmp::min(self.config.hello_holdtime, hello_holdtime)
    }

    pub(crate) fn next_hello(&self) -> Option<Duration> {
        self.hello_interval_task
            .as_ref()
            .map(IntervalTask::remaining)
    }
}

impl Drop for TargetedNbr {
    fn drop(&mut self) {
        Debug::TargetedNbrDelete(&self.addr).log();
    }
}

// ===== impl TargetedNbrCfg =====

impl Default for TargetedNbrCfg {
    fn default() -> TargetedNbrCfg {
        let enabled =
            mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;
        let hello_holdtime =
            mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let hello_interval =
            mpls_ldp::discovery::targeted::hello_interval::DFLT;

        TargetedNbrCfg {
            enabled,
            hello_holdtime,
            hello_interval,
        }
    }
}

// ===== global functions =====

pub(crate) fn adjacency_delete(
    instance: &mut InstanceUp,
    adj_idx: AdjacencyIndex,
    status_code: StatusCode,
) {
    let adjacencies = &mut instance.state.ipv4.adjacencies;
    let adj = &adjacencies[adj_idx];
    let lsr_id = adj.lsr_id;
    let source = adj.source;
    let ifname = source.iface_id.map(|iface_id| {
        let (_, iface) = instance.core.interfaces.get_by_id(iface_id).unwrap();
        iface.name.as_str()
    });

    adjacencies.delete(adj_idx);
    notification::mpls_ldp_hello_adjacency_event(
        &instance.tx.nb,
        &instance.core.name,
        ifname,
        &source.addr,
        false,
    );
    Neighbors::delete_check(instance, &lsr_id, status_code);
}
