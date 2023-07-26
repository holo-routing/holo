//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{self, AtomicU32};
use std::sync::Arc;

use async_trait::async_trait;
use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::mpls_ldp;
use holo_protocol::{InstanceChannelsTx, MessageReceiver, ProtocolInstance};
use holo_southbound::rx::SouthboundRx;
use holo_southbound::tx::SouthboundTx;
use holo_utils::ibus::IbusMsg;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{TcpListener, UdpSocket};
use holo_utils::task::Task;
use holo_utils::{Database, Receiver, Sender};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use tokio::sync::mpsc;

use crate::collections::{Adjacencies, Interfaces, Neighbors, TargetedNbrs};
use crate::debug::{Debug, InstanceInactiveReason, InterfaceInactiveReason};
use crate::discovery::TargetedNbr;
use crate::error::{Error, IoError};
use crate::fec::Fec;
use crate::interface::Interface;
use crate::neighbor::NeighborCfg;
use crate::network::{tcp, udp};
use crate::southbound::rx::InstanceSouthboundRx;
use crate::southbound::tx::InstanceSouthboundTx;
use crate::tasks::messages::input::{
    AdjTimeoutMsg, NbrBackoffTimeoutMsg, NbrKaTimeoutMsg, NbrRxPduMsg,
    TcpAcceptMsg, TcpConnectMsg, UdpRxPduMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, tasks};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, EnumAsInner)]
pub enum Instance {
    Up(InstanceUp),
    Down(InstanceDown),
    // This state is required to allow in-place mutations of Instance.
    Transitioning,
}

pub type InstanceUp = InstanceCommon<InstanceState>;
pub type InstanceDown = InstanceCommon<InstanceStateDown>;

#[derive(Debug)]
pub struct InstanceCommon<State> {
    // Instance state-independent data.
    pub core: InstanceCore,
    // Instance state-dependent data.
    pub state: State,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
}

#[derive(Debug)]
pub struct InstanceCore {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance interfaces.
    pub interfaces: Interfaces,
    // Instance targeted neighbors (configured or learned).
    pub tneighbors: TargetedNbrs,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    pub router_id: Option<Ipv4Addr>,
    pub ipv4_addr_list: BTreeSet<Ipv4Network>,
    pub ipv6_addr_list: BTreeSet<Ipv6Network>,
}

#[derive(Debug)]
pub struct InstanceCfg {
    pub router_id: Option<Ipv4Addr>,
    pub session_ka_holdtime: u16,
    pub session_ka_interval: u16,
    pub password: Option<String>,
    pub interface_hello_holdtime: u16,
    pub interface_hello_interval: u16,
    pub targeted_hello_holdtime: u16,
    pub targeted_hello_interval: u16,
    pub targeted_hello_accept: bool,
    pub ipv4: Option<InstanceIpv4Cfg>,
    pub neighbors: HashMap<Ipv4Addr, NeighborCfg>,
}

#[derive(Debug)]
pub struct InstanceIpv4Cfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InstanceState {
    // Global message ID.
    pub msg_id: Arc<AtomicU32>,
    // Global configuration sequence number.
    pub cfg_seqno: u32,
    // Router-ID in use (static or dynamic).
    pub router_id: Ipv4Addr,
    // List of neighbors.
    pub neighbors: Neighbors,
    // Known FECs and their associated label mappings.
    pub fecs: BTreeMap<IpNetwork, Fec>,
    // Next available FEC label (to be replaced by a Label Manager in the
    // future).
    pub next_fec_label: u32,
    // IPv4 instance state.
    pub ipv4: InstanceIpv4State,
}

#[derive(Debug, new)]
pub struct InstanceIpv4State {
    // UDP discovery socket.
    pub disc_socket: Arc<UdpSocket>,
    // UDP extended discovery socket.
    pub edisc_socket: Arc<UdpSocket>,
    // TCP listening socket.
    pub session_socket: Arc<TcpListener>,
    // UDP discovery Rx task.
    _disc_rx_task: Task<()>,
    // UDP extended discovery Rx task.
    _edisc_rx_task: Task<()>,
    // TCP listener task.
    _tcp_listener_task: Task<()>,
    // IPv4 transport address.
    pub trans_addr: Ipv4Addr,
    // Discovery adjacencies,
    #[new(default)]
    pub adjacencies: Adjacencies,
}

#[derive(Debug)]
pub struct InstanceStateDown();

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // UDP Rx event.
    pub udp_pdu_rx: Sender<UdpRxPduMsg>,
    // Adjacency timeout event.
    pub adj_timeout: Sender<AdjTimeoutMsg>,
    // TCP accept event.
    pub tcp_accept: Sender<TcpAcceptMsg>,
    // TCP connect event.
    pub tcp_connect: Sender<TcpConnectMsg>,
    // TCP neighbor message.
    pub nbr_pdu_rx: Sender<NbrRxPduMsg>,
    // Neighbor keepalive timeout event.
    pub nbr_ka_timeout: Sender<NbrKaTimeoutMsg>,
    // Neighbor backoff timeout event.
    pub nbr_backoff_timeout: Sender<NbrBackoffTimeoutMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // UDP Rx event.
    pub udp_pdu_rx: Receiver<UdpRxPduMsg>,
    // Adjacency timeout event.
    pub adj_timeout: Receiver<AdjTimeoutMsg>,
    // TCP accept event.
    pub tcp_accept: Receiver<TcpAcceptMsg>,
    // TCP connect event.
    pub tcp_connect: Receiver<TcpConnectMsg>,
    // TCP neighbor message.
    pub nbr_pdu_rx: Receiver<NbrRxPduMsg>,
    // Neighbor keepalive timeout event.
    pub nbr_ka_timeout: Receiver<NbrKaTimeoutMsg>,
    // Neighbor backoff timeout event.
    pub nbr_backoff_timeout: Receiver<NbrBackoffTimeoutMsg>,
}

// ===== impl Instance =====

impl Instance {
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    //
    // NOTE: Router-ID updates are ignored if the instance is already active.
    pub(crate) async fn update(&mut self) {
        let router_id = self.get_router_id();

        match self.is_ready(router_id) {
            Ok(()) if !self.is_active() => {
                self.try_start(router_id.unwrap()).await;
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    async fn try_start(&mut self, router_id: Ipv4Addr) {
        let trans_addr = router_id;
        let proto_input_tx = &self.as_down().unwrap().tx.protocol_input;

        match InstanceState::new(router_id, trans_addr, proto_input_tx).await {
            Ok(state) => {
                let instance = std::mem::replace(self, Instance::Transitioning)
                    .into_down()
                    .unwrap();
                *self = Instance::Up(instance.start(state));
            }
            Err(error) => {
                Error::InstanceStartError(Box::new(error)).log();
            }
        }
    }

    fn stop(&mut self, reason: InstanceInactiveReason) {
        if !self.is_active() {
            return;
        }

        let instance = std::mem::replace(self, Instance::Transitioning)
            .into_up()
            .unwrap();
        *self = Instance::Down(instance.stop(reason));
    }

    fn is_active(&self) -> bool {
        matches!(self, Instance::Up(_))
    }

    // Returns whether the instance is ready for LDP operation.
    fn is_ready(
        &self,
        router_id: Option<Ipv4Addr>,
    ) -> Result<(), InstanceInactiveReason> {
        if self.core().config.ipv4.is_none()
            || !self.core().config.ipv4.as_ref().unwrap().enabled
        {
            return Err(InstanceInactiveReason::AdminDown);
        }

        if router_id.is_none() {
            return Err(InstanceInactiveReason::MissingRouterId);
        }

        Ok(())
    }

    fn get_router_id(&self) -> Option<Ipv4Addr> {
        if self.core().config.router_id.is_some() {
            self.core().config.router_id
        } else if self.core().system.router_id.is_some() {
            self.core().system.router_id
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn core(&self) -> &InstanceCore {
        match self {
            Instance::Up(instance) => &instance.core,
            Instance::Down(instance) => &instance.core,
            Instance::Transitioning => unreachable!(),
        }
    }

    #[inline]
    pub(crate) fn core_mut(&mut self) -> &mut InstanceCore {
        match self {
            Instance::Up(instance) => &mut instance.core,
            Instance::Down(instance) => &mut instance.core,
            Instance::Transitioning => unreachable!(),
        }
    }
}

#[async_trait]
impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::LDP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;
    type SouthboundTx = InstanceSouthboundTx;
    type SouthboundRx = InstanceSouthboundRx;

    async fn new(
        name: String,
        _db: Option<Database>,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Debug::InstanceCreate.log();

        Instance::Down(InstanceDown {
            core: InstanceCore {
                name,
                system: Default::default(),
                config: Default::default(),
                interfaces: Default::default(),
                tneighbors: Default::default(),
            },
            state: InstanceStateDown(),
            tx,
        })
    }

    async fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
        Debug::InstanceDelete.log();
    }

    fn process_ibus_msg(&mut self, _msg: IbusMsg) {}

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        // Ignore event if the instance isn't active.
        if let Instance::Up(instance) = self {
            if let Err(error) = instance.process_protocol_msg(msg) {
                error.log();
            }
        }
    }

    fn southbound_start(
        sb_tx: SouthboundTx,
        sb_rx: SouthboundRx,
    ) -> (Self::SouthboundTx, Self::SouthboundRx) {
        let sb_tx = InstanceSouthboundTx::new(sb_tx);
        let sb_rx = InstanceSouthboundRx::new(sb_rx);
        sb_tx.initial_requests();
        (sb_tx, sb_rx)
    }

    fn protocol_input_channels(
    ) -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (udp_pdu_rxp, udp_pdu_rxc) = mpsc::channel(4);
        let (adj_timeoutp, adj_timeoutc) = mpsc::channel(4);
        let (tcp_acceptp, tcp_acceptc) = mpsc::channel(4);
        let (tcp_connectp, tcp_connectc) = mpsc::channel(4);
        let (nbr_pdu_rxp, nbr_pdu_rxc) = mpsc::channel(4);
        let (nbr_ka_timeoutp, nbr_ka_timeoutc) = mpsc::channel(4);
        let (nbr_backoff_timeoutp, nbr_backoff_timeoutc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            udp_pdu_rx: udp_pdu_rxp,
            adj_timeout: adj_timeoutp,
            tcp_accept: tcp_acceptp,
            tcp_connect: tcp_connectp,
            nbr_pdu_rx: nbr_pdu_rxp,
            nbr_ka_timeout: nbr_ka_timeoutp,
            nbr_backoff_timeout: nbr_backoff_timeoutp,
        };
        let rx = ProtocolInputChannelsRx {
            udp_pdu_rx: udp_pdu_rxc,
            adj_timeout: adj_timeoutc,
            tcp_accept: tcp_acceptc,
            tcp_connect: tcp_connectc,
            nbr_pdu_rx: nbr_pdu_rxc,
            nbr_ka_timeout: nbr_ka_timeoutc,
            nbr_backoff_timeout: nbr_backoff_timeoutc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl InstanceCommon =====

// Active LDP instance.
impl InstanceCommon<InstanceState> {
    fn process_protocol_msg(
        &mut self,
        msg: ProtocolInputMsg,
    ) -> Result<(), Error> {
        match msg {
            // Received UDP discovery PDU.
            ProtocolInputMsg::UdpRxPdu(msg) => {
                events::process_udp_pdu(
                    self,
                    msg.src_addr,
                    msg.pdu,
                    msg.multicast,
                );
            }
            // Adjacency's timeout has expired.
            ProtocolInputMsg::AdjTimeout(msg) => {
                events::process_adj_timeout(self, msg.adj_id)?;
            }
            // Accepted TCP connection request.
            ProtocolInputMsg::TcpAccept(mut msg) => {
                events::process_tcp_accept(self, msg.stream(), msg.conn_info);
            }
            // Established TCP connection.
            ProtocolInputMsg::TcpConnect(mut msg) => {
                events::process_tcp_connect(
                    self,
                    msg.nbr_id,
                    msg.stream(),
                    msg.conn_info,
                )?;
            }
            // Received PDU from neighbor.
            ProtocolInputMsg::NbrRxPdu(msg) => {
                events::process_nbr_pdu(self, msg.nbr_id, msg.pdu)?;
            }
            // Neighbor's keepalive timeout has expired.
            ProtocolInputMsg::NbrKaTimeout(msg) => {
                events::process_nbr_ka_timeout(self, msg.nbr_id)?;
            }
            // Neighbor's backoff timeout has expired.
            ProtocolInputMsg::NbrBackoffTimeout(msg) => {
                events::process_nbr_backoff_timeout(self, msg.lsr_id);
            }
        }

        Ok(())
    }

    pub(crate) fn sync_hello_tx(&mut self) {
        // Synchronize interfaces.
        for iface in self
            .core
            .interfaces
            .iter_mut()
            .filter(|iface| iface.is_active())
        {
            iface.sync_hello_tx(&self.state);
        }

        // Synchronize targeted neighbors.
        for tnbr in self
            .core
            .tneighbors
            .iter_mut()
            .filter(|tnbr| tnbr.is_active())
        {
            tnbr.sync_hello_tx(&self.state);
        }
    }

    fn stop(
        mut self,
        reason: InstanceInactiveReason,
    ) -> InstanceCommon<InstanceStateDown> {
        Debug::InstanceStop(reason).log();

        // Stop interfaces.
        for iface_idx in self.core.interfaces.indexes().collect::<Vec<_>>() {
            let iface = &self.core.interfaces[iface_idx];
            if iface.is_active() {
                let reason = InterfaceInactiveReason::InstanceDown;
                Interface::stop(&mut self, iface_idx, reason);
            }
        }

        // Stop targeted neighbors.
        for tnbr_idx in self.core.tneighbors.indexes().collect::<Vec<_>>() {
            let tnbr = &self.core.tneighbors[tnbr_idx];
            if tnbr.is_active() {
                TargetedNbr::stop(&mut self, tnbr_idx, true);
            }
        }

        InstanceCommon::<InstanceStateDown> {
            core: self.core,
            state: InstanceStateDown(),
            tx: self.tx,
        }
    }
}

// Inactive LDP instance.
impl InstanceCommon<InstanceStateDown> {
    fn start(self, state: InstanceState) -> InstanceCommon<InstanceState> {
        Debug::InstanceStart.log();

        let mut instance = InstanceCommon::<InstanceState> {
            core: self.core,
            state,
            tx: self.tx,
        };

        // Try to start interfaces.
        for iface_idx in instance.core.interfaces.indexes().collect::<Vec<_>>()
        {
            Interface::update(&mut instance, iface_idx);
        }

        // Try to start targeted neighbors.
        for tnbr_idx in instance.core.tneighbors.indexes().collect::<Vec<_>>() {
            TargetedNbr::update(&mut instance, tnbr_idx);
        }

        // Request southbound route information.
        instance.tx.sb.request_route_info();

        instance
    }
}

// ===== impl InstanceCfg =====

impl InstanceCfg {
    // Retrieves the password for a specific neighbor identified by its LSR-ID.
    // If a custom password isn't configured for the neighbor, it's inherited
    // from the global configuration.
    pub(crate) fn get_neighbor_password(
        &self,
        lsr_id: Ipv4Addr,
    ) -> Option<&str> {
        if let Some(nbr_cfg) = self.neighbors.get(&lsr_id) {
            if nbr_cfg.password.is_some() {
                return nbr_cfg.password.as_deref();
            }
        }

        self.password.as_deref()
    }
}

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let session_ka_holdtime = mpls_ldp::peers::session_ka_holdtime::DFLT;
        let session_ka_interval = mpls_ldp::peers::session_ka_interval::DFLT;
        let interface_hello_holdtime =
            mpls_ldp::discovery::interfaces::hello_holdtime::DFLT;
        let interface_hello_interval =
            mpls_ldp::discovery::interfaces::hello_interval::DFLT;
        let targeted_hello_holdtime =
            mpls_ldp::discovery::targeted::hello_holdtime::DFLT;
        let targeted_hello_interval =
            mpls_ldp::discovery::targeted::hello_interval::DFLT;
        let targeted_hello_accept =
            mpls_ldp::discovery::targeted::hello_accept::enabled::DFLT;

        InstanceCfg {
            router_id: None,
            session_ka_holdtime,
            session_ka_interval,
            password: None,
            interface_hello_holdtime,
            interface_hello_interval,
            targeted_hello_holdtime,
            targeted_hello_interval,
            targeted_hello_accept,
            ipv4: None,
            neighbors: Default::default(),
        }
    }
}

// ===== impl InstanceIpv4Cfg =====

impl Default for InstanceIpv4Cfg {
    fn default() -> InstanceIpv4Cfg {
        let enabled =
            mpls_ldp::discovery::targeted::address_families::ipv4::target::enabled::DFLT;

        InstanceIpv4Cfg { enabled }
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    async fn new(
        router_id: Ipv4Addr,
        trans_addr: Ipv4Addr,
        proto_input_tx: &ProtocolInputChannelsTx,
    ) -> Result<InstanceState, Error> {
        // Create UDP/TCP sockets.
        let disc_socket = udp::discovery_socket(IpAddr::from([0, 0, 0, 0]))
            .map(Arc::new)
            .map_err(IoError::UdpSocketError)?;
        let edisc_socket = udp::discovery_socket(IpAddr::V4(trans_addr))
            .map(Arc::new)
            .map_err(IoError::UdpSocketError)?;
        let session_socket = tcp::listen_socket(IpAddr::V4(trans_addr))
            .await
            .map(Arc::new)
            .map_err(IoError::TcpSocketError)?;

        // Start UDP/TCP tasks.
        let disc_rx_task =
            tasks::basic_discovery_rx(&disc_socket, &proto_input_tx.udp_pdu_rx);
        let edisc_rx_task = tasks::extended_discovery_rx(
            &edisc_socket,
            &proto_input_tx.udp_pdu_rx,
        );
        let tcp_listener_task =
            tasks::tcp_listener(&session_socket, &proto_input_tx.tcp_accept);

        Ok(InstanceState {
            msg_id: Arc::new(AtomicU32::new(0)),
            cfg_seqno: 0,
            router_id,
            neighbors: Default::default(),
            fecs: Default::default(),
            next_fec_label: *Label::UNRESERVED_RANGE.start(),
            ipv4: InstanceIpv4State::new(
                disc_socket,
                edisc_socket,
                session_socket,
                disc_rx_task,
                edisc_rx_task,
                tcp_listener_task,
                trans_addr,
            ),
        })
    }

    pub(crate) fn get_next_msg_id(msg_id: &Arc<AtomicU32>) -> u32 {
        msg_id.fetch_add(1, atomic::Ordering::Relaxed)
    }
}

// ===== impl ProtocolInputChannelsRx =====

#[async_trait]
impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            msg = self.udp_pdu_rx.recv() => {
                msg.map(ProtocolInputMsg::UdpRxPdu)
            }
            msg = self.adj_timeout.recv() => {
                msg.map(ProtocolInputMsg::AdjTimeout)
            }
            msg = self.tcp_accept.recv() => {
                msg.map(ProtocolInputMsg::TcpAccept)
            }
            msg = self.tcp_connect.recv() => {
                msg.map(ProtocolInputMsg::TcpConnect)
            }
            msg = self.nbr_pdu_rx.recv() => {
                msg.map(ProtocolInputMsg::NbrRxPdu)
            }
            msg = self.nbr_ka_timeout.recv() => {
                msg.map(ProtocolInputMsg::NbrKaTimeout)
            }
            msg = self.nbr_backoff_timeout.recv() => {
                msg.map(ProtocolInputMsg::NbrBackoffTimeout)
            }
        }
    }
}
