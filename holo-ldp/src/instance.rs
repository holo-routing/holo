//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU32};

use derive_new::new;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{TcpListener, UdpSocket};
use holo_utils::task::Task;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::collections::{Adjacencies, Interfaces, Neighbors, TargetedNbrs};
use crate::debug::{Debug, InstanceInactiveReason, InterfaceInactiveReason};
use crate::discovery::TargetedNbr;
use crate::error::{Error, IoError};
use crate::fec::Fec;
use crate::network::{tcp, udp};
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::input::{
    AdjTimeoutMsg, NbrBackoffTimeoutMsg, NbrKaTimeoutMsg, NbrRxPduMsg,
    TcpAcceptMsg, TcpConnectMsg, UdpRxPduMsg,
};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus, tasks};

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state-dependent data.
    pub state: Option<InstanceState>,
    // Instance interfaces.
    pub interfaces: Interfaces,
    // Instance targeted neighbors (configured or learned).
    pub tneighbors: TargetedNbrs,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    pub router_id: Option<Ipv4Addr>,
    pub ipv4_addr_list: BTreeSet<Ipv4Network>,
    pub ipv6_addr_list: BTreeSet<Ipv6Network>,
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

pub struct InstanceUpView<'a> {
    pub name: &'a str,
    pub system: &'a mut InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState,
    pub tx: &'a InstanceChannelsTx<Instance>,
    pub shared: &'a InstanceShared,
}

// ===== impl Instance =====

impl Instance {
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    //
    // NOTE: Router-ID updates are ignored if the instance is already active.
    pub(crate) fn update(&mut self) {
        let router_id = self.get_router_id();

        match self.is_ready(router_id) {
            Ok(()) if !self.is_active() => {
                self.try_start(router_id.unwrap());
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    fn try_start(&mut self, router_id: Ipv4Addr) {
        let trans_addr = router_id;
        let proto_input_tx = &self.tx.protocol_input;

        match InstanceState::new(router_id, trans_addr, proto_input_tx) {
            Ok(state) => {
                Debug::InstanceStart.log();

                // Store instance initial state.
                self.state = Some(state);

                // Try to start interfaces and targeted neighbors.
                let (mut instance, interfaces, tneighbors) =
                    self.as_up().unwrap();
                for iface in interfaces.iter_mut() {
                    iface.update(&mut instance);
                }
                for tnbr_idx in tneighbors.indexes().collect::<Vec<_>>() {
                    TargetedNbr::update(&mut instance, tneighbors, tnbr_idx);
                }
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

        Debug::InstanceStop(reason).log();

        // Stop interfaces and targeted neighbors.
        let (mut instance, interfaces, tneighbors) = self.as_up().unwrap();
        for iface in interfaces.iter_mut() {
            if iface.is_active() {
                let reason = InterfaceInactiveReason::InstanceDown;
                iface.stop(&mut instance, reason);
            }
        }
        for tnbr in tneighbors.iter_mut() {
            if tnbr.is_active() {
                tnbr.stop(&mut instance, true);
            }
        }

        // Clear instance state.
        self.state = None;
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for LDP operation.
    fn is_ready(
        &self,
        router_id: Option<Ipv4Addr>,
    ) -> Result<(), InstanceInactiveReason> {
        if self.config.ipv4.is_none()
            || !self.config.ipv4.as_ref().unwrap().enabled
        {
            return Err(InstanceInactiveReason::AdminDown);
        }

        if router_id.is_none() {
            return Err(InstanceInactiveReason::MissingRouterId);
        }

        Ok(())
    }

    fn get_router_id(&self) -> Option<Ipv4Addr> {
        self.config.router_id.or(self.system.router_id)
    }

    pub(crate) fn as_up(
        &mut self,
    ) -> Option<(InstanceUpView<'_>, &mut Interfaces, &mut TargetedNbrs)> {
        if let Some(state) = &mut self.state {
            let instance = InstanceUpView {
                name: &self.name,
                system: &mut self.system,
                config: &self.config,
                state,
                tx: &self.tx,
                shared: &self.shared,
            };
            Some((instance, &mut self.interfaces, &mut self.tneighbors))
        } else {
            None
        }
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::LDP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Debug::InstanceCreate.log();

        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: None,
            interfaces: Default::default(),
            tneighbors: Default::default(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        // Request information about the system Router ID.
        ibus::tx::router_id_sub(&self.tx.ibus);

        // Subscribe for the redistribution of all non-BGP routes.
        ibus::tx::route_redistribute_sub(&self.tx.ibus);
    }

    fn shutdown(mut self) {
        // Ensure instance is disabled before exiting.
        self.stop(InstanceInactiveReason::AdminDown);
        Debug::InstanceDelete.log();
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        // Ignore event if the instance isn't active.
        if let Some((mut instance, interfaces, tneighbors)) = self.as_up()
            && let Err(error) =
                process_protocol_msg(&mut instance, interfaces, tneighbors, msg)
        {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
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

// ===== impl InstanceCfg =====

impl InstanceCfg {
    // Retrieves the password for a specific neighbor identified by its LSR-ID.
    // If a custom password isn't configured for the neighbor, it's inherited
    // from the global configuration.
    pub(crate) fn get_neighbor_password(
        &self,
        lsr_id: Ipv4Addr,
    ) -> Option<&str> {
        if let Some(nbr_cfg) = self.neighbors.get(&lsr_id)
            && nbr_cfg.password.is_some()
        {
            return nbr_cfg.password.as_deref();
        }

        self.password.as_deref()
    }
}

// ===== impl InstanceState =====

impl InstanceState {
    fn new(
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

// ===== helper functions =====

fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            ibus::rx::process_addr_add(instance, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            ibus::rx::process_addr_del(instance, msg);
        }
        // Router ID update notification.
        IbusMsg::RouterIdUpdate(router_id) => {
            ibus::rx::process_router_id_update(instance, router_id);
        }
        // Route redistribute update notification.
        IbusMsg::RouteRedistributeAdd(msg) => {
            ibus::rx::process_route_add(instance, msg);
        }
        // Route redistribute delete notification.
        IbusMsg::RouteRedistributeDel(msg) => {
            ibus::rx::process_route_del(instance, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut InstanceUpView<'_>,
    interfaces: &mut Interfaces,
    tneighbors: &mut TargetedNbrs,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received UDP discovery PDU.
        ProtocolInputMsg::UdpRxPdu(msg) => {
            events::process_udp_pdu(
                instance,
                interfaces,
                tneighbors,
                msg.src_addr,
                msg.pdu,
                msg.multicast,
            );
        }
        // Adjacency's timeout has expired.
        ProtocolInputMsg::AdjTimeout(msg) => {
            events::process_adj_timeout(instance, tneighbors, msg.adj_id)?;
        }
        // Accepted TCP connection request.
        ProtocolInputMsg::TcpAccept(mut msg) => {
            events::process_tcp_accept(instance, msg.stream(), msg.conn_info);
        }
        // Established TCP connection.
        ProtocolInputMsg::TcpConnect(mut msg) => {
            events::process_tcp_connect(
                instance,
                msg.nbr_id,
                msg.stream(),
                msg.conn_info,
            )?;
        }
        // Received PDU from neighbor.
        ProtocolInputMsg::NbrRxPdu(msg) => {
            events::process_nbr_pdu(instance, msg.nbr_id, msg.pdu)?;
        }
        // Neighbor's keepalive timeout has expired.
        ProtocolInputMsg::NbrKaTimeout(msg) => {
            events::process_nbr_ka_timeout(instance, msg.nbr_id)?;
        }
        // Neighbor's backoff timeout has expired.
        ProtocolInputMsg::NbrBackoffTimeout(msg) => {
            events::process_nbr_backoff_timeout(instance, msg.lsr_id);
        }
    }

    Ok(())
}
