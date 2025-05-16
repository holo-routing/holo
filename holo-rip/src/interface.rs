//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use chrono::{DateTime, Utc};
use generational_arena::{Arena, Index};
use holo_protocol::InstanceChannelsTx;
use holo_utils::UnboundedSender;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{IpNetworkKind, SocketAddrKind};
use holo_utils::socket::UdpSocket;
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use tokio::sync::mpsc;

use crate::debug::{Debug, InterfaceInactiveReason};
use crate::error::{Error, IoError};
use crate::instance::{Instance, InstanceUpView};
use crate::network::SendDestination;
use crate::northbound::configuration::InterfaceCfg;
use crate::packet::AuthCtx;
use crate::tasks::messages::output::UdpTxPduMsg;
use crate::version::Version;
use crate::{output, tasks};

pub type InterfaceIndex = Index;

#[derive(Debug)]
pub struct Interface<V: Version> {
    pub name: String,
    pub system: InterfaceSys<V>,
    pub config: InterfaceCfg<V>,
    pub state: InterfaceState<V>,
}

#[derive(Debug)]
pub struct InterfaceSys<V: Version> {
    pub flags: InterfaceFlags,
    pub ifindex: Option<u32>,
    pub mtu: Option<u32>,
    pub addr_list: BTreeSet<V::IpNetwork>,
}

#[derive(Debug, Default)]
pub struct InterfaceState<V: Version> {
    // Interface protocol status.
    pub active: bool,
    // UDP socket and Tx/Rx tasks.
    pub net: Option<InterfaceNet<V>>,
    // Message statistics.
    pub statistics: MessageStatistics,
}

#[derive(Debug)]
pub struct InterfaceNet<V: Version> {
    // UDP socket.
    pub socket: Arc<UdpSocket>,
    // UDP Tx/Rx tasks.
    _udp_tx_task: Task<()>,
    _udp_rx_task: Task<()>,
    // UDP Tx output channel.
    pub udp_tx_pdup: UnboundedSender<UdpTxPduMsg<V>>,
}

#[derive(Debug)]
pub enum SplitHorizon {
    Disabled,
    Simple,
    PoisonReverse,
}

// Inbound and outbound statistic counters.
#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub discontinuity_time: Option<DateTime<Utc>>,
    pub bad_packets_rcvd: u32,
    pub bad_routes_rcvd: u32,
    pub updates_sent: u32,
}

#[derive(Debug)]
pub struct Interfaces<V: Version> {
    arena: Arena<Interface<V>>,
    name_tree: BTreeMap<String, InterfaceIndex>,
    ifindex_tree: HashMap<u32, InterfaceIndex>,
}

// RIP version-specific code.
pub trait InterfaceVersion<V: Version> {
    // Return a mutable reference to the interface corresponding to the given
    // packet source.
    fn get_iface_by_source(
        interfaces: &mut Interfaces<V>,
        source: V::SocketAddr,
    ) -> Option<&mut Interface<V>>;
}

// ===== impl Interface =====

impl<V> Interface<V>
where
    V: Version,
{
    fn new(name: String) -> Interface<V> {
        Debug::<V>::InterfaceCreate(&name).log();

        Interface {
            name,
            system: InterfaceSys::default(),
            config: InterfaceCfg::default(),
            state: InterfaceState::default(),
        }
    }

    // Checks if the interface needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(&mut self, instance: &mut InstanceUpView<'_, V>) {
        match self.is_ready() {
            Ok(()) if !self.state.active => {
                if let Err(error) = self.start(instance) {
                    Error::<V>::InterfaceStartError(self.name.clone(), error)
                        .log();
                }
            }
            Err(reason) if self.state.active => self.stop(instance, reason),
            _ => (),
        }
    }

    // Starts RIP operation on this interface.
    fn start(
        &mut self,
        instance: &mut InstanceUpView<'_, V>,
    ) -> Result<(), IoError> {
        Debug::<V>::InterfaceStart(&self.name).log();

        // Start network Tx/Rx tasks.
        if !self.system.flags.contains(InterfaceFlags::LOOPBACK) {
            let net = InterfaceNet::new(
                &self.name,
                self.auth(&instance.state.auth_seqno),
                instance.tx,
            )?;
            if !self.config.no_listen {
                self.system.join_multicast(&net.socket);
            }
            self.state.net = Some(net);
        }

        // Send RIP request.
        if !self.is_passive() {
            self.with_destinations(|iface, destination| {
                output::send_request(instance, iface, destination);
            });
        }

        // Mark interface as active.
        self.state.active = true;

        Ok(())
    }

    // Stops RIP operation on this interface.
    pub(crate) fn stop(
        &mut self,
        instance: &mut InstanceUpView<'_, V>,
        reason: InterfaceInactiveReason,
    ) {
        if !self.state.active {
            return;
        }

        Debug::<V>::InterfaceStop(&self.name, reason).log();

        // Invalidate all routes that go through this interface.
        for route in instance
            .state
            .routes
            .values_mut()
            .filter(|route| route.ifindex == self.system.ifindex.unwrap())
        {
            route.invalidate(
                self.config.flush_interval,
                instance.tx,
                &instance.config.trace_opts,
            );
        }

        // Reset interface state.
        self.state.active = false;
        self.state.net = None;
        self.state.statistics = Default::default();
    }

    // Returns whether the interface is ready for RIP operation.
    fn is_ready(&self) -> Result<(), InterfaceInactiveReason> {
        if !self.system.flags.contains(InterfaceFlags::OPERATIVE) {
            return Err(InterfaceInactiveReason::OperationalDown);
        }

        if self.system.ifindex.is_none() {
            return Err(InterfaceInactiveReason::MissingIfindex);
        }

        if self.system.addr_list.is_empty() {
            return Err(InterfaceInactiveReason::MissingIpAddress);
        }

        Ok(())
    }

    pub(crate) fn is_passive(&self) -> bool {
        self.system.flags.contains(InterfaceFlags::LOOPBACK)
            || self.config.passive
    }

    pub(crate) fn auth(&self, seqno: &Arc<AtomicU32>) -> Option<AuthCtx> {
        self.config.auth_key.as_ref().map(|auth_key| {
            AuthCtx::new(
                auth_key.clone(),
                self.config.auth_algo.unwrap_or(CryptoAlgo::Md5),
                seqno.clone(),
            )
        })
    }

    // Runs the passed closure once for each one of the valid interface
    // destinations (multicast and unicast).
    pub(crate) fn with_destinations<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Interface<V>, SendDestination<V::SocketAddr>),
    {
        // Multicast dst.
        let dst = SendDestination::Multicast(self.system.ifindex.unwrap());
        f(self, dst);

        // Unicast destinations (explicit neighbors).
        let explicit_neighbors =
            std::mem::take(&mut self.config.explicit_neighbors);
        for nbr_addr in &explicit_neighbors {
            if self.system.contains_addr(nbr_addr) {
                let sockaddr = V::SocketAddr::new(*nbr_addr, V::UDP_PORT);
                let dst = SendDestination::Unicast(sockaddr);
                f(self, dst);
            }
        }
        self.config.explicit_neighbors = explicit_neighbors;
    }
}

// ===== impl InterfaceNet =====

impl<V> InterfaceNet<V>
where
    V: Version,
{
    fn new(
        ifname: &str,
        auth: Option<AuthCtx>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) -> Result<Self, IoError> {
        // Create UDP socket.
        let socket = V::socket(ifname)
            .map_err(IoError::UdpSocketError)
            .map(Arc::new)?;

        // Start UDP Tx/Rx tasks.
        let (udp_tx_pdup, udp_tx_pduc) = mpsc::unbounded_channel();
        let udp_tx_task = tasks::udp_tx(
            &socket,
            auth.clone(),
            udp_tx_pduc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let udp_rx_task = tasks::udp_rx(
            &socket,
            auth,
            &instance_channels_tx.protocol_input.udp_pdu_rx,
        );

        Ok(InterfaceNet {
            socket,
            _udp_tx_task: udp_tx_task,
            _udp_rx_task: udp_rx_task,
            udp_tx_pdup,
        })
    }

    pub(crate) fn restart_tasks(
        &mut self,
        auth: Option<AuthCtx>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) {
        let (udp_tx_pdup, udp_tx_pduc) = mpsc::unbounded_channel();
        self._udp_tx_task = tasks::udp_tx(
            &self.socket,
            auth.clone(),
            udp_tx_pduc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        self._udp_rx_task = tasks::udp_rx(
            &self.socket,
            auth,
            &instance_channels_tx.protocol_input.udp_pdu_rx,
        );
        self.udp_tx_pdup = udp_tx_pdup;
    }
}

// ===== impl InterfaceSys =====

impl<V> InterfaceSys<V>
where
    V: Version,
{
    // Checks if the interface shares a subnet with the given IP address.
    pub(crate) fn contains_addr(&self, addr: &V::IpAddr) -> bool {
        for local in &self.addr_list {
            if local.contains(*addr) {
                return true;
            }
        }

        false
    }

    pub(crate) fn join_multicast(&self, socket: &UdpSocket) {
        if let Err(error) = V::join_multicast(socket, self.ifindex.unwrap()) {
            IoError::UdpMulticastJoinError(error).log();
        }
    }

    pub(crate) fn leave_multicast(&self, socket: &UdpSocket) {
        if let Err(error) = V::leave_multicast(socket, self.ifindex.unwrap()) {
            IoError::UdpMulticastJoinError(error).log();
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
        }
    }
}

// ===== impl MessageStatistics =====

impl MessageStatistics {
    pub(crate) fn update_discontinuity_time(&mut self) {
        self.discontinuity_time = Some(Utc::now());
    }
}

// ===== impl Interfaces =====

impl<V> Interfaces<V>
where
    V: Version,
{
    pub(crate) fn add(
        &mut self,
        ifname: &str,
    ) -> (InterfaceIndex, &mut Interface<V>) {
        // Check for existing entry first.
        if let Some(iface_idx) = self.name_tree.get(ifname).copied() {
            let iface = &mut self.arena[iface_idx];
            return (iface_idx, iface);
        }

        // Create and insert interface into the arena.
        let iface = Interface::new(ifname.to_owned());
        let iface_idx = self.arena.insert(iface);

        // Link interface to different collections.
        let iface = &mut self.arena[iface_idx];
        self.name_tree.insert(iface.name.clone(), iface_idx);

        (iface_idx, iface)
    }

    pub(crate) fn delete(&mut self, iface_idx: InterfaceIndex) {
        let iface = &mut self.arena[iface_idx];

        Debug::<V>::InterfaceDelete(&iface.name).log();

        // Unlink interface from different collections.
        self.name_tree.remove(&iface.name);
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }

        // Remove interface from the arena.
        self.arena.remove(iface_idx);
    }

    pub(crate) fn update_ifindex(
        &mut self,
        ifname: &str,
        ifindex: Option<u32>,
    ) -> Option<(InterfaceIndex, &mut Interface<V>)> {
        let iface_idx = self.name_tree.get(ifname).copied()?;
        let iface = &mut self.arena[iface_idx];

        // Update interface ifindex.
        if let Some(ifindex) = iface.system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        iface.system.ifindex = ifindex;
        if let Some(ifindex) = ifindex {
            self.ifindex_tree.insert(ifindex, iface_idx);
        }

        Some((iface_idx, iface))
    }

    // Returns a reference to the interface corresponding to the given name.
    #[expect(unused)]
    pub(crate) fn get_by_name(
        &self,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &Interface<V>)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(|iface_idx| (iface_idx, &self.arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // name.
    pub(crate) fn get_mut_by_name(
        &mut self,
        ifname: &str,
    ) -> Option<(InterfaceIndex, &mut Interface<V>)> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut self.arena[iface_idx]))
    }

    // Returns a reference to the interface corresponding to the given ifindex.
    pub(crate) fn get_by_ifindex(
        &self,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &Interface<V>)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| (iface_idx, &self.arena[iface_idx]))
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    #[expect(unused)]
    pub(crate) fn get_mut_by_ifindex(
        &mut self,
        ifindex: u32,
    ) -> Option<(InterfaceIndex, &mut Interface<V>)> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(move |iface_idx| (iface_idx, &mut self.arena[iface_idx]))
    }

    // Returns an iterator visiting all interfaces.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Interface<V>> + '_ {
        self.name_tree
            .values()
            .map(|iface_idx| &self.arena[*iface_idx])
    }

    // Returns an iterator visiting all interfaces with mutable references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Interface<V>> + '_ {
        self.arena.iter_mut().map(|(_, iface)| iface)
    }
}

impl<V> Default for Interfaces<V>
where
    V: Version,
{
    fn default() -> Interfaces<V> {
        Interfaces {
            arena: Arena::new(),
            name_tree: Default::default(),
            ifindex_tree: Default::default(),
        }
    }
}

impl<V> std::ops::Index<InterfaceIndex> for Interfaces<V>
where
    V: Version,
{
    type Output = Interface<V>;

    fn index(&self, index: InterfaceIndex) -> &Self::Output {
        &self.arena[index]
    }
}

impl<V> std::ops::IndexMut<InterfaceIndex> for Interfaces<V>
where
    V: Version,
{
    fn index_mut(&mut self, index: InterfaceIndex) -> &mut Self::Output {
        &mut self.arena[index]
    }
}
