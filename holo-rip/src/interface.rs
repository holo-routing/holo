//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use chrono::{DateTime, Utc};
use enum_as_inner::EnumAsInner;
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
use crate::instance::{Instance, InstanceState};
use crate::network::SendDestination;
use crate::northbound::configuration::InterfaceCfg;
use crate::packet::AuthCtx;
use crate::tasks::messages::output::UdpTxPduMsg;
use crate::version::Version;
use crate::{output, tasks};

pub type InterfaceIndex = Index;
pub type InterfaceUp<V> = InterfaceCommon<V, InterfaceState<V>>;
pub type InterfaceDown<V> = InterfaceCommon<V, InterfaceStateDown>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, EnumAsInner)]
pub enum Interface<V: Version> {
    Up(InterfaceUp<V>),
    Down(InterfaceDown<V>),
    // This state is required to allow in-place mutations of Interface.
    Transitioning,
}

#[derive(Debug)]
pub struct InterfaceCommon<V: Version, State> {
    // Interface state-independent data.
    pub core: InterfaceCore<V>,
    // Interface state-dependent data.
    pub state: State,
}

#[derive(Debug)]
pub struct InterfaceCore<V: Version> {
    pub name: String,
    pub system: InterfaceSys<V>,
    pub config: InterfaceCfg<V>,
}

#[derive(Debug)]
pub struct InterfaceSys<V: Version> {
    pub flags: InterfaceFlags,
    pub ifindex: Option<u32>,
    pub mtu: Option<u32>,
    pub addr_list: BTreeSet<V::IpNetwork>,
}

#[derive(Debug)]
pub struct InterfaceState<V: Version> {
    // UDP socket and Tx/Rx tasks.
    pub net: Option<InterfaceNet<V>>,
    // Message statistics.
    pub statistics: MessageStatistics,
}

#[derive(Debug)]
pub struct InterfaceStateDown();

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
    pub arena: Arena<Interface<V>>,
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
    ) -> Option<(InterfaceIndex, &mut Interface<V>)>;
}

// ===== impl Interface =====

impl<V> Interface<V>
where
    V: Version,
{
    fn new(name: String) -> Interface<V> {
        Debug::<V>::InterfaceCreate(&name).log();

        Interface::Down(InterfaceDown {
            core: InterfaceCore {
                name,
                system: InterfaceSys::default(),
                config: InterfaceCfg::default(),
            },
            state: InterfaceStateDown(),
        })
    }

    // Checks if the interface needs to be started or stopped in response to a
    // northbound or southbound event.
    pub(crate) fn update(
        &mut self,
        instance_state: &mut InstanceState<V>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) {
        match self.is_ready() {
            Ok(()) if !self.is_active() => {
                self.start(instance_state, instance_channels_tx);
            }
            Err(reason) if self.is_active() => {
                self.stop(instance_state, instance_channels_tx, reason);
            }
            _ => (),
        }
    }

    // Starts RIP operation on this interface.
    fn start(
        &mut self,
        instance_state: &mut InstanceState<V>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) {
        let iface = std::mem::replace(self, Interface::Transitioning)
            .into_down()
            .unwrap();
        match iface.start(instance_state, instance_channels_tx) {
            Ok(iface) => {
                *self = Interface::Up(iface);
            }
            Err(error) => {
                let ifname = self.core().name.clone();
                Error::<V>::InterfaceStartError(ifname, error).log();
            }
        }
    }

    // Stops RIP operation on this interface.
    pub(crate) fn stop(
        &mut self,
        instance_state: &mut InstanceState<V>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
        reason: InterfaceInactiveReason,
    ) {
        if !self.is_active() {
            return;
        }

        let iface = std::mem::replace(self, Interface::Transitioning)
            .into_up()
            .unwrap();
        *self = Interface::Down(iface.stop(
            instance_state,
            instance_channels_tx,
            reason,
        ));
    }

    // Checks if RIP is operational on this interface.
    pub(crate) fn is_active(&self) -> bool {
        matches!(self, Interface::Up(_))
    }

    // Returns whether the interface is ready for RIP operation.
    fn is_ready(&self) -> Result<(), InterfaceInactiveReason> {
        if !self.core().system.flags.contains(InterfaceFlags::OPERATIVE) {
            return Err(InterfaceInactiveReason::OperationalDown);
        }

        if self.core().system.ifindex.is_none() {
            return Err(InterfaceInactiveReason::MissingIfindex);
        }

        if self.core().system.addr_list.is_empty() {
            return Err(InterfaceInactiveReason::MissingIpAddress);
        }

        Ok(())
    }

    #[inline]
    pub(crate) fn core(&self) -> &InterfaceCore<V> {
        match self {
            Interface::Up(iface) => &iface.core,
            Interface::Down(iface) => &iface.core,
            Interface::Transitioning => unreachable!(),
        }
    }

    #[inline]
    pub(crate) fn core_mut(&mut self) -> &mut InterfaceCore<V> {
        match self {
            Interface::Up(iface) => &mut iface.core,
            Interface::Down(iface) => &mut iface.core,
            Interface::Transitioning => unreachable!(),
        }
    }
}

// ===== impl InterfaceCommon =====

// Active RIP interface.
impl<V> InterfaceCommon<V, InterfaceState<V>>
where
    V: Version,
{
    fn stop(
        self,
        instance_state: &mut InstanceState<V>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
        reason: InterfaceInactiveReason,
    ) -> InterfaceCommon<V, InterfaceStateDown> {
        Debug::<V>::InterfaceStop(&self.core.name, reason).log();

        // Invalidate all routes that go through this interface.
        for route in instance_state
            .routes
            .values_mut()
            .filter(|route| route.ifindex == self.core.system.ifindex.unwrap())
        {
            route.invalidate(
                self.core.config.flush_interval,
                instance_channels_tx,
            );
        }

        InterfaceCommon::<V, InterfaceStateDown> {
            core: self.core,
            state: InterfaceStateDown(),
        }
    }

    pub(crate) fn is_passive(&self) -> bool {
        self.core.system.flags.contains(InterfaceFlags::LOOPBACK)
            || self.core.config.passive
    }

    pub(crate) fn auth(&self, seqno: &Arc<AtomicU32>) -> Option<AuthCtx> {
        self.core.config.auth_key.as_ref().map(|auth_key| {
            AuthCtx::new(
                auth_key.clone(),
                self.core.config.auth_algo.unwrap_or(CryptoAlgo::Md5),
                seqno.clone(),
            )
        })
    }

    // Runs the passed closure once for each one of the valid interface
    // destinations (multicast and unicast).
    pub(crate) fn with_destinations<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut InterfaceUp<V>, SendDestination<V::SocketAddr>),
    {
        // Multicast dst.
        let dst = SendDestination::Multicast(self.core.system.ifindex.unwrap());
        f(self, dst);

        // Unicast destinations (explicit neighbors).
        let explicit_neighbors =
            std::mem::take(&mut self.core.config.explicit_neighbors);
        for nbr_addr in &explicit_neighbors {
            if self.core.system.contains_addr(nbr_addr) {
                let sockaddr = V::SocketAddr::new(*nbr_addr, V::UDP_PORT);
                let dst = SendDestination::Unicast(sockaddr);
                f(self, dst);
            }
        }
        self.core.config.explicit_neighbors = explicit_neighbors;
    }
}

// Inactive RIP interface.
impl<V> InterfaceCommon<V, InterfaceStateDown>
where
    V: Version,
{
    fn start(
        self,
        instance_state: &mut InstanceState<V>,
        instance_channels_tx: &InstanceChannelsTx<Instance<V>>,
    ) -> Result<InterfaceCommon<V, InterfaceState<V>>, IoError> {
        Debug::<V>::InterfaceStart(&self.core.name).log();

        let mut iface = InterfaceCommon {
            core: self.core,
            state: InterfaceState {
                net: None,
                statistics: Default::default(),
            },
        };

        // Start network Tx/Rx tasks.
        if !iface.core.system.flags.contains(InterfaceFlags::LOOPBACK) {
            let net = InterfaceNet::new(
                &iface.core.name,
                iface.auth(&instance_state.auth_seqno),
                instance_channels_tx,
            )?;
            if !iface.core.config.no_listen {
                iface.core.system.join_multicast(&net.socket);
            }
            iface.state.net = Some(net);
        }

        // Send RIP request.
        if !iface.is_passive() {
            iface.with_destinations(|iface, destination| {
                output::send_request(instance_state, iface, destination);
            });
        }

        Ok(iface)
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
        self.name_tree.insert(iface.core().name.clone(), iface_idx);

        (iface_idx, iface)
    }

    pub(crate) fn delete(&mut self, iface_idx: InterfaceIndex) {
        let iface = &mut self.arena[iface_idx];

        Debug::<V>::InterfaceDelete(&iface.core().name).log();

        // Unlink interface from different collections.
        self.name_tree.remove(&iface.core().name);
        if let Some(ifindex) = iface.core().system.ifindex {
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
        if let Some(ifindex) = iface.core().system.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        iface.core_mut().system.ifindex = ifindex;
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
