//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use holo_utils::socket::{AsyncFd, RawSocketExt, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, IoError};
use crate::group::Group;
use crate::instance::InstanceUpView;
use crate::northbound::configuration::InterfaceCfg;
use crate::packet::{IgmpV2Message, MembershipReportV2, Packet, PacketType};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::{network, tasks};

/// Collection of multicast groups on this interface
pub type Groups = BTreeMap<Ipv4Addr, Group>;

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub system: InterfaceSys,
    pub config: InterfaceCfg,
    pub state: InterfaceState,
    /// Multicast groups with local members on this interface
    pub groups: Groups,
}

#[derive(Debug, Default)]
pub struct InterfaceSys {
    pub flags: InterfaceFlags,
    pub ifindex: Option<u32>,
}

#[derive(Debug, Default)]
pub struct InterfaceState {
    pub active: bool,
    pub net: Option<InterfaceNet>,
    pub tasks: InterfaceTasks,
}

#[derive(Debug)]
pub struct InterfaceNet {
    pub socket_tx: Arc<AsyncFd<Socket>>,
    _net_tx_task: Task<()>,
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg>,
}

#[derive(Debug, Default)]
pub struct InterfaceTasks {}

// ===== impl Interface =====

impl Interface {
    pub(crate) fn new(name: String) -> Interface {
        Interface {
            name,
            system: InterfaceSys::default(),
            config: InterfaceCfg::default(),
            state: InterfaceState::default(),
            groups: BTreeMap::new(),
        }
    }

    pub(crate) fn update(&mut self, instance: &mut InstanceUpView<'_>) {
        match self.is_ready() {
            Ok(()) if !self.state.active => {
                if let Err(error) = self.start(instance) {
                    Error::InterfaceStartError(
                        self.name.clone(),
                        Box::new(error),
                    )
                    .log();
                }
            }
            Err(reason) if self.state.active => self.stop(instance, reason),
            _ => (),
        }
    }

    fn start(
        &mut self,
        instance: &mut InstanceUpView<'_>,
    ) -> Result<(), Error> {
        //Debug::InterfaceStart(&self.name).log();

        let ifindex = self.system.ifindex.unwrap();

        #[cfg(not(feature = "testing"))]
        instance
            .state
            .net
            .socket_rx
            .get_ref()
            .start_vif(ifindex, ifindex as u16)
            .expect("TODO: panic message");

        #[cfg(not(feature = "testing"))]
        instance
            .state
            .net
            .socket_rx
            .get_ref()
            .join_multicast_ifindex_v4_raw(&network::ALL_ROUTERS, ifindex)
            .map_err(IoError::SocketError)?;
        // Create raw socket.
        let socket =
            network::socket_tx(&self.name).map_err(IoError::SocketError)?;
        let socket = AsyncFd::new(socket).map_err(IoError::SocketError)?;
        let socket = Arc::new(socket);

        // TODO: join multicast addresses?

        // Start network Tx task.
        self.state.net = Some(InterfaceNet::new(socket, instance));

        // XXX send IGMP packet just for testing the socket.
        let packet =
            Packet::MembershipReport(MembershipReportV2(IgmpV2Message {
                igmp_type: PacketType::MembershipReportV2Type,
                max_resp_time: Some(0x00),
                checksum: 0x06fb,
                group_address: Some("225.1.2.3".parse().unwrap()),
            }));
        self.send_packet(packet);

        // TODO: send periodic messages?

        // Mark interface as active.
        self.state.active = true;

        Ok(())
    }

    #[allow(clippy::needless_return)]
    pub(crate) fn stop(
        &mut self,
        _instance: &mut InstanceUpView<'_>,
        _reason: InterfaceInactiveReason,
    ) {
        if !self.state.active {
            return;
        }

        // TODO clean up everything
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

        Ok(())
    }

    pub(crate) fn send_packet(&mut self, packet: Packet) {
        // TODO: Update packet counters.

        // Enqueue packet for transmission.
        let msg = NetTxPacketMsg {
            #[cfg(feature = "testing")]
            ifname: self.name.clone(),
            dst: *network::ALL_SYSTEMS,
            packet,
        };
        let _ = self.state.net.as_ref().unwrap().net_tx_packetp.send(msg);
    }

    /// Get or create a multicast group.
    ///
    /// Returns a mutable reference to the group, creating it if it doesn't exist.
    pub(crate) fn get_or_create_group(
        &mut self,
        group_addr: Ipv4Addr,
    ) -> &mut Group {
        self.groups
            .entry(group_addr)
            .or_insert_with(|| Group::new(group_addr))
    }

    /// Get a multicast group if it exists.
    pub(crate) fn get_group(&self, group_addr: &Ipv4Addr) -> Option<&Group> {
        self.groups.get(group_addr)
    }

    /// Get a mutable reference to a multicast group if it exists.
    pub(crate) fn get_group_mut(
        &mut self,
        group_addr: &Ipv4Addr,
    ) -> Option<&mut Group> {
        self.groups.get_mut(group_addr)
    }

    /// Remove a multicast group.
    ///
    /// Returns true if the group was present and removed.
    pub(crate) fn remove_group(&mut self, group_addr: &Ipv4Addr) -> bool {
        self.groups.remove(group_addr).is_some()
    }

    /// Check if the interface has any active multicast groups.
    pub(crate) fn has_groups(&self) -> bool {
        !self.groups.is_empty()
    }
}

// ===== impl InterfaceNet =====

impl InterfaceNet {
    pub(crate) fn new(
        socket_tx: Arc<AsyncFd<Socket>>,
        #[allow(unused_variables)] instance: &mut InstanceUpView<'_>,
    ) -> Self {
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let mut net_tx_task = tasks::net_tx(
            socket_tx.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance.tx.protocol_output,
        );
        net_tx_task.detach();

        InterfaceNet {
            socket_tx,
            _net_tx_task: net_tx_task,
            net_tx_packetp,
        }
    }
}
