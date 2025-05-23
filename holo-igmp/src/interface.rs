//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, IoError};
use crate::instance::InstanceView;
use crate::northbound::configuration::InterfaceCfg;
use crate::packet::{IgmpV2Message, MembershipReportV2, Packet, PacketType};
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::{network, tasks};

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub system: InterfaceSys,
    pub config: InterfaceCfg,
    pub state: InterfaceState,
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
    pub socket: Arc<AsyncFd<Socket>>,
    _net_tx_task: Task<()>,
    _net_rx_task: Task<()>,
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
        }
    }

    pub(crate) fn update(&mut self, instance: &mut InstanceView<'_>) {
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

    fn start(&mut self, instance: &mut InstanceView<'_>) -> Result<(), Error> {
        //Debug::InterfaceStart(&self.name).log();

        // Create raw socket.
        let socket =
            network::socket(&self.name).map_err(IoError::SocketError)?;
        let socket = AsyncFd::new(socket).map_err(IoError::SocketError)?;
        let socket = Arc::new(socket);

        // TODO: join multicast addresses?

        // Start network Tx/Rx tasks.
        self.state.net = Some(InterfaceNet::new(socket, self, instance));

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
        _instance: &mut InstanceView<'_>,
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
}

// ===== impl InterfaceNet =====

impl InterfaceNet {
    pub(crate) fn new(
        socket: Arc<AsyncFd<Socket>>,
        iface: &Interface,
        instance: &mut InstanceView<'_>,
    ) -> Self {
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let mut net_tx_task = tasks::net_tx(
            socket.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance.tx.protocol_output,
        );
        let net_rx_task = tasks::net_rx(
            socket.clone(),
            iface.name.clone(),
            &instance.tx.protocol_input.net_packet_rx,
        );
        net_tx_task.detach();

        InterfaceNet {
            socket,
            _net_tx_task: net_tx_task,
            _net_rx_task: net_rx_task,
            net_tx_packetp,
        }
    }
}
