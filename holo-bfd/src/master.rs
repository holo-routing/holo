//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::HashMap;

use derive_new::new;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::bfd::{PathType, State};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::task::Task;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::error::{Error, IoError};
use crate::session::Sessions;
use crate::tasks::messages::input::{DetectTimerMsg, UdpRxPacketMsg};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus, network, tasks};

#[derive(Debug)]
pub struct Master {
    // UDP Rx tasks.
    udp_sh_rx_tasks: Option<UdpRxTasks>,
    udp_mh_rx_tasks: Option<UdpRxTasks>,
    // BFD sessions.
    pub sessions: Sessions,
    // System interfaces.
    pub interfaces: HashMap<String, Interface>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Master>,
}

#[derive(Debug)]
pub struct UdpRxTasks {
    _ipv4: Option<Task<()>>,
    _ipv6: Option<Task<()>>,
}

#[derive(Debug, new)]
pub struct Interface {
    pub name: String,
    pub ifindex: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // UDP Rx event.
    pub udp_packet_rx: Sender<UdpRxPacketMsg>,
    // Detection timer.
    pub detect_timer: Sender<DetectTimerMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // UDP Rx event.
    pub udp_packet_rx: Receiver<UdpRxPacketMsg>,
    // Detection timer.
    pub detect_timer: Receiver<DetectTimerMsg>,
}

// ===== impl Master =====

impl Master {
    // Starts or stops UDP Rx tasks for single-hop and multihop sessions.
    //
    // A single-hop/multihop UDP Rx task is conditioned to existence of at least
    // one BFD session of that path type. This is done to avoid creating UDP
    // sockets that are not necessary.
    pub(crate) fn update_udp_rx_tasks(&mut self) {
        let ip_sh_sessions =
            self.sessions.iter().any(|sess| sess.key.is_ip_single_hop());
        let ip_mh_sessions =
            self.sessions.iter().any(|sess| sess.key.is_ip_multihop());
        let udp_packet_rxp = &self.tx.protocol_input.udp_packet_rx;

        // Update IP single-hop Rx tasks.
        if ip_sh_sessions && self.udp_sh_rx_tasks.is_none() {
            self.udp_sh_rx_tasks =
                Some(UdpRxTasks::new(PathType::IpSingleHop, udp_packet_rxp));
        } else if !ip_sh_sessions && self.udp_sh_rx_tasks.is_some() {
            self.udp_sh_rx_tasks = None;
        }

        // Update IP multihop Rx tasks.
        if ip_mh_sessions && self.udp_mh_rx_tasks.is_none() {
            self.udp_mh_rx_tasks =
                Some(UdpRxTasks::new(PathType::IpMultihop, udp_packet_rxp));
        } else if !ip_mh_sessions && self.udp_mh_rx_tasks.is_some() {
            self.udp_mh_rx_tasks = None;
        }
    }

    // Counts the number of sessions that match the given path type and local
    // state.
    pub(crate) fn sessions_count(
        &self,
        path_type: Option<PathType>,
        local_state: Option<State>,
    ) -> usize {
        self.sessions
            .iter()
            .filter(|sess| match path_type {
                Some(path_type) => sess.key.path_type() == path_type,
                None => true,
            })
            .filter(|sess| match local_state {
                Some(local_state) => sess.state.local_state == local_state,
                None => true,
            })
            .count()
    }
}

impl ProtocolInstance for Master {
    const PROTOCOL: Protocol = Protocol::BFD;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        _name: String,
        _shared: InstanceShared,
        tx: InstanceChannelsTx<Master>,
    ) -> Master {
        Master {
            udp_sh_rx_tasks: None,
            udp_mh_rx_tasks: None,
            sessions: Default::default(),
            interfaces: Default::default(),
            tx,
        }
    }

    fn init(&mut self) {
        // Request information about all interfaces.
        self.tx.ibus.interface_sub(None, None);
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg) {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = process_protocol_msg(self, msg) {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (udp_packet_rxp, udp_packet_rxc) = mpsc::channel(4);
        let (detect_timerp, detect_timerc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            udp_packet_rx: udp_packet_rxp,
            detect_timer: detect_timerp,
        };
        let rx = ProtocolInputChannelsRx {
            udp_packet_rx: udp_packet_rxc,
            detect_timer: detect_timerc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl UdpRxTasks =====

impl UdpRxTasks {
    // Starts UDP Rx tasks for the given BFD path type.
    fn new(
        path_type: PathType,
        udp_packet_rxp: &Sender<UdpRxPacketMsg>,
    ) -> Self {
        let udp_rx_task = |af| match network::socket_rx(path_type, af) {
            Ok(socket) => {
                Some(tasks::udp_rx(socket, path_type, udp_packet_rxp))
            }
            Err(error) => {
                IoError::UdpSocketError(error).log();
                None
            }
        };
        UdpRxTasks {
            _ipv4: udp_rx_task(AddressFamily::Ipv4),
            _ipv6: udp_rx_task(AddressFamily::Ipv6),
        }
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            msg = self.udp_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::UdpRxPacket)
            }
            msg = self.detect_timer.recv() => {
                msg.map(ProtocolInputMsg::DetectTimer)
            }
        }
    }
}

// ===== helper functions =====

fn process_ibus_msg(master: &mut Master, msg: IbusMsg) -> Result<(), Error> {
    match msg {
        // BFD peer registration.
        IbusMsg::BfdSessionReg {
            subscriber,
            client_id,
            sess_key,
            client_config,
        } => ibus::process_client_peer_reg(
            master,
            subscriber.unwrap(),
            sess_key,
            client_id,
            client_config,
        )?,
        // BFD peer unregistration.
        IbusMsg::BfdSessionUnreg {
            subscriber,
            sess_key,
        } => ibus::process_client_peer_unreg(
            master,
            subscriber.unwrap(),
            sess_key,
        )?,
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::process_iface_update(master, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    master: &mut Master,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received UDP packet.
        ProtocolInputMsg::UdpRxPacket(msg) => {
            events::process_udp_packet(master, msg.packet_info, msg.packet)?;
        }
        // Session detection timer expired.
        ProtocolInputMsg::DetectTimer(msg) => {
            events::process_detection_timer_expiry(master, msg.sess_id)?;
        }
    }

    Ok(())
}
