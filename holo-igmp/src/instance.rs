//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::debug::Debug;
use crate::error::Error;
use crate::interface::Interface;
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, ibus};

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: InstanceState,
    // Instance interfaces.
    pub interfaces: BTreeMap<String, Interface>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {}

#[derive(Debug, Default)]
pub struct InstanceState {
    pub statistics: Statistics,
}

#[derive(Debug, Default)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub errors: ErrorStatistics,
    pub msgs_rcvd: MessageStatistics,
    pub msgs_sent: MessageStatistics,
}

#[derive(Debug, Default)]
pub struct ErrorStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
    pub checksum: u64,
    pub too_short: u64,
}

#[derive(Debug, Default)]
pub struct MessageStatistics {
    pub total: u64,
    pub query: u64,
    pub report: u64,
    pub leave: u64,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // Packet Rx event.
    pub net_packet_rx: Sender<NetRxPacketMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // Packet Rx event.
    pub net_packet_rx: Receiver<NetRxPacketMsg>,
}

pub struct InstanceView<'a> {
    pub name: &'a str,
    pub system: &'a InstanceSys,
    pub config: &'a InstanceCfg,
    pub state: &'a mut InstanceState,
    pub tx: &'a InstanceChannelsTx<Instance>,
    pub shared: &'a InstanceShared,
}

// ===== impl Instance =====

impl Instance {
    pub(crate) fn get_interface(
        &mut self,
        ifname: &str,
    ) -> Option<(InstanceView<'_>, &mut Interface)> {
        let iface = self.interfaces.get_mut(ifname)?;
        let instance = InstanceView {
            name: &self.name,
            system: &self.system,
            config: &self.config,
            state: &mut self.state,
            tx: &self.tx,
            shared: &self.shared,
        };
        Some((instance, iface))
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::IGMP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Instance>,
    ) -> Instance {
        Instance {
            name,
            system: Default::default(),
            config: Default::default(),
            state: Default::default(),
            interfaces: Default::default(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        // TODO: anything to do here?
    }

    fn shutdown(self) {
        // TODO: stop IGMP on all interfaces.
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
        let (net_packet_rxp, net_packet_rxc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            net_packet_rx: net_packet_rxp,
        };
        let rx = ProtocolInputChannelsRx {
            net_packet_rx: net_packet_rxc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl ProtocolInputChannelsRx =====

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::NetRxPacket)
            }
        }
    }
}

// ===== helper functions =====

fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    Debug::IbusRx(&msg).log();

    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            ibus::rx::process_iface_update(instance, msg)?;
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}

fn process_protocol_msg(
    instance: &mut Instance,
    msg: ProtocolInputMsg,
) -> Result<(), Error> {
    match msg {
        // Received network packet.
        ProtocolInputMsg::NetRxPacket(msg) => {
            events::process_packet(instance, msg.ifname, msg.src, msg.packet)?;
        }
    }

    Ok(())
}
