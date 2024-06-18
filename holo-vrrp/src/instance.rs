//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use async_trait::async_trait;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc;

use crate::debug::{Debug, InstanceInactiveReason};
use crate::error::{Error, IoError};
use crate::northbound::configuration::InstanceCfg;
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, southbound};

#[derive(Debug)]
pub struct Instance {
    // Instance name.
    pub name: String,
    // Instance system data.
    pub system: InstanceSys,
    // Instance configuration data.
    pub config: InstanceCfg,
    // Instance state data.
    pub state: Option<InstanceState>,
    // Instance Tx channels.
    pub tx: InstanceChannelsTx<Instance>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InstanceSys {
    // System Router ID.
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub struct InstanceState {
    // Instance Router ID.
    pub router_id: Ipv4Addr,
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

// ===== impl Instance =====

/*
impl Instance {
    // Checks if the instance needs to be started or stopped in response to a
    // northbound or southbound event.
    //
    // Note: Router ID updates are ignored if the instance is already active.
    pub(crate) async fn update(&mut self) {
        let router_id = self.get_router_id();

        match self.is_ready(router_id) {
            Ok(()) if !self.is_active() => {
                self.start(router_id.unwrap()).await;
            }
            Err(reason) if self.is_active() => {
                self.stop(reason);
            }
            _ => (),
        }
    }

    // Starts the BGP instance.
    async fn start(&mut self, router_id: Ipv4Addr) {
        Debug::InstanceStart.log();

        match InstanceState::new(router_id, &self.tx).await {
            Ok(state) => {
                // Store instance initial state.
                self.state = Some(state);
            }
            Err(error) => {
                Error::InstanceStartError(Box::new(error)).log();
            }
        }
    }

    // Stops the BGP instance.
    fn stop(&mut self, reason: InstanceInactiveReason) {
        let Some((mut instance, neighbors)) = self.as_up() else {
            return;
        };

        Debug::InstanceStop(reason).log();

        // Stop neighbors.
        let error_code = ErrorCode::Cease;
        let error_subcode = CeaseSubcode::AdministrativeShutdown;
        for nbr in neighbors.values_mut() {
            let msg = NotificationMsg::new(error_code, error_subcode);
            nbr.fsm_event(&mut instance, fsm::Event::Stop(Some(msg)));
        }

        // Clear instance state.
        self.state = None;
    }

    // Returns whether the BGP instance is operational.
    fn is_active(&self) -> bool {
        self.state.is_some()
    }

    // Returns whether the instance is ready for BGP operation.
    fn is_ready(
        &self,
        router_id: Option<Ipv4Addr>,
    ) -> Result<(), InstanceInactiveReason> {
        if router_id.is_none() {
            return Err(InstanceInactiveReason::MissingRouterId);
        }

        Ok(())
    }

    // Retrieves the Router ID from configuration or system information.
    // Prioritizes the configured Router ID, using the system's Router ID as a
    // fallback.
    fn get_router_id(&self) -> Option<Ipv4Addr> {
        self.config.identifier.or(self.system.router_id)
    }
}
*/

#[async_trait]
impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::VRRP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    async fn new(
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
            tx,
            shared,
        }
    }

    async fn init(&mut self) {
        // Request information about the system Router ID.
        southbound::router_id_query(&self.tx.ibus);
    }

    async fn shutdown(mut self) {
        // TODO
        // Ensure instance is disabled before exiting.
        //self.stop(InstanceInactiveReason::AdminDown);
        Debug::InstanceDelete.log();
    }

    async fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg).await {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = match msg {
            // Received network packet.
            ProtocolInputMsg::NetRxPacket(msg) => {
                events::process_packet(self, msg.src, msg.packet)
            }
        } {
            error.log();
        }
    }

    fn protocol_input_channels(
    ) -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
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

// ===== impl InstanceState =====

impl InstanceState {}

// ===== impl ProtocolInputChannelsRx =====

#[async_trait]
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

async fn process_ibus_msg(
    instance: &mut Instance,
    msg: IbusMsg,
) -> Result<(), Error> {
    match msg {
        // Router ID update notification.
        IbusMsg::RouterIdUpdate(router_id) => {
            southbound::process_router_id_update(instance, router_id).await;
        }
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            southbound::process_iface_update(instance, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            southbound::process_addr_add(instance, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            southbound::process_addr_del(instance, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}
