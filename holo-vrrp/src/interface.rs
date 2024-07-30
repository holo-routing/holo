//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use holo_utils::{Receiver, Sender, UnboundedSender};
use ipnetwork::Ipv4Network;
use tokio::sync::mpsc;

use crate::error::{Error, IoError};
use crate::instance::Instance;
use crate::packet::{ArpPacket, EthernetFrame, VrrpPacket};
use crate::tasks::messages::input::NetRxPacketMsg;
use crate::tasks::messages::output::NetTxPacketMsg;
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, network, southbound, tasks};

#[derive(Debug)]
pub struct Interface {
    // Interface name.
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
    // Interface raw sockets and Tx/Rx tasks.
    pub net: InterfaceNet,
    // Interface VRRP instances.
    pub instances: BTreeMap<u8, Instance>,
    // Tx channels.
    pub tx: InstanceChannelsTx<Interface>,
    // Shared data.
    pub shared: InstanceShared,
}

#[derive(Debug, Default)]
pub struct InterfaceSys {
    // Interface flags.
    pub flags: InterfaceFlags,
    // Interface index.
    pub ifindex: Option<u32>,
    // Interface IPv4 addresses.
    pub addresses: BTreeSet<Ipv4Network>,
    // interface Mac Address
    pub mac_address: [u8; 6],
}

#[derive(Debug)]
pub struct InterfaceNet {
    // Raw sockets.
    pub socket_vrrp: Arc<AsyncFd<Socket>>,
    pub socket_arp: Arc<AsyncFd<Socket>>,
    // Network Tx/Rx tasks.
    _net_tx_task: Task<()>,
    _net_rx_task: Task<()>,
    // Network Tx output channel.
    pub net_tx_packetp: UnboundedSender<NetTxPacketMsg>,
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

// ===== impl Interface =====

impl Interface {
    pub(crate) fn send_vrrp_advert(&self, vrid: u8) {
        if let Some(instance) = self.instances.get(&vrid) {
            // send advertisement then reset the timer.
            let mut ip_addresses: Vec<Ipv4Addr> = vec![];
            for addr in &instance.config.virtual_addresses {
                ip_addresses.push(addr.ip());
            }

            let mut packet = VrrpPacket {
                version: 2,
                hdr_type: 1,
                vrid: u8::default(),
                priority: instance.config.priority,
                count_ip: instance.config.virtual_addresses.len() as u8,
                auth_type: 0,
                adver_int: instance.config.advertise_interval,
                checksum: 0,
                ip_addresses,
                auth_data: 0,
                auth_data2: 0,
            };
            packet.generate_checksum();
            network::send_packet_vrrp(&self.net.socket_vrrp, packet);
        }
    }

     pub(crate) async fn send_gratuitous_arp(&self, vrid: u8) {
        let ifname  = &self.name;

        if let Some(instance) = self.instances.get(&vrid) {

            // send a gratuitous for each of the 
            // virutal IP addresses
            for addr in instance.config.virtual_addresses.clone() {

                let arp_packet = ArpPacket {
                    hw_type: 1, 
                    // for Ipv4 
                    proto_type: 0x0800,
                    // mac address length
                    hw_length: 6, 
                    proto_length: 4,
                    operation: 1,
                    // sender hw address is virtual mac.
                    // https://datatracker.ietf.org/doc/html/rfc3768#section-7.3
                    sender_hw_address: [0x00, 0x00, 0x5e, 0x00, 0x01, vrid], 
                    sender_proto_address: addr.ip().octets(), 
                    target_hw_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // broadcast
                    target_proto_address:  addr.ip().octets() 
                };

                let mut mac_addr = self.system.mac_address.clone();
                let eth_frame = EthernetFrame {
                    ethertype: 0x806,
                    dst_mac: [0xff; 6],
                    src_mac: mac_addr
                };
                let _ = network::send_packet_arp(
                    &self.net.socket_arp, 
                    &self.name, 
                    eth_frame, 
                    arp_packet
                );

            }

        }
    }


}

#[async_trait]
impl ProtocolInstance for Interface {
    const PROTOCOL: Protocol = Protocol::VRRP;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    async fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Interface>,
    ) -> Interface {
        // TODO: proper error handling
        let net = InterfaceNet::new(&name, &tx)
            .expect("Failed to initialize VRRP network tasks");
        Interface {
            name,
            system: Default::default(),
            net,
            instances: Default::default(),
            tx,
            shared,
        }
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
                events::process_packet(self, msg.packet)
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

// ===== impl InterfaceNet =====

impl InterfaceNet {
    fn new(
        ifname: &str,
        instance_channels_tx: &InstanceChannelsTx<Interface>,
    ) -> Result<Self, IoError> {
        // Create raw sockets.
        let socket_vrrp = network::socket_vrrp(ifname)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;
        let socket_arp = network::socket_arp(ifname)
            .map_err(IoError::SocketError)
            .and_then(|socket| {
                AsyncFd::new(socket).map_err(IoError::SocketError)
            })
            .map(Arc::new)?;

        // Start network Tx/Rx tasks.
        let (net_tx_packetp, net_tx_packetc) = mpsc::unbounded_channel();
        let net_tx_task = tasks::net_tx(
            socket_vrrp.clone(),
            socket_arp.clone(),
            net_tx_packetc,
            #[cfg(feature = "testing")]
            &instance_channels_tx.protocol_output,
        );
        let net_rx_task = tasks::net_rx(
            socket_vrrp.clone(),
            &instance_channels_tx.protocol_input.net_packet_rx,
        );

        Ok(InterfaceNet {
            socket_vrrp,
            socket_arp,
            _net_tx_task: net_tx_task,
            _net_rx_task: net_rx_task,
            net_tx_packetp,
        })
    }
}

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
    interface: &mut Interface,
    msg: IbusMsg,
) -> Result<(), Error> {
    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            southbound::process_iface_update(interface, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            southbound::process_addr_add(interface, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            southbound::process_addr_del(interface, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}
