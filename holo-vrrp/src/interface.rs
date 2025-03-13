//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::InterfaceFlags;
use holo_utils::{Receiver, Sender};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;

use crate::error::Error;
use crate::instance::{Instance, Version};
use crate::tasks::messages::input::{MasterDownTimerMsg, VrrpNetRxPacketMsg};
use crate::tasks::messages::{ProtocolInputMsg, ProtocolOutputMsg};
use crate::{events, southbound};

#[derive(Debug)]
pub struct Interface {
    // Interface name.
    pub name: String,
    // Interface system data.
    pub system: InterfaceSys,
    // Interface VRRPv2 instances.
    pub vrrp_v2_instances: BTreeMap<u8, Instance>,
    // Interface IPv4 VRRPv3 instances.
    pub vrrp_v3_instances_ipv4: BTreeMap<u8, Instance>,
    // Interface IPv6 VRRPv3 instances.
    pub vrrp_v3_instances_ipv6: BTreeMap<u8, Instance>,
    // Global statistics.
    pub statistics: Statistics,
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
    // Interface IP addresses.
    pub addresses: BTreeSet<IpNetwork>,
    // interface MAC Address
    pub mac_address: [u8; 6],
}

#[derive(Debug, Default)]
pub struct Statistics {
    pub discontinuity_time: DateTime<Utc>,
    pub checksum_errors: u64,
    pub version_errors: u64,
    pub vrid_errors: u64,
    pub ip_ttl_errors: u64,
}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    // VRRP packet Rx event.
    pub vrrp_net_packet_tx: Sender<VrrpNetRxPacketMsg>,
    // Master down timer.
    pub master_down_timer_tx: Sender<MasterDownTimerMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    // VRRP packet Rx event.
    pub vrrp_net_packet_rx: Receiver<VrrpNetRxPacketMsg>,
    // Master down timer.
    pub master_down_timer_rx: Receiver<MasterDownTimerMsg>,
}

pub struct InterfaceView<'a> {
    pub name: &'a str,
    pub system: &'a mut InterfaceSys,
    pub statistics: &'a mut Statistics,
    pub tx: &'a InstanceChannelsTx<Interface>,
    pub shared: &'a InstanceShared,
}

// ===== impl Interface =====

impl Interface {
    pub(crate) fn get_instance(
        &mut self,
        vrid: u8,
        version: Version,
    ) -> Option<(InterfaceView<'_>, &mut Instance)> {
        let instances = match version {
            Version::V2 => &mut self.vrrp_v2_instances,
            Version::V3(AddressFamily::Ipv4) => {
                &mut self.vrrp_v3_instances_ipv4
            }
            Version::V3(AddressFamily::Ipv6) => {
                &mut self.vrrp_v3_instances_ipv6
            }
        };
        instances.get_mut(&vrid).map(|instance| {
            (
                InterfaceView {
                    name: &self.name,
                    system: &mut self.system,
                    statistics: &mut self.statistics,
                    tx: &self.tx,
                    shared: &self.shared,
                },
                instance,
            )
        })
    }

    pub(crate) fn iter_instances(
        &mut self,
    ) -> (InterfaceView<'_>, impl Iterator<Item = &mut Instance>) {
        (
            InterfaceView {
                name: &self.name,
                system: &mut self.system,
                statistics: &mut self.statistics,
                tx: &self.tx,
                shared: &self.shared,
            },
            self.vrrp_v2_instances
                .values_mut()
                .chain(self.vrrp_v3_instances_ipv4.values_mut())
                .chain(self.vrrp_v3_instances_ipv6.values_mut()),
        )
    }

    pub(crate) fn as_view(&mut self) -> InterfaceView<'_> {
        InterfaceView {
            name: &self.name,
            system: &mut self.system,
            statistics: &mut self.statistics,
            tx: &self.tx,
            shared: &self.shared,
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
        Interface {
            name,
            system: Default::default(),
            vrrp_v2_instances: Default::default(),
            vrrp_v3_instances_ipv4: Default::default(),
            vrrp_v3_instances_ipv6: Default::default(),
            statistics: Default::default(),
            tx,
            shared,
        }
    }

    async fn init(&mut self) {
        // Request system information about all interfaces.
        self.tx.ibus.interface_sub(None, None);
    }

    async fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let Err(error) = process_ibus_msg(self, msg).await {
            error.log();
        }
    }

    fn process_protocol_msg(&mut self, msg: ProtocolInputMsg) {
        if let Err(error) = match msg {
            // Received network packet.
            ProtocolInputMsg::VrrpNetRxPacket(msg) => {
                events::process_vrrp_packet(self, msg.src, msg.packet)
            }
            // Master down timer.
            ProtocolInputMsg::MasterDownTimer(msg) => {
                events::handle_master_down_timer(self, msg.vrid, msg.version)
            }
        } {
            error.log();
        }
    }

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (vrrp_net_packet_rxp, vrrp_net_packet_rxc) = mpsc::channel(4);
        let (master_down_timerp, master_down_timerc) = mpsc::channel(4);

        let tx = ProtocolInputChannelsTx {
            vrrp_net_packet_tx: vrrp_net_packet_rxp,
            master_down_timer_tx: master_down_timerp,
        };
        let rx = ProtocolInputChannelsRx {
            vrrp_net_packet_rx: vrrp_net_packet_rxc,
            master_down_timer_rx: master_down_timerc,
        };

        (tx, rx)
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests/conformance", env!("CARGO_MANIFEST_DIR"),)
    }
}

// ===== impl ProtocolInputChannelsRx =====

#[async_trait]
impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        tokio::select! {
            biased;
            msg = self.vrrp_net_packet_rx.recv() => {
                msg.map(ProtocolInputMsg::VrrpNetRxPacket)
            }
            msg = self.master_down_timer_rx.recv() => {
                msg.map(ProtocolInputMsg::MasterDownTimer)
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
            southbound::rx::process_iface_update(interface, msg);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            southbound::rx::process_addr_add(interface, msg);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            southbound::rx::process_addr_del(interface, msg);
        }
        // Ignore other events.
        _ => {}
    }

    Ok(())
}
