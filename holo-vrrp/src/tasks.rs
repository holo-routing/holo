//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use holo_utils::{Sender, UnboundedReceiver, UnboundedSender};
use messages::input::MasterDownTimerMsg;
use messages::output::NetTxPacketMsg;
use tracing::{debug_span, Instrument};

use crate::instance::Instance;
use crate::interface::InterfaceSys;
use crate::network;
use crate::packet::VrrpPacket;

//
// VRRP tasks diagram:
//                                     +--------------+
//                                     |  northbound  |
//                                     +--------------+
//                                           | ^
//                                           | |
//                        northbound_rx (1x) V | (1x) northbound_tx
//                                     +--------------+
//                                     |              |
//                 vrrp_net_rx (Nx) -> |   instance   | -> (Nx) net_tx
//           master_down_timer (Nx) -> |              | -> (Nx) advertisement_interval
//                                     |              |
//                                     +--------------+
//                              ibus_tx (1x) | ^ (1x) ibus_rx
//                                           | |
//                                           V |
//                                     +--------------+
//                                     |     ibus     |
//                                     +--------------+
//

// VRRP inter-task message types.
pub mod messages {
    use serde::{Deserialize, Serialize};

    use crate::packet::{DecodeError, VrrpHdr};

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use std::net::Ipv4Addr;

        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            VrrpNetRxPacket(VrrpNetRxPacketMsg),
            MasterDownTimer(MasterDownTimerMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct VrrpNetRxPacketMsg {
            pub src: Ipv4Addr,
            pub packet: Result<VrrpHdr, DecodeError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct MasterDownTimerMsg {
            pub vrid: u8,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;
        use crate::packet::{ArpHdr, EthernetHdr, VrrpPacket};

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {
            NetTxPacket(NetTxPacketMsg),
        }

        #[derive(Clone, Debug, Serialize)]
        pub enum NetTxPacketMsg {
            Vrrp {
                packet: VrrpPacket,
            },
            Arp {
                vrid: u8,
                ifindex: u32,
                eth_hdr: EthernetHdr,
                arp_hdr: ArpHdr,
            },
        }
    }
}

// ===== VRRP tasks =====

// Network Rx task.
pub(crate) fn vrrp_net_rx(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    net_packet_rxp: &Sender<messages::input::VrrpNetRxPacketMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let net_packet_rxp = net_packet_rxp.clone();

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                let _ =
                    network::vrrp_read_loop(socket_vrrp, net_packet_rxp).await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Network Tx task.
#[allow(unused_mut)]
pub(crate) fn net_tx(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    socket_arp: Arc<AsyncFd<Socket>>,
    mut net_packet_txc: UnboundedReceiver<messages::output::NetTxPacketMsg>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg,
    >,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("output");
        let _span2_guard = span2.enter();

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                network::write_loop(socket_vrrp, socket_arp, net_packet_txc)
                    .await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        let proto_output_tx = proto_output_tx.clone();
        Task::spawn(async move {
            // Relay message to the test framework.
            while let Some(msg) = net_packet_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NetTxPacket(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Master down timer.
pub(crate) fn master_down_timer(
    instance: &mut Instance,
    duration: Duration,
    master_down_timer_rx: &Sender<MasterDownTimerMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let vrid = instance.vrid;
        let master_down_timer_rx = master_down_timer_rx.clone();

        TimeoutTask::new(duration, move || async move {
            let _ = master_down_timer_rx
                .send(messages::input::MasterDownTimerMsg { vrid })
                .await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Advertisement interval.
pub(crate) fn advertisement_interval(
    instance: &Instance,
    src_ip: Ipv4Addr,
    iface_system: &InterfaceSys,
    net_tx_packetp: &UnboundedSender<NetTxPacketMsg>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let packet = VrrpPacket {
            ip: instance.generate_ipv4_packet(src_ip),
            vrrp: instance.generate_vrrp_packet(iface_system),
        };
        let adv_sent = instance.state.statistics.adv_sent.clone();
        let net_tx_packetp = net_tx_packetp.clone();
        IntervalTask::new(
            Duration::from_secs(instance.config.advertise_interval as u64),
            true,
            move || {
                let adv_sent = adv_sent.clone();
                let packet = packet.clone();
                let net_tx_packetp = net_tx_packetp.clone();
                async move {
                    adv_sent.fetch_add(1, Ordering::Relaxed);
                    let msg = NetTxPacketMsg::Vrrp { packet };
                    let _ = net_tx_packetp.send(msg);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}
