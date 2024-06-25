//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
//use std::time::Duration;
use holo_utils::task::Task;
use holo_utils::{Sender, UnboundedReceiver};
use tracing::{debug_span, Instrument};

use crate::network;

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
//                      net_rx (Nx) -> |   instance   | -> (Nx) net_tx
//                                     |              |
//                                     +--------------+
//                              ibus_tx (1x) | ^ (1x) ibus_rx
//                                           | |
//                                           V |
//                                     +--------------+
//                                     |     ibus     |
//                                     +--------------+
//

// BGP inter-task message types.
pub mod messages {
    use std::net::IpAddr;

    use serde::{Deserialize, Serialize};

    use crate::packet::{DecodeError, VrrpPacket};

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            NetRxPacket(NetRxPacketMsg),
            // TODO
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NetRxPacketMsg {
            pub src: IpAddr,
            pub packet: Result<VrrpPacket, DecodeError>,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {
            NetTxPacket(NetTxPacketMsg),
        }

        #[derive(Clone, Debug, Serialize)]
        pub enum NetTxPacketMsg {
            Vrrp {
                packet: VrrpPacket,
                src: IpAddr,
                dst: IpAddr,
            },
            Arp {
                // TODO
            },
        }
    }
}

// ===== VRRP tasks =====

// Network Rx task.
pub(crate) fn net_rx(
    socket_vrrp: Arc<AsyncFd<Socket>>,
    net_packet_rxp: &Sender<messages::input::NetRxPacketMsg>,
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
                let _ = network::read_loop(socket_vrrp, net_packet_rxp).await;
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
