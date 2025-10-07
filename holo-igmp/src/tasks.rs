//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::Task;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tracing::{Instrument, debug_span};

use crate::network;

//
// IGMP tasks diagram:
//                                     +--------------+
//                                     |  northbound  |
//                                     +--------------+
//                                           | ^
//                                           | |
//                        northbound_rx (1x) V | (1x) northbound_tx
//                                     +--------------+
//                                     |              |
//                      net_rx (Nx) -> |              | -> (Nx) net_tx
//                                     |   instance   |
//                                     |              |
//                                     |              |
//                                     +--------------+
//                              ibus_tx (1x) | ^ (1x) ibus_rx
//                                           | |
//                                           V |
//                                     +--------------+
//                                     |     ibus     |
//                                     +--------------+
//

// IGMP inter-task message types.
pub mod messages {
    use std::net::Ipv4Addr;

    use serde::{Deserialize, Serialize};

    use crate::packet::{DecodeResult, Packet};

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            NetRxPacket(NetRxPacketMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NetRxPacketMsg {
            pub ifindex: u32,
            pub src: Ipv4Addr,
            pub packet: DecodeResult<Packet>,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {
            NetTxPacket(NetTxPacketMsg),
        }

        #[derive(Debug, Serialize)]
        pub struct NetTxPacketMsg {
            #[cfg(feature = "testing")]
            pub ifname: String,
            pub dst: Ipv4Addr,
            pub packet: Packet,
        }
    }
}

// ===== IGMP tasks =====

// Network Rx task.
pub(crate) fn net_rx(
    socket: Arc<AsyncFd<Socket>>,
    net_packet_rxp: &Sender<messages::input::NetRxPacketMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let net_packet_rxp = net_packet_rxp.clone();

        Task::spawn(
            async move {
                let _ = network::read_loop(socket, net_packet_rxp).await;
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
    socket: Arc<AsyncFd<Socket>>,
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

        Task::spawn(
            async move {
                network::write_loop(socket, net_packet_txc).await;
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
