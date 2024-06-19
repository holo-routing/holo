//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;

use holo_utils::socket::{AsyncFd, Socket};
//use std::time::Duration;
use holo_utils::task::Task;
use holo_utils::{Sender, UnboundedReceiver, UnboundedSender};
use tracing::{debug_span, Instrument};

use crate::debug::Debug;
//use crate::network;

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
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};

    use crate::packet::{DecodeError, VRRPPacket};

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
            pub packet: Result<VRRPPacket, DecodeError>,
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
        pub struct NetTxPacketMsg {
            pub packet: VRRPPacket,
            pub src: IpAddr,
            pub dst: IpAddr,
        }
    }
}

// ===== VRRP tasks =====

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

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                //let _ = network::read_loop(socket, net_packet_rxp).await;
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

        let span = tracing::span::Span::current();
        Task::spawn(
            async move {
                let _span_enter = span.enter();
                //network::write_loop(socket, net_packet_txc).await;
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
