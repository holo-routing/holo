//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;
use std::time::Duration;

use holo_utils::socket::UdpSocket;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tracing::{Instrument, debug_span};

use crate::network;
use crate::packet::AuthCtx;
use crate::version::Version;

//
// RIP tasks diagram:
//                                 +--------------+
//                                 |  northbound  |
//                                 +--------------+
//                                       | ^
//                                       | |
//                    northbound_rx (1x) V | (1x) northbound_tx
//                                 +--------------+
//                                 |              |
//                  udp_rx (Nx) -> |              |
//        initial_update (0/1x) -> |              |
//         update_interval (1x) -> |              |
//         triggered_upd (0/1x) -> |   instance   | -> (Nx) udp_tx
// triggered_upd_timeout (0/1x) -> |              |
//             nbr_timeout (Nx) -> |              |
//           route_timeout (Nx) -> |              |
//        route_gc_timeout (Nx) -> |              |
//                                 +--------------+
//                          ibus_tx (1x) | ^ (1x) ibus_rx
//                                       | |
//                                       V |
//                                 +--------------+
//                                 |     ibus     |
//                                 +--------------+
//

// RIP inter-task message types.
pub mod messages {
    use serde::{Deserialize, Serialize};

    use crate::network::SendDestination;
    use crate::version::Version;

    // Type aliases.
    pub type ProtocolInputMsg<V> = input::ProtocolMsg<V>;
    pub type ProtocolOutputMsg<V> = output::ProtocolMsg<V>;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub enum ProtocolMsg<V: Version> {
            UdpRxPdu(UdpRxPduMsg<V>),
            InitialUpdate(InitialUpdateMsg),
            UpdateInterval(UpdateIntervalMsg),
            TriggeredUpd(TriggeredUpdMsg),
            TriggeredUpdTimeout(TriggeredUpdTimeoutMsg),
            NbrTimeout(NbrTimeoutMsg<V>),
            RouteTimeout(RouteTimeoutMsg<V>),
            RouteGcTimeout(RouteGcTimeoutMsg<V>),
        }

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct UdpRxPduMsg<V: Version> {
            pub src: V::SocketAddr,
            pub pdu: Result<V::Pdu, V::PduDecodeError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct InitialUpdateMsg {}

        #[derive(Debug, Deserialize, Serialize)]
        pub struct UpdateIntervalMsg {}

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TriggeredUpdMsg {}

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TriggeredUpdTimeoutMsg {}

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct NbrTimeoutMsg<V: Version> {
            pub addr: V::IpAddr,
        }

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct RouteTimeoutMsg<V: Version> {
            pub prefix: V::IpNetwork,
        }

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct RouteGcTimeoutMsg<V: Version> {
            pub prefix: V::IpNetwork,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        #[serde(bound = "V: Version")]
        pub enum ProtocolMsg<V: Version> {
            UdpTxPdu(UdpTxPduMsg<V>),
        }

        #[derive(Debug, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct UdpTxPduMsg<V: Version> {
            pub dst: SendDestination<V::SocketAddr>,
            pub pdu: V::Pdu,
        }
    }
}

// ===== RIP tasks =====

// UDP Rx task.
pub(crate) fn udp_rx<V>(
    socket: &Arc<UdpSocket>,
    auth: Option<AuthCtx>,
    udp_pdu_rxp: &Sender<messages::input::UdpRxPduMsg<V>>,
) -> Task<()>
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let socket = socket.clone();
        let udp_pdu_rxp = udp_pdu_rxp.clone();

        Task::spawn_supervised(move || {
            let socket = socket.clone();
            let auth = auth.clone();
            let udp_pdu_rxp = udp_pdu_rxp.clone();
            async move {
                let _ = network::read_loop(socket, auth, udp_pdu_rxp).await;
            }
            .in_current_span()
        })
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// UDP Tx task.
#[allow(unused_mut)]
pub(crate) fn udp_tx<V>(
    socket: &Arc<UdpSocket>,
    auth: Option<AuthCtx>,
    mut udp_pdu_txc: UnboundedReceiver<messages::output::UdpTxPduMsg<V>>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg<V>,
    >,
) -> Task<()>
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("output");
        let _span2_guard = span2.enter();

        let socket = socket.clone();
        Task::spawn(
            async move {
                network::write_loop(socket, auth, udp_pdu_txc).await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        let proto_output_tx = proto_output_tx.clone();
        Task::spawn(async move {
            // Relay message to the test framework.
            while let Some(msg) = udp_pdu_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::UdpTxPdu(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Initial RIP update.
pub(crate) fn initial_update(
    initial_updatep: &Sender<messages::input::InitialUpdateMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        // The initial RIP update needs to be delayed for a few seconds to give
        // time for all connected routes to be received from the southbound
        // layer.
        let timeout = Duration::from_secs(2);
        let initial_updatep = initial_updatep.clone();
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::InitialUpdateMsg {};
            let _ = initial_updatep.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// RIP route update interval.
pub(crate) fn update_interval(
    interval: Duration,
    update_intervalp: &Sender<messages::input::UpdateIntervalMsg>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let update_intervalp = update_intervalp.clone();
        IntervalTask::new(interval, false, move || {
            let update_intervalp = update_intervalp.clone();
            async move {
                let msg = messages::input::UpdateIntervalMsg {};
                let _ = update_intervalp.send(msg).await;
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Triggered update timeout.
pub(crate) fn triggered_upd_timeout(
    timeout: Duration,
    triggered_upd_timeoutp: &Sender<messages::input::TriggeredUpdTimeoutMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let triggered_upd_timeoutp = triggered_upd_timeoutp.clone();
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::TriggeredUpdTimeoutMsg {};
            let _ = triggered_upd_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Neighbor timeout task.
pub(crate) fn nbr_timeout<V>(
    addr: V::IpAddr,
    timeout: Duration,
    nbr_timeoutp: &Sender<messages::input::NbrTimeoutMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let nbr_timeoutp = nbr_timeoutp.clone();
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::NbrTimeoutMsg { addr };
            let _ = nbr_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Route timeout task.
pub(crate) fn route_timeout<V>(
    prefix: V::IpNetwork,
    timeout: Duration,
    route_timeoutp: &Sender<messages::input::RouteTimeoutMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let route_timeoutp = route_timeoutp.clone();
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::RouteTimeoutMsg { prefix };
            let _ = route_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Route garbage-collection timeout task.
pub(crate) fn route_gc_timeout<V>(
    prefix: V::IpNetwork,
    timeout: Duration,
    route_gc_timeoutp: &Sender<messages::input::RouteGcTimeoutMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let route_gc_timeoutp = route_gc_timeoutp.clone();
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::RouteGcTimeoutMsg { prefix };
            let _ = route_gc_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
