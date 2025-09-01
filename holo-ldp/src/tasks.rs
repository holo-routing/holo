//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU32, AtomicU64};
use std::time::Duration;

use holo_utils::socket::{
    OwnedReadHalf, OwnedWriteHalf, TcpListener, UdpSocket,
};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tokio::time::sleep;
use tracing::{Instrument, debug_span, error};

use crate::collections::AdjacencyId;
use crate::debug::Debug;
use crate::discovery::TargetedNbr;
use crate::error::Error;
use crate::instance::InstanceState;
use crate::interface::Interface;
use crate::neighbor::{Neighbor, NeighborFlags};
use crate::network;

//
// LDP tasks diagram:
//                                +--------------+
//                                |  northbound  |
//                                +--------------+
//                                      | ^
//                                      | |
//                   northbound_rx (1x) V | (1x) northbound_tx
//                                +--------------+
//     basic_discovery_rx (1x) -> |              | -> (Nx) iface_hello_interval
//  extended_discovery_rx (1x) -> |              | -> (Nx) tnbr_hello_interval
//            adj_timeout (Nx) -> |              |
//                                |              |
//           tcp_listener (1x) -> |   instance   |
//            tcp_connect (Nx) -> |              |
//                 nbr_rx (Nx) -> |              | -> (Nx) nbr_tx
//     nbr_kalive_timeout (Nx) -> |              | -> (Nx) nbr_kalive_interval
//    nbr_backoff_timeout (Nx) -> |              |
//                                +--------------+
//                         ibus_tx (1x) | ^ (1x) ibus_rx
//                                      | |
//                                      V |
//                                +--------------+
//                                |     ibus     |
//                                +--------------+
//

// LDP inter-task message types.
pub mod messages {
    use std::net::{IpAddr, Ipv4Addr};

    use holo_utils::socket::{TcpConnInfo, TcpStream};
    use serde::{Deserialize, Serialize};

    use crate::collections::{AdjacencyId, NeighborId};
    use crate::error::Error;
    use crate::packet::{DecodeError, Message, Pdu};

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            UdpRxPdu(UdpRxPduMsg),
            AdjTimeout(AdjTimeoutMsg),
            TcpAccept(TcpAcceptMsg),
            TcpConnect(TcpConnectMsg),
            NbrRxPdu(NbrRxPduMsg),
            NbrKaTimeout(NbrKaTimeoutMsg),
            NbrBackoffTimeout(NbrBackoffTimeoutMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct UdpRxPduMsg {
            pub src_addr: IpAddr,
            pub multicast: bool,
            pub pdu: Result<Pdu, DecodeError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct AdjTimeoutMsg {
            pub adj_id: AdjacencyId,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TcpAcceptMsg {
            #[serde(skip)]
            pub stream: Option<TcpStream>,
            pub conn_info: TcpConnInfo,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TcpConnectMsg {
            pub nbr_id: NeighborId,
            #[serde(skip)]
            pub stream: Option<TcpStream>,
            pub conn_info: TcpConnInfo,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NbrRxPduMsg {
            pub nbr_id: NeighborId,
            pub pdu: Result<Pdu, Error>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NbrKaTimeoutMsg {
            pub nbr_id: NeighborId,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NbrBackoffTimeoutMsg {
            pub lsr_id: Ipv4Addr,
        }

        impl TcpAcceptMsg {
            pub(crate) fn stream(&mut self) -> TcpStream {
                #[cfg(not(feature = "testing"))]
                {
                    self.stream.take().unwrap()
                }
                #[cfg(feature = "testing")]
                {
                    Default::default()
                }
            }
        }

        impl TcpConnectMsg {
            pub(crate) fn stream(&mut self) -> TcpStream {
                #[cfg(not(feature = "testing"))]
                {
                    self.stream.take().unwrap()
                }
                #[cfg(feature = "testing")]
                {
                    Default::default()
                }
            }
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {
            NbrTxPdu(NbrTxPduMsg),
        }

        #[derive(Debug, Serialize)]
        pub struct NbrTxPduMsg {
            pub nbr_id: NeighborId,
            pub msg: Message,
            pub flush: bool,
        }
    }
}

// ===== LDP tasks =====

// UDP basic discovery Rx task.
pub(crate) fn basic_discovery_rx(
    disc_socket: &Arc<UdpSocket>,
    udp_pdu_rxp: &Sender<messages::input::UdpRxPduMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("discovery");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let disc_socket = disc_socket.clone();
        let udp_pdu_rxp = udp_pdu_rxp.clone();

        Task::spawn_supervised(move || {
            let disc_socket = disc_socket.clone();
            let udp_pdu_rxp = udp_pdu_rxp.clone();
            async move {
                let _ = network::udp::read_loop(disc_socket, true, udp_pdu_rxp)
                    .await;
            }
            .in_current_span()
        })
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// UDP extended discovery Rx task.
pub(crate) fn extended_discovery_rx(
    edisc_socket: &Arc<UdpSocket>,
    udp_pdu_rxp: &Sender<messages::input::UdpRxPduMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("discovery");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let edisc_socket = edisc_socket.clone();
        let udp_pdu_rxp = udp_pdu_rxp.clone();

        Task::spawn_supervised(move || {
            let edisc_socket = edisc_socket.clone();
            let udp_pdu_rxp = udp_pdu_rxp.clone();
            async move {
                let _ =
                    network::udp::read_loop(edisc_socket, false, udp_pdu_rxp)
                        .await;
            }
            .in_current_span()
        })
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Send periodic LDP link hello messages.
pub(crate) fn iface_hello_interval(
    interface: &Interface,
    disc_socket: &Arc<UdpSocket>,
    instance_state: &InstanceState,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("interface", name = %interface.name);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("discovery");
        let _span2_guard = span2.enter();
        let span3 = debug_span!("output");
        let _span3_guard = span3.enter();

        let disc_socket = disc_socket.clone();
        let router_id = instance_state.router_id;
        let msg_id = instance_state.msg_id.clone();
        let hello = interface.generate_hello(instance_state);

        IntervalTask::new(
            Duration::from_secs(interface.config.hello_interval.into()),
            true,
            move || {
                let disc_socket = disc_socket.clone();
                let msg_id = msg_id.clone();
                let hello = hello.clone();

                Interface::send_hello(disc_socket, router_id, msg_id, hello)
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Send periodic LDP targeted hello messages.
pub(crate) fn tnbr_hello_interval(
    tnbr: &TargetedNbr,
    instance_state: &InstanceState,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("targeted-nbr", address = %tnbr.addr);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("discovery");
        let _span2_guard = span2.enter();
        let span3 = debug_span!("output");
        let _span3_guard = span3.enter();

        let edisc_socket = instance_state.ipv4.edisc_socket.clone();
        let addr = tnbr.addr;
        let router_id = instance_state.router_id;
        let msg_id = instance_state.msg_id.clone();
        let hello = tnbr.generate_hello(instance_state);

        IntervalTask::new(
            Duration::from_secs(tnbr.config.hello_interval.into()),
            true,
            move || {
                let edisc_socket = edisc_socket.clone();
                let msg_id = msg_id.clone();
                let hello = hello.clone();

                TargetedNbr::send_hello(
                    edisc_socket,
                    addr,
                    router_id,
                    msg_id,
                    hello,
                )
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Hello adjacency timeout task.
pub(crate) fn adj_timeout(
    adj_id: AdjacencyId,
    holdtime: Duration,
    adj_timeoutp: &Sender<messages::input::AdjTimeoutMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let adj_timeoutp = adj_timeoutp.clone();
        TimeoutTask::new(holdtime, move || async move {
            let msg = messages::input::AdjTimeoutMsg { adj_id };
            let _ = adj_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// TCP listening task.
pub(crate) fn tcp_listener(
    session_socket: &Arc<TcpListener>,
    tcp_acceptp: &Sender<messages::input::TcpAcceptMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("session");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let session_socket = session_socket.clone();
        let tcp_acceptp = tcp_acceptp.clone();
        Task::spawn(
            async move {
                let _ = network::tcp::listen_loop(session_socket, tcp_acceptp)
                    .await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// TCP connect task.
pub(crate) fn tcp_connect(
    nbr: &Neighbor,
    local_addr: IpAddr,
    password: Option<&str>,
    tcp_connectp: &Sender<messages::input::TcpConnectMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span = debug_span!("neighbor", lsr_id = %nbr.lsr_id);
        let _span_guard = span.enter();

        let nbr_id = nbr.id;
        let remote_addr = nbr.trans_addr;
        let gtsm = nbr.flags.contains(NeighborFlags::GTSM);
        let password = password.map(String::from);
        let tcp_connectp = tcp_connectp.clone();
        Task::spawn(
            async move {
                loop {
                    let result = network::tcp::connect(
                        local_addr,
                        remote_addr,
                        gtsm,
                        &password,
                    )
                    .await;

                    match result {
                        Ok((stream, conn_info)) => {
                            // Send message to the parent LDP task.
                            let msg = messages::input::TcpConnectMsg {
                                nbr_id,
                                stream: Some(stream),
                                conn_info,
                            };
                            let _ = tcp_connectp.send(msg).await;
                            return;
                        }
                        Err(error) => {
                            error.log();
                            // Wait one second before trying again.
                            sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Neighbor TCP Rx task.
pub(crate) fn nbr_rx(
    nbr: &Neighbor,
    read_half: OwnedReadHalf,
    nbr_pdu_rxp: &Sender<messages::input::NbrRxPduMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("neighbor", lsr_id = %nbr.lsr_id);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let nbr_id = nbr.id;
        let nbr_lsr_id = nbr.lsr_id;
        let nbr_raddr = nbr.conn_info.as_ref().unwrap().remote_addr;
        let nbr_pdu_rxp = nbr_pdu_rxp.clone();

        // Spawn a supervised task for this neighbor.
        //
        // The TCP read loop runs inside an inner supervised task, which lets us
        // catch panics (for example, from malformed or malicious input) and
        // handle them gracefully. Rather than propagating the panic, we treat
        // it as if the TCP connection was closed, containing the failure.
        Task::spawn(
            async move {
                let worker_task = {
                    let nbr_pdu_rxp = nbr_pdu_rxp.clone();
                    Task::spawn(async move {
                        let _ = network::tcp::nbr_read_loop(
                            read_half,
                            nbr_id,
                            nbr_lsr_id,
                            nbr_raddr,
                            nbr_pdu_rxp,
                        )
                        .await;
                    })
                };
                if let Err(error) = worker_task.await
                    && error.is_panic()
                {
                    error!(%error, "task panicked");
                    let msg = messages::input::NbrRxPduMsg {
                        nbr_id,
                        pdu: Err(Error::TcpConnClosed(nbr_lsr_id)),
                    };
                    let _ = nbr_pdu_rxp.send(msg).await;
                }
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Neighbor TCP Tx task.
#[cfg_attr(not(feature = "testing"), allow(unused_mut))]
pub(crate) fn nbr_tx(
    nbr: &Neighbor,
    local_lsr_id: Ipv4Addr,
    write_half: OwnedWriteHalf,
    mut pdu_txc: UnboundedReceiver<messages::output::NbrTxPduMsg>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg,
    >,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("neighbor", lsr_id = %nbr.lsr_id);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("output");
        let _span2_guard = span2.enter();

        let max_pdu_len = nbr.max_pdu_len;
        Task::spawn(
            async move {
                network::tcp::nbr_write_loop(
                    write_half,
                    local_lsr_id,
                    max_pdu_len,
                    pdu_txc,
                )
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
            while let Some(msg) = pdu_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NbrTxPdu(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Send periodic keepalive messages.
pub(crate) fn nbr_kalive_interval(
    nbr: &Neighbor,
    msg_id: &Arc<AtomicU32>,
    keepalive_counter: &Arc<AtomicU64>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let nbr_id = nbr.id;
        let lsr_id = nbr.lsr_id;
        let msg_id = msg_id.clone();
        let pdu_txp = nbr.pdu_txp.as_ref().unwrap().clone();
        let keepalive_counter = keepalive_counter.clone();

        IntervalTask::new(
            Duration::from_secs(nbr.kalive_interval.into()),
            false,
            move || {
                let msg_id = msg_id.clone();
                let pdu_txp = pdu_txp.clone();
                let keepalive_counter = keepalive_counter.clone();

                async move {
                    let msg = Neighbor::generate_keepalive(&msg_id);
                    Debug::NbrMsgTx(&lsr_id, &msg).log();

                    let flush = true;
                    let msg =
                        messages::output::NbrTxPduMsg { nbr_id, msg, flush };
                    let _ = pdu_txp.send(msg);
                    keepalive_counter.fetch_add(1, atomic::Ordering::Relaxed);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Neighbor keepalive timeout task.
pub(crate) fn nbr_kalive_timeout(
    nbr: &Neighbor,
    nbr_ka_timeoutp: &Sender<messages::input::NbrKaTimeoutMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let nbr_ka_timeoutp = nbr_ka_timeoutp.clone();
        let nbr_id = nbr.id;

        TimeoutTask::new(
            Duration::from_secs(nbr.kalive_holdtime_negotiated.unwrap().into()),
            move || async move {
                let msg = messages::input::NbrKaTimeoutMsg { nbr_id };
                let _ = nbr_ka_timeoutp.send(msg).await;
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Neighbor initialization backoff timeout task.
pub(crate) fn nbr_backoff_timeout(
    nbr: &mut Neighbor,
    nbr_backoff_timeoutp: &Sender<messages::input::NbrBackoffTimeoutMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let nbr_backoff_timeoutp = nbr_backoff_timeoutp.clone();
        let lsr_id = nbr.lsr_id;

        //
        // RFC 5036 - Section 2.5.3:
        // "The session establishment setup attempt following a NAK'd
        // Initialization message MUST be delayed no less than 15
        // seconds, and subsequent delays MUST grow to a maximum delay
        // of no less than 2 minutes".
        //
        let timeout = match nbr.init_attempts {
            0 => 15,
            1 => 30,
            2 => 60,
            _ => 120,
        };
        nbr.init_attempts = nbr.init_attempts.saturating_add(1);

        TimeoutTask::new(Duration::from_secs(timeout), move || async move {
            let msg = messages::input::NbrBackoffTimeoutMsg { lsr_id };
            let _ = nbr_backoff_timeoutp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
