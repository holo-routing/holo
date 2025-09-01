//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::{Arc, atomic};
use std::time::Duration;

use holo_utils::socket::{OwnedReadHalf, OwnedWriteHalf, TcpListener};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;
use tracing::{Instrument, debug_span, error};

use crate::debug::Debug;
use crate::error::NbrRxError;
use crate::neighbor::{Neighbor, fsm};
use crate::packet::message::{DecodeCxt, EncodeCxt, KeepaliveMsg, Message};
use crate::{network, policy};

//
// BGP tasks diagram:
//                                     +--------------+
//                                     |  northbound  |
//                                     +--------------+
//                                           | ^
//                                           | |
//                        northbound_rx (1x) V | (1x) northbound_tx
//                                     +--------------+
//                                     |              |
//                tcp_listener (1x) -> |              |
//                 tcp_connect (Nx) -> |              | -> (Nx) nbr_tx
//                      nbr_rx (Nx) -> |              | -> (Nx) nbr_kalive_interval
//                   nbr_timer (Nx) -> |   instance   |
//                                     |              |
//                policy_apply (Nx) -> |              | -> (Nx) policy_apply
// schedule_decision_process (0/1x) -> |              |
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
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    use std::sync::Arc;

    use holo_utils::bgp::AfiSafi;
    use holo_utils::policy::{
        DefaultPolicyType, MatchSets, Policy, PolicyResult, PolicyType,
    };
    use holo_utils::socket::{TcpConnInfo, TcpStream};
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Serialize};

    use crate::error::NbrRxError;
    use crate::neighbor::fsm;
    use crate::packet::message::{Message, NegotiatedCapability};
    use crate::policy::RoutePolicyInfo;

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            TcpAccept(TcpAcceptMsg),
            TcpConnect(TcpConnectMsg),
            NbrRx(NbrRxMsg),
            NbrTimer(NbrTimerMsg),
            PolicyResult(PolicyResultMsg),
            TriggerDecisionProcess(()),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TcpAcceptMsg {
            #[serde(skip)]
            pub stream: Option<TcpStream>,
            pub conn_info: TcpConnInfo,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TcpConnectMsg {
            #[serde(skip)]
            pub stream: Option<TcpStream>,
            pub conn_info: TcpConnInfo,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NbrRxMsg {
            pub nbr_addr: IpAddr,
            pub msg: Result<Message, NbrRxError>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NbrTimerMsg {
            pub nbr_addr: IpAddr,
            pub timer: fsm::Timer,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub enum PolicyResultMsg {
            Neighbor {
                policy_type: PolicyType,
                nbr_addr: IpAddr,
                afi_safi: AfiSafi,
                routes: Vec<(IpNetwork, PolicyResult<RoutePolicyInfo>)>,
            },
            Redistribute {
                afi_safi: AfiSafi,
                prefix: IpNetwork,
                result: PolicyResult<RoutePolicyInfo>,
            },
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
            NbrTx(NbrTxMsg),
            PolicyApply(PolicyApplyMsg),
        }

        #[derive(Debug, Serialize)]
        pub enum NbrTxMsg {
            SendMessage {
                nbr_addr: IpAddr,
                msg: Message,
            },
            SendMessageList {
                nbr_addr: IpAddr,
                msg_list: Vec<Message>,
            },
            UpdateCapabilities(BTreeSet<NegotiatedCapability>),
        }

        #[derive(Debug, Serialize)]
        pub enum PolicyApplyMsg {
            Neighbor {
                policy_type: PolicyType,
                nbr_addr: IpAddr,
                afi_safi: AfiSafi,
                routes: Vec<(IpNetwork, RoutePolicyInfo)>,
                #[serde(skip)]
                policies: Vec<Arc<Policy>>,
                #[serde(skip)]
                match_sets: Arc<MatchSets>,
                #[serde(skip)]
                default_policy: DefaultPolicyType,
            },
            Redistribute {
                afi_safi: AfiSafi,
                prefix: IpNetwork,
                route: RoutePolicyInfo,
                #[serde(skip)]
                policies: Vec<Arc<Policy>>,
                #[serde(skip)]
                match_sets: Arc<MatchSets>,
                #[serde(skip)]
                default_policy: DefaultPolicyType,
            },
        }
    }
}

// ===== BGP tasks =====

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
                let _ = network::listen_loop(session_socket, tcp_acceptp).await;
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
    tcp_connectp: &Sender<messages::input::TcpConnectMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span = debug_span!("neighbor", addr = %nbr.remote_addr);
        let _span_guard = span.enter();

        let remote_addr = nbr.remote_addr;
        let local_addr = nbr.config.transport.local_addr;
        let ttl = nbr.tx_ttl();
        let ttl_security = nbr.config.transport.ttl_security;
        let tcp_mss = nbr.config.transport.tcp_mss;
        let tcp_password = nbr.config.transport.md5_key.clone();
        let tcp_connectp = tcp_connectp.clone();
        Task::spawn(
            async move {
                loop {
                    let result = network::connect(
                        remote_addr,
                        local_addr,
                        ttl,
                        ttl_security,
                        tcp_mss,
                        &tcp_password,
                    )
                    .await;

                    match result {
                        Ok((stream, conn_info)) => {
                            // Send message to the parent BGP task.
                            let msg = messages::input::TcpConnectMsg {
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
    cxt: DecodeCxt,
    read_half: OwnedReadHalf,
    nbr_msg_rxp: &Sender<messages::input::NbrRxMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("neighbor", addr = %nbr.remote_addr);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let nbr_addr = nbr.remote_addr;
        let nbr_msg_rxp = nbr_msg_rxp.clone();

        // Spawn a supervised task for this neighbor.
        //
        // The TCP read loop runs inside an inner supervised task, which lets us
        // catch panics (for example, from malformed or malicious input) and
        // handle them gracefully. Rather than propagating the panic, we treat
        // it as if the TCP connection was closed, containing the failure.
        Task::spawn(
            async move {
                let worker_task = {
                    let nbr_msg_rxp = nbr_msg_rxp.clone();
                    Task::spawn(async move {
                        let _ = network::nbr_read_loop(
                            read_half,
                            nbr_addr,
                            cxt,
                            nbr_msg_rxp,
                        )
                        .await;
                    })
                };
                if let Err(error) = worker_task.await
                    && error.is_panic()
                {
                    error!(%error, "task panicked");
                    let msg = messages::input::NbrRxMsg {
                        nbr_addr,
                        msg: Err(NbrRxError::TcpConnClosed),
                    };
                    let _ = nbr_msg_rxp.send(msg).await;
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
    cxt: EncodeCxt,
    write_half: OwnedWriteHalf,
    mut msg_txc: UnboundedReceiver<messages::output::NbrTxMsg>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg,
    >,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("neighbor", addr = %nbr.remote_addr);
        let _span1_guard = span1.enter();
        let span2 = debug_span!("output");
        let _span2_guard = span2.enter();

        Task::spawn(
            async move {
                network::nbr_write_loop(write_half, cxt, msg_txc).await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        let proto_output_tx = proto_output_tx.clone();
        Task::spawn(async move {
            // Relay message to the test framework.
            while let Some(msg) = msg_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NbrTx(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Neighbor timer task.
pub(crate) fn nbr_timer(
    nbr: &Neighbor,
    timer: fsm::Timer,
    seconds: u16,
    nbr_timerp: &Sender<messages::input::NbrTimerMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let nbr_timerp = nbr_timerp.clone();
        let nbr_addr = nbr.remote_addr;

        TimeoutTask::new(
            Duration::from_secs(seconds.into()),
            move || async move {
                let msg = messages::input::NbrTimerMsg { nbr_addr, timer };
                let _ = nbr_timerp.send(msg).await;
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Send periodic keepalive messages.
pub(crate) fn nbr_kalive_interval(
    nbr: &Neighbor,
    interval: u16,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let msg_txp = nbr.msg_txp.as_ref().unwrap().clone();
        let nbr_addr = nbr.remote_addr;
        let msg_counter = nbr.statistics.msgs_sent.total.clone();
        let trace_opts = nbr.config.trace_opts.packets_resolved.clone();

        IntervalTask::new(
            Duration::from_secs(interval.into()),
            false,
            move || {
                let msg_txp = msg_txp.clone();
                let msg_counter = msg_counter.clone();
                let trace_opts = trace_opts.clone();

                async move {
                    let msg = Message::Keepalive(KeepaliveMsg {});
                    if trace_opts.load().tx(&msg) {
                        Debug::NbrMsgTx(&nbr_addr, &msg).log();
                    }

                    let msg = messages::output::NbrTxMsg::SendMessage {
                        nbr_addr,
                        msg,
                    };
                    let _ = msg_txp.send(msg);
                    msg_counter.fetch_add(1, atomic::Ordering::Relaxed);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Policy processing task.
#[cfg_attr(not(feature = "testing"), allow(unused_mut))]
pub(crate) fn policy_apply(
    policy_applyc: crossbeam_channel::Receiver<
        messages::output::PolicyApplyMsg,
    >,
    policy_resultp: &UnboundedSender<messages::input::PolicyResultMsg>,
    #[cfg(feature = "testing")] proto_output_tx: &Sender<
        messages::ProtocolOutputMsg,
    >,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let policy_resultp = policy_resultp.clone();
        Task::spawn_blocking(move || {
            while let Ok(msg) = policy_applyc.recv() {
                match msg {
                    messages::output::PolicyApplyMsg::Neighbor {
                        policy_type,
                        nbr_addr,
                        afi_safi,
                        routes,
                        policies,
                        match_sets,
                        default_policy,
                    } => {
                        policy::neighbor_apply(
                            policy_type,
                            nbr_addr,
                            afi_safi,
                            routes,
                            &policies,
                            &match_sets,
                            default_policy,
                            &policy_resultp,
                        );
                    }
                    messages::output::PolicyApplyMsg::Redistribute {
                        afi_safi,
                        prefix,
                        route,
                        policies,
                        match_sets,
                        default_policy,
                    } => {
                        policy::redistribute_apply(
                            afi_safi,
                            prefix,
                            route,
                            &policies,
                            &match_sets,
                            default_policy,
                            &policy_resultp,
                        );
                    }
                }
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn_blocking(move || {})
    }
}

// Timeout to trigger the decision process.
pub(crate) fn schedule_decision_process(
    decision_processp: &Sender<()>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let decision_processp = decision_processp.clone();
        let timeout = Duration::from_millis(100);
        TimeoutTask::new(timeout, move || async move {
            let _ = decision_processp.send(()).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
