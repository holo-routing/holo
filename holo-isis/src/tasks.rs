//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::{Arc, atomic};
use std::time::Duration;

use arc_swap::ArcSwap;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tracing::{Instrument, debug_span};

use crate::adjacency::Adjacency;
use crate::collections::LspEntryId;
use crate::debug::LspPurgeReason;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, InterfaceType};
use crate::network::MulticastAddr;
use crate::northbound::configuration::TraceOptionPacketResolved;
use crate::packet::auth::AuthMethod;
use crate::packet::pdu::{Hello, Lsp, Pdu};
use crate::packet::{LevelNumber, LevelType, Levels};
use crate::{lsdb, network, spf};

//
// IS-IS tasks diagram:
//                                     +--------------+
//                                     |  northbound  |
//                                     +--------------+
//                                           | ^
//                                           | |
//                        northbound_rx (1x) V | (1x) northbound_tx
//                                     +--------------+
//                                     |              |
//                      net_rx (Nx) -> |              | -> (Nx) net_tx
//         adjacency_holdtimer (Nx) -> |              | -> (Nx) hello_interval
//        dis_initial_election (Nx) -> |              |
//               psnp_interval (Nx) -> |              |
//               csnp_interval (Nx) -> |   instance   |
//         lsp_originate_timer (Nx) -> |              | -> (Nx) lsp_rxmt_interval
//            lsp_expiry_timer (Nx) -> |              |
//            lsp_delete_timer (Nx) -> |              |
//           lsp_refresh_timer (Nx) -> |              |
//             spf_delay_timer (Nx) -> |              |
//                                     |              |
//                                     +--------------+
//                              ibus_tx (1x) | ^ (1x) ibus_rx
//                                           | |
//                                           V |
//                                     +--------------+
//                                     |     ibus     |
//                                     +--------------+
//

// IS-IS inter-task message types.
pub mod messages {
    use bytes::Bytes;
    use holo_utils::mac_addr::MacAddr;
    use serde::{Deserialize, Serialize};

    use crate::collections::{AdjacencyKey, InterfaceKey, LspEntryKey};
    use crate::debug::LspPurgeReason;
    use crate::network::MulticastAddr;
    use crate::packet::LevelNumber;
    use crate::packet::error::DecodeError;
    use crate::packet::pdu::Pdu;
    use crate::spf;

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub enum ProtocolMsg {
            NetRxPdu(NetRxPduMsg),
            AdjHoldTimer(AdjHoldTimerMsg),
            DisElection(DisElectionMsg),
            SendPsnp(SendPsnpMsg),
            SendCsnp(SendCsnpMsg),
            LspOriginate(LspOriginateMsg),
            LspPurge(LspPurgeMsg),
            LspDelete(LspDeleteMsg),
            LspRefresh(LspRefreshMsg),
            SpfDelayEvent(SpfDelayEventMsg),
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct NetRxPduMsg {
            pub iface_key: InterfaceKey,
            #[serde(default)]
            pub src: MacAddr,
            #[serde(default)]
            pub bytes: Bytes,
            pub pdu: Result<Pdu, DecodeError>,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub enum AdjHoldTimerMsg {
            Broadcast {
                iface_key: InterfaceKey,
                adj_key: AdjacencyKey,
                level: LevelNumber,
            },
            PointToPoint {
                iface_key: InterfaceKey,
            },
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct DisElectionMsg {
            pub iface_key: InterfaceKey,
            pub level: LevelNumber,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct SendPsnpMsg {
            pub iface_key: InterfaceKey,
            pub level: LevelNumber,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct SendCsnpMsg {
            pub iface_key: InterfaceKey,
            pub level: LevelNumber,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct LspOriginateMsg {}

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct LspPurgeMsg {
            pub level: LevelNumber,
            pub lse_key: LspEntryKey,
            pub reason: LspPurgeReason,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct LspDeleteMsg {
            pub level: LevelNumber,
            pub lse_key: LspEntryKey,
        }

        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct LspRefreshMsg {
            pub level: LevelNumber,
            pub lse_key: LspEntryKey,
        }
        #[derive(Debug)]
        #[derive(Deserialize, Serialize)]
        pub struct SpfDelayEventMsg {
            pub level: LevelNumber,
            pub event: spf::fsm::Event,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug)]
        #[derive(Serialize)]
        pub enum ProtocolMsg {
            NetTxPdu(NetTxPduMsg),
        }

        #[derive(Debug)]
        #[derive(Serialize)]
        pub struct NetTxPduMsg {
            pub pdu: Pdu,
            #[cfg(feature = "testing")]
            pub ifname: String,
            pub dst: MulticastAddr,
        }
    }
}

// ===== IS-IS tasks =====

// Network Rx task.
pub(crate) fn net_rx(
    socket: Arc<AsyncFd<Socket>>,
    broadcast: bool,
    hello_auth: Option<AuthMethod>,
    global_auth: Option<AuthMethod>,
    iface: &Interface,
    net_pdu_rxp: &Sender<messages::input::NetRxPduMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let span1 = debug_span!("network");
        let _span1_guard = span1.enter();
        let span2 = debug_span!("input");
        let _span2_guard = span2.enter();

        let iface_id = iface.id;
        let net_pdu_rxp = net_pdu_rxp.clone();

        Task::spawn_supervised(move || {
            let socket = socket.clone();
            let hello_auth = hello_auth.clone();
            let global_auth = global_auth.clone();
            let net_pdu_rxp = net_pdu_rxp.clone();
            async move {
                let _ = network::read_loop(
                    socket,
                    broadcast,
                    iface_id,
                    hello_auth,
                    global_auth,
                    net_pdu_rxp,
                )
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

// Network Tx task.
#[allow(unused_mut)]
pub(crate) fn net_tx(
    socket: Arc<AsyncFd<Socket>>,
    broadcast: bool,
    ifname: String,
    ifindex: u32,
    hello_padding: Option<u16>,
    hello_auth: Option<AuthMethod>,
    global_auth: Option<AuthMethod>,
    trace_opts: Arc<ArcSwap<TraceOptionPacketResolved>>,
    mut net_pdu_txc: UnboundedReceiver<messages::output::NetTxPduMsg>,
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
                network::write_loop(
                    socket,
                    broadcast,
                    ifname,
                    ifindex,
                    hello_padding,
                    hello_auth,
                    global_auth,
                    trace_opts,
                    net_pdu_txc,
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
            while let Some(msg) = net_pdu_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NetTxPdu(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Send periodic IS-IS Hello PDUs.
pub(crate) fn hello_interval(
    iface: &Interface,
    level_type: impl Into<LevelType>,
    hello: Hello,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let level_type = level_type.into();
        let interval = iface.config.hello_interval.get(level_type);
        let dst = iface.config.interface_type.multicast_addr(level_type);
        let packet_counters = &iface.state.packet_counters;
        let iih_out_counters = Levels {
            l1: packet_counters.get(LevelNumber::L1).iih_out.clone(),
            l2: packet_counters.get(LevelNumber::L2).iih_out.clone(),
        };
        let ext_seqnum_next = iface.state.ext_seqnum.1.clone();
        let net_tx_pdup = iface.state.net.as_ref().unwrap().net_tx_pdup.clone();
        IntervalTask::new(
            Duration::from_secs(interval.into()),
            true,
            move || {
                let mut hello = hello.clone();
                let net_tx_pdup = net_tx_pdup.clone();

                // Update packet counters.
                for level in level_type {
                    iih_out_counters
                        .get(level)
                        .fetch_add(1, atomic::Ordering::Relaxed);
                }

                // Update ESN TLV.
                if let Some(ext_seqnum) = &mut hello.tlvs.ext_seqnum {
                    ext_seqnum.get_mut().packet =
                        ext_seqnum_next.fetch_add(1, atomic::Ordering::Relaxed);
                }

                async move {
                    let msg = messages::output::NetTxPduMsg {
                        pdu: Pdu::Hello(hello),
                        dst,
                    };
                    let _ = net_tx_pdup.send(msg);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Adjacency hold timer.
pub(crate) fn adjacency_holdtimer(
    adj: &Adjacency,
    iface: &Interface,
    instance: &InstanceUpView<'_>,
    holdtime: u16,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(holdtime.into());
        let msg = match iface.config.interface_type {
            InterfaceType::Broadcast => {
                messages::input::AdjHoldTimerMsg::Broadcast {
                    iface_key: iface.id.into(),
                    adj_key: adj.id.into(),
                    level: adj.level_usage.into(),
                }
            }
            InterfaceType::PointToPoint => {
                messages::input::AdjHoldTimerMsg::PointToPoint {
                    iface_key: iface.id.into(),
                }
            }
        };
        let adj_holdtimerp = instance.tx.protocol_input.adj_holdtimer.clone();

        TimeoutTask::new(timeout, move || async move {
            let _ = adj_holdtimerp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// DIS initial election.
pub(crate) fn dis_initial_election(
    iface: &Interface,
    level: LevelNumber,
    instance: &InstanceUpView<'_>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let hello_interval = iface.config.hello_interval.get(level);
        let timeout = Duration::from_secs(hello_interval as u64 * 2);
        let iface_id = iface.id;
        let dis_electionp = instance.tx.protocol_input.dis_election.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::DisElectionMsg {
                iface_key: iface_id.into(),
                level,
            };
            let _ = dis_electionp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Send periodic IS-IS PSNP PDUs.
pub(crate) fn psnp_interval(
    iface: &Interface,
    level: LevelNumber,
    instance: &InstanceUpView<'_>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        const PSNP_INTERVAL: u64 = 2;

        let iface_id = iface.id;
        let send_psnpp = instance.tx.protocol_input.send_psnp.clone();
        IntervalTask::new(Duration::from_secs(PSNP_INTERVAL), true, move || {
            let send_psnpp = send_psnpp.clone();

            async move {
                let msg = messages::input::SendPsnpMsg {
                    iface_key: iface_id.into(),
                    level,
                };
                let _ = send_psnpp.send(msg);
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Send periodic IS-IS CSNP PDUs.
pub(crate) fn csnp_interval(
    iface: &Interface,
    level: LevelNumber,
    instance: &InstanceUpView<'_>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let interval = iface.config.csnp_interval;
        let iface_id = iface.id;
        let send_csnpp = instance.tx.protocol_input.send_csnp.clone();
        IntervalTask::new(
            Duration::from_secs(interval.into()),
            true,
            move || {
                let send_csnpp = send_csnpp.clone();

                async move {
                    let msg = messages::input::SendCsnpMsg {
                        iface_key: iface_id.into(),
                        level,
                    };
                    let _ = send_csnpp.send(msg);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Send periodic IS-IS LSP retransmissions.
pub(crate) fn lsp_rxmt_interval(
    iface: &Interface,
    lsp: Lsp,
    dst: MulticastAddr,
    interval: u16,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let pdu = Pdu::Lsp(lsp);
        let net_tx_pdup = iface.state.net.as_ref().unwrap().net_tx_pdup.clone();
        IntervalTask::new(
            Duration::from_secs(interval.into()),
            false,
            move || {
                let pdu = pdu.clone();
                let net_tx_pdup = net_tx_pdup.clone();

                async move {
                    let msg = messages::output::NetTxPduMsg { pdu, dst };
                    let _ = net_tx_pdup.send(msg);
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// LSP originate timer task.
pub(crate) fn lsp_originate_timer(
    lsp_originatep: &UnboundedSender<messages::input::LspOriginateMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(lsdb::LSP_MIN_GEN_INTERVAL);
        let lsp_originatep = lsp_originatep.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LspOriginateMsg {};
            let _ = lsp_originatep.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSP expiry timer task.
pub(crate) fn lsp_expiry_timer(
    level: LevelNumber,
    lse_id: LspEntryId,
    lsp: &Lsp,
    lsp_purgep: &UnboundedSender<messages::input::LspPurgeMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(lsp.rem_lifetime.into());
        let lsp_purgep = lsp_purgep.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LspPurgeMsg {
                level,
                lse_key: lse_id.into(),
                reason: LspPurgeReason::Expired,
            };
            let _ = lsp_purgep.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSP delete timer task.
pub(crate) fn lsp_delete_timer(
    level: LevelNumber,
    lse_id: LspEntryId,
    timeout: u64,
    lsp_deletep: &UnboundedSender<messages::input::LspDeleteMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(timeout);
        let lsp_deletep = lsp_deletep.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LspDeleteMsg {
                level,
                lse_key: lse_id.into(),
            };
            let _ = lsp_deletep.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSP refresh timer task.
pub(crate) fn lsp_refresh_timer(
    level: LevelNumber,
    lse_id: LspEntryId,
    refresh_interval: u16,
    lsp_refreshp: &UnboundedSender<messages::input::LspRefreshMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(refresh_interval.into());
        let lsp_refreshp = lsp_refreshp.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LspRefreshMsg {
                level,
                lse_key: lse_id.into(),
            };
            let _ = lsp_refreshp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// SPF delay timer task.
pub(crate) fn spf_delay_timer(
    level: LevelNumber,
    event: spf::fsm::Event,
    timeout: u32,
    spf_delay_eventp: &UnboundedSender<messages::input::SpfDelayEventMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_millis(timeout.into());
        let spf_delay_eventp = spf_delay_eventp.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::SpfDelayEventMsg { level, event };
            let _ = spf_delay_eventp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
