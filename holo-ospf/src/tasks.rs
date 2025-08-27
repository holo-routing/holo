//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use holo_utils::ip::AddressFamily;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use smallvec::SmallVec;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tracing::{Instrument, debug_span};

use crate::area::Area;
use crate::collections::{LsaEntryId, LsdbId};
use crate::debug::LsaFlushReason;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, ism};
use crate::neighbor::{Neighbor, nsm};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::version::Version;
use crate::{lsdb, network, spf};

//
// OSPF tasks diagram:
//                                    +--------------+
//                                    |  northbound  |
//                                    +--------------+
//                                          | ^
//                                          | |
//                       northbound_rx (1x) V | (1x) northbound_tx
//                                    +--------------+
//                     net_rx (Nx) -> |              | -> (Nx) net_tx
//                                    |              |
//             ism_wait_timer (Nx) -> |              | -> (Nx) hello_interval
//                                    |              |
//       nsm_inactivity_timer (Nx) -> |              |
//       packet_rxmt_interval (Nx) -> |              |
//          dbdesc_free_timer (Nx) -> |              |
//            ls_update_timer (Nx) -> |              |
//          delayed_ack_timer (Nx) -> |   instance   |
//                                    |              |
//           lsa_expiry_timer (Nx) -> |              |
//          lsa_refresh_timer (Nx) -> |              |
//     lsa_orig_delayed_timer (Nx) -> |              |
// lsdb_maxage_sweep_interval (Nx) -> |              |
//                                    |              |
//            spf_delay_timer (Nx) -> |              |
//                                    +--------------+
//                             ibus_tx (1x) | ^ (1x) ibus_rx
//                                          | |
//                                          V |
//                                    +--------------+
//                                    |     ibus     |
//                                    +--------------+
//

// OSPF inter-task message types.
pub mod messages {
    use std::net::Ipv4Addr;

    use serde::{Deserialize, Serialize};
    use smallvec::SmallVec;

    use crate::collections::{
        AreaKey, InterfaceKey, LsaEntryKey, LsdbKey, NeighborKey,
    };
    use crate::debug::LsaFlushReason;
    use crate::interface::ism;
    use crate::lsdb::LsaOriginateEvent;
    use crate::neighbor::{RxmtPacketType, nsm};
    use crate::packet::Packet;
    use crate::packet::error::DecodeError;
    use crate::packet::lsa::LsaKey;
    use crate::spf;
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
            IsmEvent(IsmEventMsg),
            NsmEvent(NsmEventMsg),
            NetRxPacket(NetRxPacketMsg<V>),
            DbDescFree(DbDescFreeMsg),
            SendLsUpdate(SendLsUpdateMsg),
            RxmtInterval(RxmtIntervalMsg),
            DelayedAck(DelayedAckMsg),
            LsaOrigEvent(LsaOrigEventMsg),
            LsaOrigCheck(LsaOrigCheckMsg<V>),
            LsaOrigDelayed(LsaOrigDelayedMsg<V>),
            LsaFlush(LsaFlushMsg<V>),
            LsaRefresh(LsaRefreshMsg<V>),
            LsdbMaxAgeSweep(LsdbMaxAgeSweepMsg),
            SpfDelayEvent(SpfDelayEventMsg),
            GracePeriod(GracePeriodMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct IsmEventMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub event: ism::Event,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct NsmEventMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub nbr_key: NeighborKey,
            pub event: nsm::Event,
        }

        #[derive(Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct NetRxPacketMsg<V: Version> {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub src: V::NetIpAddr,
            pub dst: V::NetIpAddr,
            pub packet: Result<Packet<V>, DecodeError>,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct DbDescFreeMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub nbr_key: NeighborKey,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct SendLsUpdateMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub nbr_key: Option<NeighborKey>,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct RxmtIntervalMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub nbr_key: NeighborKey,
            pub packet_type: RxmtPacketType,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct DelayedAckMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct LsaOrigEventMsg {
            pub event: LsaOriginateEvent,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct LsaOrigCheckMsg<V: Version> {
            pub lsdb_key: LsdbKey,
            pub options: Option<V::PacketOptions>,
            pub lsa_id: Ipv4Addr,
            pub lsa_body: V::LsaBody,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct LsaOrigDelayedMsg<V: Version> {
            pub lsdb_key: LsdbKey,
            pub lsa_key: LsaKey<V::LsaType>,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct LsaFlushMsg<V: Version> {
            pub lsdb_key: LsdbKey,
            pub lse_key: LsaEntryKey<V::LsaType>,
            pub reason: LsaFlushReason,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct LsaRefreshMsg<V: Version> {
            pub lsdb_key: LsdbKey,
            pub lse_key: LsaEntryKey<V::LsaType>,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct LsdbMaxAgeSweepMsg {
            pub lsdb_key: LsdbKey,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct SpfDelayEventMsg {
            pub event: spf::fsm::Event,
        }

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct GracePeriodMsg {
            pub area_key: AreaKey,
            pub iface_key: InterfaceKey,
            pub nbr_key: NeighborKey,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        #[serde(bound = "V: Version")]
        pub enum ProtocolMsg<V: Version> {
            NetTxPacket(NetTxPacketMsg<V>),
        }

        #[derive(Clone, Debug, Serialize)]
        #[serde(bound = "V: Version")]
        pub struct NetTxPacketMsg<V: Version> {
            pub packet: Packet<V>,
            #[cfg(feature = "testing")]
            pub ifname: String,
            pub dst: SmallVec<[V::NetIpAddr; 4]>,
        }
    }
}

// ===== OSPF tasks =====

// Network Rx task.
pub(crate) fn net_rx<V>(
    socket: Arc<AsyncFd<Socket>>,
    iface: &Interface<V>,
    area: &Area<V>,
    af: AddressFamily,
    net_packet_rxp: &Sender<messages::input::NetRxPacketMsg<V>>,
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

        let area_id = area.id;
        let iface_id = iface.id;
        let auth = iface.state.auth.clone();
        let net_packet_rxp = net_packet_rxp.clone();

        Task::spawn_supervised(move || {
            let socket = socket.clone();
            let auth = auth.clone();
            let net_packet_rxp = net_packet_rxp.clone();
            async move {
                let _ = network::read_loop(
                    socket,
                    area_id,
                    iface_id,
                    af,
                    auth,
                    net_packet_rxp,
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
pub(crate) fn net_tx<V>(
    socket: Arc<AsyncFd<Socket>>,
    iface: &Interface<V>,
    auth_seqno: &Arc<AtomicU64>,
    mut net_packet_txc: UnboundedReceiver<messages::output::NetTxPacketMsg<V>>,
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

        let ifname = iface.name.clone();
        let ifindex = iface.system.ifindex.unwrap();
        let src = iface.state.src_addr.unwrap();
        let auth = iface.state.auth.clone();
        let auth_seqno = auth_seqno.clone();
        let trace_opts = iface.config.trace_opts.packets_resolved.clone();

        Task::spawn(
            async move {
                network::write_loop(
                    socket,
                    ifname,
                    ifindex,
                    src,
                    auth,
                    auth_seqno,
                    trace_opts,
                    net_packet_txc,
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
            while let Some(msg) = net_packet_txc.recv().await {
                let msg = messages::ProtocolOutputMsg::NetTxPacket(msg);
                let _ = proto_output_tx.send(msg).await;
            }
        })
    }
}

// Send periodic OSPF Hello messages.
pub(crate) fn hello_interval<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    dst: SmallVec<[V::NetIpAddr; 4]>,
    interval: u16,
) -> IntervalTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        // Generate hello packet.
        let packet = V::generate_hello(iface, area, instance);

        let net_tx_packetp =
            iface.state.net.as_ref().unwrap().net_tx_packetp.clone();
        IntervalTask::new(
            Duration::from_secs(interval.into()),
            true,
            move || {
                let packet = packet.clone();
                let dst = dst.clone();
                let net_tx_packetp = net_tx_packetp.clone();

                async move {
                    let msg = messages::output::NetTxPacketMsg { packet, dst };
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

// Interface wait timer task.
pub(crate) fn ism_wait_timer<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(iface.config.dead_interval.into());
        let area_id = area.id;
        let iface_id = iface.id;
        let ism_eventp = instance.tx.protocol_input.ism_event.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::IsmEventMsg {
                area_key: area_id.into(),
                iface_key: iface_id.into(),
                event: ism::Event::WaitTimer,
            };
            let _ = ism_eventp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Neighbor inactivity timer.
pub(crate) fn nsm_inactivity_timer<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_secs(iface.config.dead_interval.into());
        let nbr_id = nbr.id;
        let area_id = area.id;
        let iface_id = iface.id;
        let nsm_eventp = instance.tx.protocol_input.nsm_event.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::NsmEventMsg {
                area_key: area_id.into(),
                iface_key: iface_id.into(),
                nbr_key: nbr_id.into(),
                event: nsm::Event::InactivityTimer,
            };
            let _ = nsm_eventp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Send periodic packet retransmissions.
pub(crate) fn packet_rxmt_interval<V>(
    iface: &Interface<V>,
    msg: messages::input::RxmtIntervalMsg,
    instance: &InstanceUpView<'_, V>,
) -> IntervalTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let rxmt_intervalp = instance.tx.protocol_input.rxmt_interval.clone();

        IntervalTask::new(
            Duration::from_secs(iface.config.retransmit_interval.into()),
            false,
            move || {
                let rxmt_intervalp = rxmt_intervalp.clone();
                let msg = msg.clone();

                async move {
                    let _ = rxmt_intervalp.send(msg).await;
                }
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Timer to free the neighbor's last sent/received Database Description packets.
pub(crate) fn dbdesc_free_timer<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let area_id = area.id;
        let iface_id = iface.id;
        let nbr_id = nbr.id;
        let dbdesc_freep = instance.tx.protocol_input.dbdesc_free.clone();

        TimeoutTask::new(
            Duration::from_secs(iface.config.dead_interval.into()),
            move || async move {
                let _ = dbdesc_freep
                    .send(messages::input::DbDescFreeMsg {
                        area_key: area_id.into(),
                        iface_key: iface_id.into(),
                        nbr_key: nbr_id.into(),
                    })
                    .await;
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Interface LS Update timer task.
pub(crate) fn ls_update_timer<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) -> TimeoutTask
where
    V: Version,
{
    let area_id = area.id;
    let iface_id = iface.id;
    let send_lsupdp = instance.tx.protocol_input.send_lsupd.clone();

    #[cfg(not(feature = "testing"))]
    {
        // Start timer.
        TimeoutTask::new(Duration::from_millis(100), move || async move {
            let _ = send_lsupdp.send(messages::input::SendLsUpdateMsg {
                area_key: area_id.into(),
                iface_key: iface_id.into(),
                nbr_key: None,
            });
        })
    }
    #[cfg(feature = "testing")]
    {
        // Send LS Update immediately.
        let _ = send_lsupdp.send(messages::input::SendLsUpdateMsg {
            area_key: area_id.into(),
            iface_key: iface_id.into(),
            nbr_key: None,
        });

        TimeoutTask {}
    }
}

// Interface delayed Ack timer task.
pub(crate) fn delayed_ack_timer<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
) -> TimeoutTask
where
    V: Version,
{
    let area_id = area.id;
    let iface_id = iface.id;
    let delayed_ack_timeoutp =
        instance.tx.protocol_input.delayed_ack_timeout.clone();

    #[cfg(not(feature = "testing"))]
    {
        // RFC 2328 - Section 13.5:
        // "The fixed interval between a router's delayed transmissions must be
        // short (less than RxmtInterval) or needless retransmissions will
        // ensue".
        let timeout = Duration::from_secs(1);
        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::DelayedAckMsg {
                area_key: area_id.into(),
                iface_key: iface_id.into(),
            };
            let _ = delayed_ack_timeoutp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        // Send LS Ack immediately.
        let msg = messages::input::DelayedAckMsg {
            area_key: area_id.into(),
            iface_key: iface_id.into(),
        };
        let _ = delayed_ack_timeoutp.send(msg);

        TimeoutTask {}
    }
}

// LSA expiry timer task.
pub(crate) fn lsa_expiry_timer<V>(
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
    lsa: &Lsa<V>,
    lsa_flushp: &UnboundedSender<messages::input::LsaFlushMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let timeout = lsdb::LSA_MAX_AGE - lsa.hdr.age();
        let timeout = Duration::from_secs(timeout.into());
        let lsa_flushp = lsa_flushp.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LsaFlushMsg {
                lsdb_key: lsdb_id.into(),
                lse_key: lse_id.into(),
                reason: LsaFlushReason::Expiry,
            };
            let _ = lsa_flushp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSA refresh timer task.
pub(crate) fn lsa_refresh_timer<V>(
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
    lsa_refreshp: &UnboundedSender<messages::input::LsaRefreshMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let timeout = lsdb::LSA_REFRESH_TIME;
        let timeout = Duration::from_secs(timeout.into());
        let lsa_refreshp = lsa_refreshp.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LsaRefreshMsg {
                lsdb_key: lsdb_id.into(),
                lse_key: lse_id.into(),
            };
            let _ = lsa_refreshp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSA delayed origination timer task.
pub(crate) fn lsa_orig_delayed_timer<V>(
    lsdb_id: LsdbId,
    lsa_key: LsaKey<V::LsaType>,
    lsa_base_time: Option<Instant>,
    lsa_orig_delayed_timerp: &Sender<messages::input::LsaOrigDelayedMsg<V>>,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let lsa_orig_delayed_timerp = lsa_orig_delayed_timerp.clone();

        let lsa_age = lsa_base_time.unwrap().elapsed();
        let timeout =
            Duration::from_secs(lsdb::LSA_MIN_INTERVAL).saturating_sub(lsa_age);

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::LsaOrigDelayedMsg {
                lsdb_key: lsdb_id.into(),
                lsa_key,
            };
            let _ = lsa_orig_delayed_timerp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// LSDB MaxAge sweeper interval task.
pub(crate) fn lsdb_maxage_sweep_interval(
    lsdb_id: LsdbId,
    lsdb_maxage_sweep_intervalp: &Sender<messages::input::LsdbMaxAgeSweepMsg>,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let lsdb_maxage_sweep_intervalp = lsdb_maxage_sweep_intervalp.clone();

        let timeout = Duration::from_secs(5);
        IntervalTask::new(timeout, false, move || {
            let lsdb_maxage_sweep_intervalp =
                lsdb_maxage_sweep_intervalp.clone();
            async move {
                let msg = messages::input::LsdbMaxAgeSweepMsg {
                    lsdb_key: lsdb_id.into(),
                };
                let _ = lsdb_maxage_sweep_intervalp.send(msg).await;
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// SPF delay timer task.
pub(crate) fn spf_delay_timer<V>(
    instance: &InstanceUpView<'_, V>,
    event: spf::fsm::Event,
    timeout: u32,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let timeout = Duration::from_millis(timeout.into());
        let spf_delay_eventp =
            instance.tx.protocol_input.spf_delay_event.clone();

        TimeoutTask::new(timeout, move || async move {
            let msg = messages::input::SpfDelayEventMsg { event };
            let _ = spf_delay_eventp.send(msg);
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}

// Grace period timer task.
pub(crate) fn grace_period_timer<V>(
    nbr: &Neighbor<V>,
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    grace_period: u32,
) -> TimeoutTask
where
    V: Version,
{
    #[cfg(not(feature = "testing"))]
    {
        let area_id = area.id;
        let iface_id = iface.id;
        let nbr_id = nbr.id;
        let grace_periodp = instance.tx.protocol_input.grace_period.clone();

        TimeoutTask::new(
            Duration::from_secs(grace_period.into()),
            move || async move {
                let _ = grace_periodp
                    .send(messages::input::GracePeriodMsg {
                        area_key: area_id.into(),
                        iface_key: iface_id.into(),
                        nbr_key: nbr_id.into(),
                    })
                    .await;
            },
        )
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
