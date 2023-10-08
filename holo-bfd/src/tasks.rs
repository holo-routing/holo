//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::SocketAddr;
use std::sync::{atomic, Arc};
use std::time::Duration;

use holo_utils::bfd::PathType;
use holo_utils::socket::UdpSocket;
use holo_utils::task::{IntervalTask, Task, TimeoutTask};
use holo_utils::Sender;
use tracing::Instrument;

use crate::network;
use crate::packet::PacketFlags;
use crate::session::Session;

//
// BFD tasks diagram:
//                                +--------------+
//                                |  northbound  |
//                                +--------------+
//                                      | ^
//                                      | |
//                   northbound_rx (1x) V | (1x) northbound_tx
//                                +--------------+
//                 udp_rx (1x) -> |              | -> (Nx) udp_tx_interval
//        detection_timer (Nx) -> |    master    | -> (Nx) udp_tx_final
//                                |              |
//                                +--------------+
//                   southbound_tx (1x) | ^ (1x) southbound_rx
//                                      | |
//                                      V |
//                                +--------------+
//                                |    zebra     |
//                                +--------------+
//

// BFD inter-task message types.
pub mod messages {
    use serde::{Deserialize, Serialize};

    use crate::network::PacketInfo;
    use crate::packet::Packet;
    use crate::session::SessionId;

    // Type aliases.
    pub type ProtocolInputMsg = input::ProtocolMsg;
    pub type ProtocolOutputMsg = output::ProtocolMsg;

    // Input messages (child task -> main task).
    pub mod input {
        use super::*;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ProtocolMsg {
            UdpRxPacket(UdpRxPacketMsg),
            DetectTimer(DetectTimerMsg),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct UdpRxPacketMsg {
            pub packet_info: PacketInfo,
            pub packet: Packet,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct DetectTimerMsg {
            pub sess_id: SessionId,
        }
    }

    // Output messages (main task -> child task).
    pub mod output {
        use super::*;

        #[derive(Debug, Serialize)]
        pub enum ProtocolMsg {}
    }
}

// ===== BFD tasks =====

// UDP Rx task.
pub(crate) fn udp_rx(
    socket: UdpSocket,
    path_type: PathType,
    udp_packet_rxp: &Sender<messages::input::UdpRxPacketMsg>,
) -> Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        let socket = Arc::new(socket);
        let udp_packet_rxp = udp_packet_rxp.clone();
        Task::spawn(
            async move {
                let _ =
                    network::read_loop(socket, path_type, udp_packet_rxp).await;
            }
            .in_current_span(),
        )
    }
    #[cfg(feature = "testing")]
    {
        Task::spawn(async move { std::future::pending().await })
    }
}

// Sends periodic BFD control packets.
pub(crate) fn udp_tx_interval(
    sess: &Session,
    interval: u32,
    socket: &Arc<UdpSocket>,
    sockaddr: SocketAddr,
) -> IntervalTask {
    #[cfg(not(feature = "testing"))]
    {
        let interval = Duration::from_micros(interval as u64);
        let packet = sess.generate_packet();

        // Clone reference-counted pointers.
        let socket = socket.clone();
        let poll_active = sess.state.poll_active.clone();
        let tx_packet_count = sess.statistics.tx_packet_count.clone();
        let tx_error_count = sess.statistics.tx_error_count.clone();

        IntervalTask::new(interval, true, move || {
            // Clone reference-counted pointers.
            let socket = socket.clone();
            let poll_active = poll_active.clone();
            let tx_packet_count = tx_packet_count.clone();
            let tx_error_count = tx_error_count.clone();

            // Update the P-bit as necessary.
            let mut packet = packet.clone();
            if poll_active.load(atomic::Ordering::Relaxed) {
                packet.flags.insert(PacketFlags::P);
            } else {
                packet.flags.remove(PacketFlags::P);
            }

            // Send packet.
            network::send_packet(
                socket,
                sockaddr,
                packet,
                tx_packet_count,
                tx_error_count,
            )
        })
    }
    #[cfg(feature = "testing")]
    {
        IntervalTask {}
    }
}

// Sends single BFD control packet with the F-bit set.
pub(crate) fn udp_tx_final(
    sess: &Session,
    socket: &Arc<UdpSocket>,
    sockaddr: SocketAddr,
) {
    #[cfg(not(feature = "testing"))]
    {
        // Generate packet with the F-bit set.
        let mut packet = sess.generate_packet();
        packet.flags.insert(PacketFlags::F);

        // Clone reference-counted pointers.
        let socket = socket.clone();
        let tx_packet_count = sess.statistics.tx_packet_count.clone();
        let tx_error_count = sess.statistics.tx_error_count.clone();

        // Send the packet asynchronously.
        let mut task = Task::spawn(async move {
            network::send_packet(
                socket,
                sockaddr,
                packet,
                tx_packet_count,
                tx_error_count,
            )
            .await;
        });
        task.detach();
    }
}

// BFD session detection timer.
pub(crate) fn detection_timer(
    sess: &Session,
    detect_timerp: &Sender<messages::input::DetectTimerMsg>,
) -> TimeoutTask {
    #[cfg(not(feature = "testing"))]
    {
        let holdtime =
            Duration::from_micros(sess.detection_time().unwrap() as u64);
        let sess_id = sess.id;
        let detect_timerp = detect_timerp.clone();
        TimeoutTask::new(holdtime, move || async move {
            let msg = messages::input::DetectTimerMsg { sess_id };
            let _ = detect_timerp.send(msg).await;
        })
    }
    #[cfg(feature = "testing")]
    {
        TimeoutTask {}
    }
}
