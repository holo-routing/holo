//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::SocketAddr;

use holo_utils::bfd::{ClientCfg, ClientId, SessionKey, State};
use tracing::trace;

use crate::debug::Debug;
use crate::error::Error;
use crate::master::Master;
use crate::network::{self, PacketInfo};
use crate::packet::{DiagnosticCode, Packet, PacketFlags};
use crate::session::{SessionId, SessionRemoteInfo};

pub(crate) fn process_udp_packet(
    master: &mut Master,
    packet_info: PacketInfo,
    packet: Packet,
) -> Result<(), Error> {
    trace!(?packet_info, ?packet, "received packet");

    // Session lookup varies depending on whether the Your Discriminator field
    // is zero or not.
    let Some((_, sess)) = (match packet.your_discr {
        0 => {
            match packet_info {
                PacketInfo::IpSingleHop { src } => {
                    master.sessions.get_mut_by_sockaddr(src)
                }
                PacketInfo::IpMultihop { src, dst, ttl } => master
                    .sessions
                    .get_mut_by_key(&SessionKey::IpMultihop {
                        src: dst,
                        dst: src,
                    })
                    // Multihop requires TTL validation in the userspace.
                    .filter(|(_, sess)| sess.config.rx_ttl.unwrap() <= ttl),
            }
        }
        _ => master.sessions.get_mut_by_discr(packet.your_discr),
    }) else {
        // Discard the packet.
        return Err(Error::SessionNoMatch(packet_info, packet.your_discr));
    };

    // Update packet counter.
    sess.statistics.rx_packet_count += 1;

    // Validation checks.
    if let Err(error) = validate_bfd_packet(&packet) {
        sess.statistics.rx_error_count += 1;
        return Err(error);
    }

    // Update session's state.
    let old_remote_min_rx = sess.remote_min_rx_interval();
    sess.state.remote = Some(SessionRemoteInfo::new(
        packet.state,
        packet.my_discr,
        packet.diag,
        packet.detect_mult,
        packet.desired_min_tx,
        packet.req_min_rx,
        packet.flags.contains(PacketFlags::D),
    ));

    // If a Poll Sequence is being transmitted by the local system and the Final
    // (F) bit in the received packet is set, the Poll Sequence MUST be
    // terminated.
    if sess.poll_sequence_is_active() && packet.flags.contains(PacketFlags::F) {
        sess.poll_sequence_terminate();

        // The peer is aware of the updated interval timers, so we can now
        // effectivelly use them.
        sess.state.curr_min_tx = sess.desired_tx_interval();
        sess.state.curr_min_rx = sess.required_min_rx();
        sess.update_tx_interval();
    }

    // Update the transmit interval as described in section 6.8.2.
    if sess.remote_min_rx_interval() != old_remote_min_rx {
        // Honor the new interval immediately.
        sess.update_tx_interval();
    }

    // Update the Detection Time as described in section 6.8.4.
    sess.update_detection_time(&master.tx.protocol_input.detect_timer);

    // Invoke FSM event.
    let next_state = match (sess.state.local_state, packet.state) {
        (State::AdminDown, _) => {
            // Silently discard the packet.
            return Ok(());
        }
        (State::Init | State::Up, State::AdminDown) => {
            Some((State::Down, DiagnosticCode::NbrDown))
        }
        (State::Down, State::Down) => {
            Some((State::Init, DiagnosticCode::Nothing))
        }
        (State::Down, State::Init) => {
            Some((State::Up, DiagnosticCode::Nothing))
        }
        (State::Init, State::Init | State::Up) => {
            Some((State::Up, DiagnosticCode::Nothing))
        }
        (State::Up, State::Down) => {
            Some((State::Down, DiagnosticCode::NbrDown))
        }
        _ => None,
    };
    if let Some((state, diag)) = next_state {
        // Effectively transition to the new FSM state.
        sess.state_update(state, diag, &master.tx);
    }

    // TODO: Demand Mode processing.

    // If the Poll (P) bit is set, send a BFD Control packet to the remote
    // system with the Poll (P) bit clear, and the Final (F) bit set.
    if packet.flags.contains(PacketFlags::P) {
        sess.send_tx_final();
    }

    Ok(())
}

// Checks whether the BFD packet is valid.
fn validate_bfd_packet(packet: &Packet) -> Result<(), Error> {
    if packet.version != Packet::VERSION {
        return Err(Error::VersionMismatch(packet.version));
    }
    if packet.detect_mult == 0 {
        return Err(Error::InvalidDetectMult(packet.detect_mult));
    }
    if packet.flags.contains(PacketFlags::M)
        || packet.flags.contains(PacketFlags::P | PacketFlags::F)
    {
        return Err(Error::InvalidFlags(packet.flags));
    }
    if packet.my_discr == 0 {
        return Err(Error::InvalidMyDiscriminator(packet.my_discr));
    }
    if packet.your_discr == 0
        && !matches!(packet.state, State::Down | State::AdminDown)
    {
        return Err(Error::InvalidYourDiscriminator(packet.your_discr));
    }
    // BFD authentication isn't supported yet.
    if packet.flags.contains(PacketFlags::A) {
        return Err(Error::AuthError);
    }

    Ok(())
}

pub(crate) fn process_detection_timer_expiry(
    master: &mut Master,
    sess_id: SessionId,
) -> Result<(), Error> {
    let (_, sess) = master.sessions.get_mut_by_id(sess_id)?;

    Debug::DetectionTimeExpiry(&sess.key).log();

    // Transition to the "Down" state.
    sess.state_update(State::Down, DiagnosticCode::TimeExpired, &master.tx);

    // Reset remote data since the peer is dead.
    sess.state.remote = None;

    Ok(())
}

pub(crate) fn process_client_peer_reg(
    master: &mut Master,
    sess_key: SessionKey,
    client_id: ClientId,
    client_config: Option<ClientCfg>,
) -> Result<(), Error> {
    Debug::SessionClientReg(&sess_key, &client_id).log();

    let (sess_idx, sess) = master.sessions.insert(sess_key);
    sess.clients.insert(client_id, client_config);

    // Start Poll Sequence as the configuration parameters might have changed.
    sess.poll_sequence_start();

    // Try to initialize session if possible.
    sess.update_socket_tx();
    match &sess.key {
        SessionKey::IpSingleHop { ifname, .. } => {
            if let Some(iface) = master.interfaces.get(ifname) {
                master.sessions.update_ifindex(sess_idx, iface.ifindex);
            }
        }
        SessionKey::IpMultihop { dst, .. } => {
            sess.state.sockaddr =
                Some(SocketAddr::new(*dst, network::PORT_DST_MULTIHOP));
            sess.update_tx_interval();
        }
    }

    // Start UDP Rx tasks if necessary.
    master.update_udp_rx_tasks();

    Ok(())
}

pub(crate) fn process_client_peer_unreg(
    master: &mut Master,
    sess_key: SessionKey,
    client_id: ClientId,
) -> Result<(), Error> {
    if let Some((sess_idx, sess)) = master.sessions.get_mut_by_key(&sess_key) {
        Debug::SessionClientUnreg(&sess_key, &client_id).log();

        // Remove BFD client.
        sess.clients.remove(&client_id);

        // Check if the BFD session can be deleted.
        master.sessions.delete_check(sess_idx);

        // Stop UDP Rx tasks if necessary.
        master.update_udp_rx_tasks();
    }

    Ok(())
}
