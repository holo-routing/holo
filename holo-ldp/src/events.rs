//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{btree_map, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use holo_utils::ip::IpNetworkKind;
use holo_utils::mpls::Label;
use holo_utils::socket::{TcpConnInfo, TcpStream, TcpStreamExt, TTL_MAX};
use tracing::{debug_span, Span};

use crate::collections::{AdjacencyId, NeighborId, NeighborIndex};
use crate::debug::Debug;
use crate::discovery::{self, Adjacency, AdjacencySource, TargetedNbr};
use crate::error::{Error, IoError};
use crate::fec::{Fec, LabelMapping, LabelRequest};
use crate::instance::InstanceUp;
use crate::neighbor::{fsm, LabelAdvMode, Neighbor, NeighborFlags};
use crate::northbound::notification;
use crate::packet::error::DecodeError;
use crate::packet::messages::address::TlvAddressList;
use crate::packet::messages::hello::HelloFlags;
use crate::packet::messages::initialization::InitFlags;
use crate::packet::messages::label::{
    FecElem, FecElemWildcard, TypedWildcardFecElem,
};
use crate::packet::messages::notification::StatusCode;
use crate::packet::messages::{
    AddressMsg, CapabilityMsg, HelloMsg, InitMsg, KeepaliveMsg, LabelMsg,
    NotifMsg,
};
use crate::packet::{AddressMessageType, LabelMessageType, Message, Pdu};
use crate::southbound;

// ===== UDP packet receipt =====

pub(crate) fn process_udp_pdu(
    instance: &mut InstanceUp,
    src_addr: IpAddr,
    pdu: Result<Pdu, DecodeError>,
    multicast: bool,
) {
    match multicast {
        true => process_udp_pdu_multicast(instance, src_addr, pdu),
        false => process_udp_pdu_unicast(instance, src_addr, pdu),
    }
}

fn process_udp_pdu_multicast(
    instance: &mut InstanceUp,
    src_addr: IpAddr,
    pdu: Result<Pdu, DecodeError>,
) {
    // Lookup interface.
    let (_, iface) = match instance.core.interfaces.get_by_addr(&src_addr) {
        Some(value) => value,
        None => return,
    };

    let source = AdjacencySource::new(Some(iface.id), src_addr);

    // Handle decode error.
    let mut pdu = match pdu {
        Ok(pdu) => pdu,
        Err(error) => {
            process_udp_pdu_error(instance, source, error);
            return;
        }
    };

    // Process the first message only (if any), ignoring the others.
    if let Some(Message::Hello(hello)) = pdu.messages.pop_front() {
        if hello.params.flags.contains(HelloFlags::TARGETED) {
            return;
        }

        let local_addr = iface.system.local_ipv4_addr();
        let holdtime_adjacent = hello.params.holdtime;
        let holdtime_negotiated =
            iface.calculate_adj_holdtime(holdtime_adjacent);
        let span = debug_span!("interface", name = %iface.name);
        process_hello(
            instance,
            local_addr,
            source,
            pdu.lsr_id,
            hello,
            holdtime_adjacent,
            holdtime_negotiated,
            span,
        );
    }
}

fn process_udp_pdu_unicast(
    instance: &mut InstanceUp,
    src_addr: IpAddr,
    pdu: Result<Pdu, DecodeError>,
) {
    let source = AdjacencySource::new(None, src_addr);

    // Handle decode error.
    let mut pdu = match pdu {
        Ok(pdu) => pdu,
        Err(error) => {
            process_udp_pdu_error(instance, source, error);
            return;
        }
    };

    // Process the first message only (if any), ignoring the others.
    if let Some(Message::Hello(hello)) = pdu.messages.pop_front() {
        if !hello.params.flags.contains(HelloFlags::TARGETED) {
            return;
        }

        // Find targeted neighbor (or create a dynamic one if possible).
        let (tnbr_idx, tnbr) =
            match instance.core.tneighbors.get_mut_by_addr(&src_addr) {
                Some(value) => value,
                None => {
                    if !hello.params.flags.contains(HelloFlags::REQ_TARGETED)
                        || !instance.core.config.targeted_hello_accept
                    {
                        return;
                    }
                    instance.core.tneighbors.insert(src_addr)
                }
            };
        tnbr.dynamic = hello.params.flags.contains(HelloFlags::REQ_TARGETED)
            && instance.core.config.targeted_hello_accept;

        //
        // The targeted neighbor might need to be activated or deactivated
        // depending whether the hello's message 'R' bit changed.
        //
        TargetedNbr::update(instance, tnbr_idx);
        let tnbr = &instance.core.tneighbors[tnbr_idx];
        if !tnbr.is_active() {
            return;
        }

        // Process hello message.
        let local_addr = IpAddr::V4(instance.state.ipv4.trans_addr);
        let holdtime_adjacent = hello.params.holdtime;
        let holdtime_negotiated =
            tnbr.calculate_adj_holdtime(holdtime_adjacent);
        let span = debug_span!("targeted-nbr", address = %tnbr.addr);
        process_hello(
            instance,
            local_addr,
            source,
            pdu.lsr_id,
            hello,
            holdtime_adjacent,
            holdtime_negotiated,
            span,
        );
    }
}

fn process_udp_pdu_error(
    instance: &mut InstanceUp,
    source: AdjacencySource,
    error: DecodeError,
) {
    // Log the error first.
    Error::UdpPduDecodeError(error).log();

    // Update hello dropped counter.
    if let Some((_, adj)) =
        instance.state.ipv4.adjacencies.get_mut_by_source(&source)
    {
        adj.hello_dropped += 1;
        adj.discontinuity_time = Utc::now();
    }
}

fn process_hello(
    instance: &mut InstanceUp,
    local_addr: IpAddr,
    source: AdjacencySource,
    lsr_id: Ipv4Addr,
    hello: HelloMsg,
    holdtime_adjacent: u16,
    holdtime_negotiated: u16,
    span: Span,
) {
    Debug::AdjacencyHelloRx(&span, &source, &lsr_id, &hello).log();

    // Use implicit transport address if necessary.
    let trans_addr = hello
        .ipv4_addr
        .map(|tlv| tlv.0.into())
        .unwrap_or_else(|| source.addr);

    // Create new adjacency or udpate existing one.
    if let Some((_, adj)) =
        instance.state.ipv4.adjacencies.get_mut_by_source(&source)
    {
        let mut shutdown_nbr = false;

        // Ignore the hello message if the advertised LSR-ID has changed.
        if adj.lsr_id != lsr_id {
            return;
        }
        // Shutdown associated neighbor if the advertised transport address has
        // changed.
        if adj.trans_addr != trans_addr {
            shutdown_nbr = true;
        }

        adj.local_addr = local_addr;
        adj.trans_addr = trans_addr;
        adj.holdtime_adjacent = holdtime_adjacent;
        adj.holdtime_negotiated = holdtime_negotiated;
        adj.hello_rcvd += 1;
        adj.discontinuity_time = Utc::now();
        adj.reset(holdtime_negotiated, &instance.tx.protocol_input.adj_timeout);

        if shutdown_nbr {
            if let Some((nbr_idx, nbr)) =
                instance.state.neighbors.get_mut_by_lsr_id(&lsr_id)
            {
                if nbr.is_operational() {
                    // Send Shutdown notification.
                    nbr.send_shutdown(&instance.state.msg_id, None);
                    Neighbor::fsm(instance, nbr_idx, fsm::Event::ErrorSent);
                }
            }
        }
    } else {
        let id = instance.state.ipv4.adjacencies.next_id();
        let mut adj = Adjacency::new(
            id,
            source,
            local_addr,
            trans_addr,
            lsr_id,
            holdtime_adjacent,
            holdtime_negotiated,
        );
        adj.reset(holdtime_negotiated, &instance.tx.protocol_input.adj_timeout);

        let ifname = adj.source.iface_id.map(|iface_id| {
            let (_, iface) =
                instance.core.interfaces.get_by_id(iface_id).unwrap();
            iface.name.as_str()
        });
        notification::mpls_ldp_hello_adjacency_event(
            &instance.tx.nb,
            &instance.core.name,
            ifname,
            &adj.source.addr,
            true,
        );

        instance.state.ipv4.adjacencies.insert(adj);
    }

    // Find associated neighbor or create a new one.
    let (_, nbr) = match instance.state.neighbors.get_mut_by_lsr_id(&lsr_id) {
        Some(nbr) => nbr,
        None => {
            let id = instance.state.neighbors.next_id();
            let kalive_interval = instance.core.config.session_ka_interval;
            let nbr = Neighbor::new(id, lsr_id, trans_addr, kalive_interval);
            if let Some(password) =
                instance.core.config.get_neighbor_password(nbr.lsr_id)
            {
                // The neighbor password (if any) must be set in the TCP
                // listening socket otherwise incoming SYN requests will be
                // rejected.
                nbr.set_listener_md5sig(
                    &instance.state.ipv4.session_socket,
                    Some(password),
                );
            }
            instance.state.neighbors.insert(nbr)
        }
    };

    // Dynamic GTSM negotiation.
    if !hello.params.flags.contains(HelloFlags::TARGETED)
        && hello.params.flags.contains(HelloFlags::GTSM)
    {
        nbr.flags.insert(NeighborFlags::GTSM);
    } else {
        nbr.flags.remove(NeighborFlags::GTSM);
    }

    // Update neighbor's configuration sequence number.
    if let Some(cfg_seqno) = hello.cfg_seqno {
        if cfg_seqno.0 > nbr.cfg_seqno {
            nbr.stop_backoff_timeout();
        }
        nbr.cfg_seqno = cfg_seqno.0;
    }

    // Start TCP connection when playing the active role of session
    // establishment.
    if nbr.state == fsm::State::NonExistent
        && nbr.is_session_active_role(instance.state.ipv4.trans_addr)
        && nbr.tasks.connect.is_none()
        && nbr.tasks.backoff_timeout.is_none()
    {
        let password = instance.core.config.get_neighbor_password(nbr.lsr_id);
        nbr.connect(
            instance.state.ipv4.trans_addr,
            password,
            &instance.tx.protocol_input.tcp_connect,
        );
    }
}

// ===== hello adjacency timeout  =====

pub(crate) fn process_adj_timeout(
    instance: &mut InstanceUp,
    adj_id: AdjacencyId,
) -> Result<(), Error> {
    // Lookup adjacency.
    let (adj_idx, adj) = instance.state.ipv4.adjacencies.get_by_id(adj_id)?;

    Debug::AdjacencyTimeout(&adj.source, &adj.lsr_id).log();

    // Remove the corresponding dynamic targeted neighbor, if any.
    if adj.source.iface_id.is_none() {
        if let Some((tnbr_idx, tnbr)) =
            instance.core.tneighbors.get_mut_by_addr(&adj.source.addr)
        {
            tnbr.dynamic = false;
            TargetedNbr::update(instance, tnbr_idx);
        }
    }

    // Delete adjacency.
    discovery::adjacency_delete(instance, adj_idx, StatusCode::HoldTimerExp);

    Ok(())
}

// ===== TCP connection request =====

pub(crate) fn process_tcp_accept(
    instance: &mut InstanceUp,
    stream: TcpStream,
    conn_info: TcpConnInfo,
) {
    // Lookup neighbor.
    let source = conn_info.remote_addr;
    let (nbr_idx, nbr) =
        match instance.state.neighbors.get_mut_by_trans_addr(&source) {
            Some(value) => value,
            None => {
                Debug::NoMatchingHelloAdjacency(&source).log();
                return;
            }
        };

    // Sanity checks.
    if nbr.is_session_active_role(instance.state.ipv4.trans_addr) {
        Error::TcpInvalidConnRequest(nbr.lsr_id).log();
        return;
    }
    if nbr.state != fsm::State::NonExistent {
        Error::TcpAdditionalTransportConn(nbr.lsr_id).log();
        return;
    }

    // Enable GTSM in single-hop peering sessions.
    #[cfg(not(feature = "testing"))]
    {
        if nbr.flags.contains(NeighborFlags::GTSM) {
            if let Err(error) = stream.set_ipv4_minttl(TTL_MAX) {
                IoError::TcpSocketError(error).log();
                return;
            }
        }
    }

    // Setup connection and trigger FSM event.
    nbr.setup_connection(
        stream,
        conn_info,
        instance.state.router_id,
        &instance.tx.protocol_input.nbr_pdu_rx,
        #[cfg(feature = "testing")]
        &instance.tx.protocol_output,
    );
    Neighbor::fsm(instance, nbr_idx, fsm::Event::MatchedAdjacency);
}

// ===== TCP connection established =====

pub(crate) fn process_tcp_connect(
    instance: &mut InstanceUp,
    nbr_id: NeighborId,
    stream: TcpStream,
    conn_info: TcpConnInfo,
) -> Result<(), Error> {
    // Lookup neighbor.
    let (nbr_idx, nbr) = instance.state.neighbors.get_mut_by_id(nbr_id)?;

    nbr.tasks.connect = None;

    // Setup connection and trigger FSM event.
    nbr.setup_connection(
        stream,
        conn_info,
        instance.state.router_id,
        &instance.tx.protocol_input.nbr_pdu_rx,
        #[cfg(feature = "testing")]
        &instance.tx.protocol_output,
    );
    Neighbor::fsm(instance, nbr_idx, fsm::Event::ConnectionUp);

    Ok(())
}

// ===== neighbor PDU receipt =====

pub(crate) fn process_nbr_pdu(
    instance: &mut InstanceUp,
    nbr_id: NeighborId,
    pdu: Result<Pdu, Error>,
) -> Result<(), Error> {
    // Lookup neighbor.
    let (nbr_idx, _) = instance.state.neighbors.get_mut_by_id(nbr_id)?;

    match pdu {
        Ok(pdu) => {
            process_nbr_msgs(instance, nbr_idx, pdu.messages);
        }
        Err(error) => {
            // Log the error first.
            error.log();

            // Handle error.
            match error {
                Error::NbrPduDecodeError(_, error) => {
                    process_nbr_pdu_decode_error(instance, nbr_idx, error);
                }
                Error::TcpConnClosed(_) => {
                    // Close the session.
                    Neighbor::fsm(
                        instance,
                        nbr_idx,
                        fsm::Event::ConnectionDown,
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

fn process_nbr_pdu_decode_error(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    error: DecodeError,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Map decode error to LDP status code.
    let status = error.into();

    // Send notification and possibly torn down the session.
    nbr.send_notification(&instance.state.msg_id, status, None, None);
    if status.is_fatal_error() {
        Error::NbrSentError(nbr.lsr_id, status).log();
        Neighbor::fsm(instance, nbr_idx, fsm::Event::ErrorSent);
    }
}

fn process_nbr_msgs(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    messages: VecDeque<Message>,
) {
    for msg in messages {
        if let Err(error) = process_nbr_msg(instance, nbr_idx, msg) {
            // Log the error first.
            error.log();

            // Close the session.
            match error {
                Error::NbrRcvdError(_, _) => {
                    Neighbor::fsm(instance, nbr_idx, fsm::Event::ErrorRcvd);
                }
                Error::NbrSentError(_, _) => {
                    Neighbor::fsm(instance, nbr_idx, fsm::Event::ErrorSent);
                }
                _ => unreachable!(),
            }
            break;
        }
    }

    // Reset the keepalive timer upon receiving any LDP PDU.
    let nbr = &mut instance.state.neighbors[nbr_idx];
    if nbr.state == fsm::State::Operational {
        let kalive_timeout_task = nbr.tasks.kalive_timeout.as_mut().unwrap();
        kalive_timeout_task.reset(None);
    }
}

fn process_nbr_msg(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: Message,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];
    Debug::NbrMsgRx(&nbr.lsr_id, &msg).log();

    // Update statistics.
    nbr.statistics.msgs_rcvd.update(&msg);
    nbr.statistics.discontinuity_time = Some(Utc::now());

    match msg {
        Message::Notification(msg) => {
            process_nbr_msg_notification(instance, nbr_idx, msg)
        }
        Message::Initialization(msg) => {
            process_nbr_msg_init(instance, nbr_idx, msg)
        }
        Message::Keepalive(msg) => {
            process_nbr_msg_keepalive(instance, nbr_idx, msg)
        }
        Message::Address(msg) => {
            process_nbr_msg_address(instance, nbr_idx, msg)
        }
        Message::Label(msg) => process_nbr_msg_label(instance, nbr_idx, msg),
        Message::Capability(msg) => {
            process_nbr_msg_capability(instance, nbr_idx, msg)
        }
        // Ignore unexpected Hello message.
        Message::Hello(_) => Ok(()),
    }
}

fn process_nbr_msg_notification(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: NotifMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    if msg.is_fatal_error() {
        if nbr.state == fsm::State::OpenSent {
            nbr.start_backoff_timeout(
                &instance.tx.protocol_input.nbr_backoff_timeout,
            );
        }

        //
        // RFC 5036 - Section 3.5.1.1:
        // "When an LSR receives a Shutdown message during session
        // initialization, it SHOULD transmit a Shutdown message and then
        // close the transport connection".
        //
        let status_code = StatusCode::decode(msg.status.status_code);
        if !nbr.is_operational() && status_code == Some(StatusCode::Shutdown) {
            nbr.send_shutdown(&instance.state.msg_id, msg);
        }

        return Err(Error::NbrRcvdError(nbr.lsr_id, status_code.unwrap()));
    }

    Ok(())
}

fn process_nbr_msg_init(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: InitMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Check if the message is valid given the current neighbor's state.
    match nbr.state {
        fsm::State::Initialized | fsm::State::OpenSent => (),
        _ => {
            nbr.send_shutdown(&instance.state.msg_id, msg);
            return Err(Error::NbrSentError(nbr.lsr_id, StatusCode::Shutdown));
        }
    }

    // Sanity checks.
    if msg.params.lsr_id != instance.state.router_id
        || msg.params.lspace_id != 0
    {
        let status = StatusCode::SessRejNoHello;
        nbr.send_notification(&instance.state.msg_id, status, msg, None);
        return Err(Error::NbrSentError(nbr.lsr_id, status));
    }

    // Update keepalive holdtime.
    let kalive_holdtime_rcvd = msg.params.keepalive_time;
    let kalive_holdtime_negotiated = std::cmp::min(
        instance.core.config.session_ka_holdtime,
        kalive_holdtime_rcvd,
    );
    nbr.kalive_holdtime_rcvd = Some(kalive_holdtime_rcvd);
    nbr.kalive_holdtime_negotiated = Some(kalive_holdtime_negotiated);

    // Set received label advertised mode.
    let label_adv_mode = if msg.params.flags.contains(InitFlags::ADV_DISCIPLINE)
    {
        LabelAdvMode::DownstreamOnDemand
    } else {
        LabelAdvMode::DownstreamUnsolicited
    };
    nbr.rcvd_label_adv_mode = Some(label_adv_mode);

    //
    // Calculate maximum PDU length.
    //
    // RFC 5036 - Section 3.5.3:
    // "A value of 255 or less specifies the default maximum length of
    // 4096 octets".
    //
    let mut max_pdu_len = msg.params.max_pdu_len;
    if max_pdu_len <= 255 {
        max_pdu_len = Pdu::DFLT_MAX_LEN;
    }
    nbr.max_pdu_len = std::cmp::min(max_pdu_len, Pdu::DFLT_MAX_LEN);

    // Process capabilities.
    if msg.cap_dynamic.is_some() {
        nbr.flags.insert(NeighborFlags::CAP_DYNAMIC);
    }
    if msg.cap_twcard_fec.is_some() {
        nbr.flags.insert(NeighborFlags::CAP_TYPED_WCARD);
    }
    if msg.cap_unrec_notif.is_some() {
        nbr.flags.insert(NeighborFlags::CAP_UNREC_NOTIF);
    }

    Neighbor::fsm(instance, nbr_idx, fsm::Event::InitRcvd);

    Ok(())
}

fn process_nbr_msg_keepalive(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: KeepaliveMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    match nbr.state {
        fsm::State::OpenRec => {
            // Session initialization event.
            Neighbor::fsm(instance, nbr_idx, fsm::Event::KeepaliveRcvd);
        }
        fsm::State::Operational => {
            // The keepalive timer will be reset later.
        }
        _ => {
            // Unexpected message given the current neighbor's state.
            nbr.send_shutdown(&instance.state.msg_id, msg);
            return Err(Error::NbrSentError(nbr.lsr_id, StatusCode::Shutdown));
        }
    }

    Ok(())
}

fn process_nbr_msg_address(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: AddressMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Check if the message is valid given the current neighbor's state.
    if !nbr.is_operational() {
        nbr.send_shutdown(&instance.state.msg_id, msg);
        return Err(Error::NbrSentError(nbr.lsr_id, StatusCode::Shutdown));
    }

    // Create family-agnostic address list.
    let addr_list = match msg.addr_list {
        TlvAddressList::Ipv4(addr_list) => addr_list
            .into_iter()
            .map(|addr| addr.into())
            .collect::<Vec<IpAddr>>(),
        TlvAddressList::Ipv6(addr_list) => addr_list
            .into_iter()
            .map(|addr| addr.into())
            .collect::<Vec<IpAddr>>(),
    };

    // Reevaluate all label mappings received from this neighbor.
    for (prefix, mapping) in &nbr.rcvd_mappings {
        let fec = instance.state.fecs.get_mut(prefix).unwrap();
        let old_fec_status = fec.is_operational();

        for nexthop in fec.nexthops.values_mut() {
            for addr in &addr_list {
                if nexthop.addr != *addr {
                    continue;
                }

                match msg.msg_type {
                    AddressMessageType::Address => {
                        nexthop.set_label(Some(mapping.label));
                        southbound::tx::label_install(
                            &instance.tx.ibus,
                            &fec.inner,
                            nexthop,
                        );
                    }
                    AddressMessageType::AddressWithdraw => {
                        southbound::tx::label_uninstall(
                            &instance.tx.ibus,
                            &fec.inner,
                            nexthop,
                        );
                        nexthop.set_label(None);
                    }
                }
            }
        }

        if old_fec_status != fec.is_operational() {
            notification::mpls_ldp_fec_event(
                &instance.tx.nb,
                &instance.core.name,
                fec,
            );
        }
    }

    match msg.msg_type {
        AddressMessageType::Address => {
            // Add new addresses.
            nbr.addr_list.extend(addr_list);
        }
        AddressMessageType::AddressWithdraw => {
            // Remove addresses.
            nbr.addr_list.retain(|addr| !addr_list.contains(addr));
        }
    }

    Ok(())
}

fn process_nbr_msg_label(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: LabelMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Check if the message is valid given the current neighbor's state.
    if !nbr.is_operational() {
        nbr.send_shutdown(&instance.state.msg_id, msg);
        return Err(Error::NbrSentError(nbr.lsr_id, StatusCode::Shutdown));
    }

    // Process each FEC element separetely.
    for fec_elem in &msg.fec.0 {
        match msg.msg_type {
            LabelMessageType::LabelMapping => {
                let label = msg.get_label().unwrap();
                process_nbr_msg_label_mapping(
                    instance, nbr_idx, label, *fec_elem,
                );
            }
            LabelMessageType::LabelRequest => {
                process_nbr_msg_label_request(
                    instance, nbr_idx, &msg, *fec_elem,
                );
            }
            LabelMessageType::LabelWithdraw => {
                process_nbr_msg_label_withdraw(
                    instance, nbr_idx, &msg, *fec_elem,
                );
            }
            LabelMessageType::LabelRelease => {
                process_nbr_msg_label_release(
                    instance, nbr_idx, &msg, *fec_elem,
                );
            }
            LabelMessageType::LabelAbortReq => {
                process_nbr_msg_label_abort_request(
                    instance, nbr_idx, &msg, *fec_elem,
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn process_nbr_msg_label_mapping(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    label: Label,
    fec_elem: FecElem,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Fetch FEC prefix.
    let prefix = match fec_elem {
        FecElem::Prefix(value) => value,
        _ => unreachable!(),
    };

    // Find or create new FEC node.
    let fec = instance
        .state
        .fecs
        .entry(prefix)
        .or_insert_with(|| Fec::new(prefix));
    let old_fec_status = fec.is_operational();

    // LMp.1: first check if we have a pending request running.
    let mut req_response = false;
    if let btree_map::Entry::Occupied(o) = nbr.sent_requests.entry(prefix) {
        req_response = true;

        // LMp.2: delete record of outstanding label request.
        o.remove_entry();
    }

    // LMp.3 - LMp.8: loop detection - unnecessary for frame-mode MPLS networks.

    // LMp.9: does LSR have a previously received label mapping for FEC from
    // MsgSource for the LSP in question?
    if let btree_map::Entry::Occupied(o) = nbr.rcvd_mappings.entry(prefix) {
        // LMp.10.
        let mapping = o.get();
        let old_label = mapping.label;
        if old_label != label && !req_response {
            // LMp.10a.
            for nexthop in fec.nexthops.values_mut() {
                if nbr.addr_list.get(&nexthop.addr).is_none() {
                    continue;
                }

                southbound::tx::label_uninstall(
                    &instance.tx.ibus,
                    &fec.inner,
                    nexthop,
                );
                nexthop.set_label(None);
            }
            nbr.send_label_release(
                &instance.state.msg_id,
                fec_elem,
                Some(old_label),
            );
        }
    }

    // LMp.11 - 12: consider multiple nexthops in order to support multipath.
    for nexthop in fec.nexthops.values_mut() {
        // LMp.15: install FEC in the FIB.
        if nbr.addr_list.get(&nexthop.addr).is_none() {
            continue;
        }

        // Ignore duplicate mapping.
        if nexthop.get_label() == Some(label) {
            continue;
        }

        nexthop.set_label(Some(label));
        if fec.inner.local_label.is_some() {
            southbound::tx::label_install(
                &instance.tx.ibus,
                &fec.inner,
                nexthop,
            );
        }
    }

    if old_fec_status != fec.is_operational() {
        notification::mpls_ldp_fec_event(
            &instance.tx.nb,
            &instance.core.name,
            fec,
        );
    }

    // LMp.13 & LMp.16: Record the mapping from this peer.
    let mapping = LabelMapping { label };
    fec.inner.downstream.insert(nbr.lsr_id, mapping);
    nbr.rcvd_mappings.insert(prefix, mapping);

    // LMp.17 - LMp.27 are unnecessary since we don't need to implement loop
    // detection.
    // LMp.28 - LMp.30 are unnecessary because we are merging capable.
}

fn process_nbr_msg_label_request(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    fec_elem: FecElem,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Fetch FEC prefix.
    let prefix = match fec_elem {
        FecElem::Prefix(value) => value,
        FecElem::Wildcard(FecElemWildcard::Typed(wcard)) => {
            process_nbr_msg_label_request_wcard(instance, nbr_idx, msg, wcard);
            return;
        }
        FecElem::Wildcard(FecElemWildcard::All) => unreachable!(),
    };

    // LRq.1: skip loop detection (not necessary).

    // LRq.2: is there a next hop for fec?
    let has_nexthop = match instance.state.fecs.entry(prefix) {
        btree_map::Entry::Occupied(mut o) => {
            let fec = o.get_mut();
            !fec.nexthops.is_empty()
        }
        btree_map::Entry::Vacant(_) => false,
    };
    if !has_nexthop {
        // LRq.5: send No Route notification.
        nbr.send_notification(
            &instance.state.msg_id,
            StatusCode::NoRoute,
            msg.clone(),
            None,
        );
        return;
    }

    // LRq.3: is MsgSource the next hop?
    let fec = instance.state.fecs.get_mut(&prefix).unwrap();
    for nexthop in fec.nexthops.values() {
        if nbr.addr_list.get(&nexthop.addr).is_none() {
            continue;
        }

        // LRq.4: send Loop Detected notification.
        nbr.send_notification(
            &instance.state.msg_id,
            StatusCode::LoopDetected,
            msg.clone(),
            None,
        );
        return;
    }

    // LRq.6: first check if we have a pending request running.
    match nbr.rcvd_requests.entry(prefix) {
        btree_map::Entry::Occupied(_) => {
            // LRq.7: duplicate request.
            return;
        }
        btree_map::Entry::Vacant(v) => {
            // LRq.8: record label request.
            let request = LabelRequest { id: msg.msg_id };
            v.insert(request);
        }
    }

    // LRq.9: perform LSR label distribution.
    nbr.send_label_mapping(&instance.state.msg_id, fec);

    // LRq.10: do nothing (Request Never) since we use liberal label retention.
    // LRq.11 - 12 are unnecessary since we are merging capable.
}

fn process_nbr_msg_label_request_wcard(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    wcard: TypedWildcardFecElem,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    for fec in instance
        .state
        .fecs
        .values_mut()
        // Check wildcard constraints.
        .filter(|fec| match wcard {
            TypedWildcardFecElem::Prefix(af) => {
                af == fec.inner.prefix.address_family()
            }
        })
    {
        // LRq.2: is there a next hop for fec?
        if fec.nexthops.is_empty() {
            continue;
        }

        // LRq.6: first check if we have a pending request running.
        match nbr.rcvd_requests.entry(*fec.inner.prefix) {
            btree_map::Entry::Occupied(_) => {
                // LRq.7: duplicate request.
                continue;
            }
            btree_map::Entry::Vacant(v) => {
                // LRq.8: record label request.
                let request = LabelRequest { id: msg.msg_id };
                v.insert(request);
            }
        }

        // LRq.9: perform LSR label distribution.
        nbr.send_label_mapping(&instance.state.msg_id, fec);
    }

    // Signal completion of label advertisements.
    if nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF) {
        nbr.send_end_of_lib(&instance.state.msg_id, wcard);
    }
}

fn process_nbr_msg_label_withdraw(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    fec_elem: FecElem,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Fetch FEC prefix.
    let prefix = match fec_elem {
        FecElem::Prefix(value) => value,
        FecElem::Wildcard(wcard) => {
            process_nbr_msg_label_withdraw_wcard(instance, nbr_idx, msg, wcard);
            return;
        }
    };

    let fec = instance
        .state
        .fecs
        .entry(prefix)
        .or_insert_with(|| Fec::new(prefix));
    let old_fec_status = fec.is_operational();

    // LWd.1: remove label from forwarding/switching use.
    for nexthop in fec.nexthops.values_mut() {
        if nbr.addr_list.get(&nexthop.addr).is_none() {
            continue;
        }

        if msg.label.is_some() && msg.get_label() != nexthop.get_label() {
            continue;
        }

        southbound::tx::label_uninstall(&instance.tx.ibus, &fec.inner, nexthop);
        nexthop.set_label(None);
    }

    if old_fec_status != fec.is_operational() {
        notification::mpls_ldp_fec_event(
            &instance.tx.nb,
            &instance.core.name,
            fec,
        );
    }

    // LWd.2: send label release.
    nbr.send_label_release(&instance.state.msg_id, fec_elem, msg.get_label());

    // LWd.3: check previously received label mapping.
    if let btree_map::Entry::Occupied(o) = nbr.rcvd_mappings.entry(prefix) {
        let mapping = o.get();
        if msg.label.is_none() || msg.get_label().unwrap() == mapping.label {
            // LWd.4: remove record of previously received label mapping.
            o.remove_entry();
            fec.inner.downstream.remove(&nbr.lsr_id);
        }
    }
}

fn process_nbr_msg_label_withdraw_wcard(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    wcard: FecElemWildcard,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // LWd.2: send label release.
    nbr.send_label_release(
        &instance.state.msg_id,
        FecElem::Wildcard(wcard),
        msg.get_label(),
    );

    for fec in instance
        .state
        .fecs
        .values_mut()
        // Check wildcard constraints.
        .filter(|fec| match wcard {
            FecElemWildcard::All => true,
            FecElemWildcard::Typed(TypedWildcardFecElem::Prefix(af)) => {
                af == fec.inner.prefix.address_family()
            }
        })
    {
        let old_fec_status = fec.is_operational();

        // LWd.1: remove label from forwarding/switching use.
        for nexthop in fec.nexthops.values_mut() {
            if nbr.addr_list.get(&nexthop.addr).is_none() {
                continue;
            }

            if msg.label.is_some() && msg.get_label() != nexthop.get_label() {
                continue;
            }

            southbound::tx::label_uninstall(
                &instance.tx.ibus,
                &fec.inner,
                nexthop,
            );
            nexthop.set_label(None);
        }

        if old_fec_status != fec.is_operational() {
            notification::mpls_ldp_fec_event(
                &instance.tx.nb,
                &instance.core.name,
                fec,
            );
        }

        // LWd.3: check previously received label mapping.
        let prefix = *fec.inner.prefix;
        if let btree_map::Entry::Occupied(o) = nbr.rcvd_mappings.entry(prefix) {
            let mapping = o.get();
            if msg.label.is_none() || msg.get_label().unwrap() == mapping.label
            {
                // LWd.4: remove record of previously received label mapping.
                o.remove_entry();
                fec.inner.downstream.remove(&nbr.lsr_id);
            }
        }
    }
}

fn process_nbr_msg_label_release(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    fec_elem: FecElem,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Fetch FEC prefix.
    let prefix = match fec_elem {
        FecElem::Prefix(value) => value,
        FecElem::Wildcard(wcard) => {
            process_nbr_msg_label_release_wcard(instance, nbr_idx, msg, wcard);
            return;
        }
    };

    // LRl.1: does FEC match a known FEC?
    let fec = match instance.state.fecs.get_mut(&prefix) {
        Some(fec) => fec,
        None => return,
    };

    // LRl.6: check sent map list and remove it if available.
    if let btree_map::Entry::Occupied(o) = nbr.sent_mappings.entry(prefix) {
        let mapping = o.get();
        if msg.label.is_none() || msg.get_label().unwrap() == mapping.label {
            o.remove_entry();
            fec.inner.upstream.remove(&nbr.lsr_id);
        }
    }

    // LRl.3: first check if we have a pending withdraw running.
    if let btree_map::Entry::Occupied(o) = nbr.sent_withdraws.entry(prefix) {
        if msg.label.is_none() || msg.get_label().unwrap() == *o.get() {
            o.remove_entry();
        }
    }

    // LRl.11 - 13 are unnecessary since we remove the label from
    // forwarding/switching as soon as the FEC is unreachable.
}

fn process_nbr_msg_label_release_wcard(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: &LabelMsg,
    wcard: FecElemWildcard,
) {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    for fec in instance
        .state
        .fecs
        .values_mut()
        // Check wildcard constraints.
        .filter(|fec| match wcard {
            FecElemWildcard::All => true,
            FecElemWildcard::Typed(TypedWildcardFecElem::Prefix(af)) => {
                af == fec.inner.prefix.address_family()
            }
        })
    {
        let prefix = *fec.inner.prefix;

        // LRl.6: check sent map list and remove it if available.
        if let btree_map::Entry::Occupied(o) = nbr.sent_mappings.entry(prefix) {
            let mapping = o.get();
            if msg.label.is_none() || msg.get_label().unwrap() == mapping.label
            {
                o.remove_entry();
                fec.inner.upstream.remove(&nbr.lsr_id);
            }
        }

        // LRl.3: first check if we have a pending withdraw running.
        if let btree_map::Entry::Occupied(o) = nbr.sent_withdraws.entry(prefix)
        {
            if msg.label.is_none() || msg.get_label().unwrap() == *o.get() {
                o.remove_entry();
            }
        }

        // LRl.11 - 13 are unnecessary since we remove the label from
        // forwarding/switching as soon as the FEC is unreachable.
    }
}

fn process_nbr_msg_label_abort_request(
    _instance: &mut InstanceUp,
    _nbr_idx: NeighborIndex,
    _msg: &LabelMsg,
    _fec_elem: FecElem,
) {
    // Nothing to do as this implementation only supports the Independent Label
    // Distribution mode. This means that all received label requests are
    // replied to immediately, giving no room for request abortions to take
    // place.
}

fn process_nbr_msg_capability(
    instance: &mut InstanceUp,
    nbr_idx: NeighborIndex,
    msg: CapabilityMsg,
) -> Result<(), Error> {
    let nbr = &mut instance.state.neighbors[nbr_idx];

    // Check if the message is valid given the current neighbor's state.
    if !nbr.is_operational() {
        nbr.send_shutdown(&instance.state.msg_id, msg);
        return Err(Error::NbrSentError(nbr.lsr_id, StatusCode::Shutdown));
    }

    // Process capabilities.
    if let Some(tlv) = msg.twcard_fec {
        if tlv.0 {
            nbr.flags.insert(NeighborFlags::CAP_TYPED_WCARD);
        } else {
            nbr.flags.remove(NeighborFlags::CAP_TYPED_WCARD);
        }
    }
    if let Some(tlv) = msg.unrec_notif {
        if tlv.0 {
            nbr.flags.insert(NeighborFlags::CAP_UNREC_NOTIF);
        } else {
            nbr.flags.remove(NeighborFlags::CAP_UNREC_NOTIF);
        }
    }

    Ok(())
}

// ===== neighbor keepalive timeout =====

pub(crate) fn process_nbr_ka_timeout(
    instance: &mut InstanceUp,
    nbr_id: NeighborId,
) -> Result<(), Error> {
    // Lookup neighbor.
    let (nbr_idx, nbr) = instance.state.neighbors.get_mut_by_id(nbr_id)?;

    // Send error notification.
    nbr.send_notification(
        &instance.state.msg_id,
        StatusCode::KeepaliveExp,
        None,
        None,
    );
    Neighbor::fsm(instance, nbr_idx, fsm::Event::ErrorSent);

    Ok(())
}

// ===== neighbor initialization backoff timeout =====

pub(crate) fn process_nbr_backoff_timeout(
    instance: &mut InstanceUp,
    lsr_id: Ipv4Addr,
) {
    // Lookup neighbor.
    let (_, nbr) = match instance.state.neighbors.get_mut_by_lsr_id(&lsr_id) {
        Some(value) => value,
        None => return,
    };

    Debug::NbrInitBackoffTimeout(&nbr.lsr_id).log();

    nbr.tasks.backoff_timeout = None;
    let password = instance.core.config.get_neighbor_password(nbr.lsr_id);
    nbr.connect(
        instance.state.ipv4.trans_addr,
        password,
        &instance.tx.protocol_input.tcp_connect,
    );
}
