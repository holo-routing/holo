//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use chrono::Utc;
use holo_protocol::InstanceShared;
use holo_utils::bgp::RouteType;
use holo_utils::ibus::IbusChannelsTx;
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use holo_utils::policy::{PolicyResult, PolicyType};
use holo_utils::socket::{TcpConnInfo, TcpStream};
use ipnetwork::IpNetwork;
use num_traits::FromPrimitive;

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::error::{Error, IoError, NbrRxError};
use crate::instance::{InstanceUpView, PolicyApplyTasks};
use crate::neighbor::{ConnOrigin, Neighbor, Neighbors, PeerType, fsm};
use crate::packet::attribute::Attrs;
use crate::packet::iana::{Afi, ErrorCode, FsmErrorSubcode, Safi};
use crate::packet::message::{
    Capability, Message, MpReachNlri, MpUnreachNlri, NotificationMsg,
    RouteRefreshMsg, UpdateMsg,
};
use crate::policy::{POLICY_APPLY_BATCH_SIZE_MAX, RoutePolicyInfo};
use crate::rib::{
    AttrSetsCxt, BestRoute, Redistribute, Rib, Route, RouteOrigin,
    RoutingTable, SelectionState,
};
use crate::tasks::messages::output::PolicyApplyMsg;
use crate::{network, rib};

// ===== TCP connection request =====

pub(crate) fn process_tcp_accept(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    stream: TcpStream,
    conn_info: TcpConnInfo,
) -> Result<(), Error> {
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&conn_info.remote_addr) else {
        return Ok(());
    };

    // Initialize the accepted stream.
    network::accepted_stream_init(
        &stream,
        nbr.remote_addr.address_family(),
        nbr.tx_ttl(),
        nbr.config.transport.ttl_security,
        nbr.config.transport.tcp_mss,
    )
    .map_err(IoError::TcpSocketError)?;

    nbr.connection_new(instance, stream, conn_info, ConnOrigin::Remote);

    Ok(())
}

// ===== TCP connection established =====

pub(crate) fn process_tcp_connect(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    stream: TcpStream,
    conn_info: TcpConnInfo,
) -> Result<(), Error> {
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&conn_info.remote_addr) else {
        return Ok(());
    };
    nbr.tasks.connect = None;

    nbr.connection_new(instance, stream, conn_info, ConnOrigin::Local);

    Ok(())
}

// ===== neighbor message receipt =====

pub(crate) fn process_nbr_msg(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    conn_info: Option<TcpConnInfo>,
    msg: Result<Message, NbrRxError>,
) -> Result<(), Error> {
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&nbr_addr) else {
        return Ok(());
    };

    // Tell apart what arrives on a connection colliding with the neighbor's,
    // and drop what is left over from a connection since closed.
    if let Some(conn_info) = &conn_info {
        if nbr
            .colliding
            .as_ref()
            .is_some_and(|colliding| colliding.conn_info == *conn_info)
        {
            process_nbr_colliding_msg(instance, nbr, msg);
            return Ok(());
        }
        if nbr.conn_info.as_ref() != Some(conn_info) {
            return Ok(());
        }
    }

    // Process received message.
    //
    // A connection that fails while another collides with it gives way to
    // that one, rather than bringing the session down.
    match msg {
        Ok(msg) => {
            if nbr.config.trace_opts.packets_resolved.load().rx(&msg) {
                Debug::NbrMsgRx(&nbr.remote_addr, &msg).log();
            }

            // Update statistics.
            nbr.statistics.msgs_rcvd.update(&msg);

            match msg {
                Message::Open(msg) => {
                    // The neighbor's BGP Identifier resolves any collision
                    // first, which may leave this connection.
                    if !nbr.collision_resolve(instance, msg.identifier) {
                        nbr.fsm_event(instance, fsm::Event::RcvdOpen(msg));
                    }
                }
                Message::Update(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdUpdate);
                    if nbr.state == fsm::State::Established {
                        process_nbr_update(instance, nbr, msg)?;
                    }
                }
                Message::Notification(msg) => {
                    if nbr.colliding.is_some() {
                        nbr.colliding_promote(instance);
                    } else {
                        let event = fsm::Event::RcvdNotif(msg.clone());
                        nbr.fsm_event(instance, event);
                    }
                    // Keep track of the last received notification.
                    nbr.notification_rcvd = Some((Utc::now(), msg));
                }
                Message::Keepalive(_) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdKalive);
                }
                Message::RouteRefresh(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdRouteRefresh);
                    if nbr.state == fsm::State::Established {
                        process_nbr_route_refresh(instance, nbr, msg)?;
                    }
                }
            }
        }
        Err(error) => match error {
            NbrRxError::TcpConnClosed => {
                if nbr.colliding.is_some() {
                    nbr.colliding_promote(instance);
                } else {
                    nbr.fsm_event(instance, fsm::Event::ConnFail);
                }
            }
            NbrRxError::MsgDecodeError(error) => {
                if nbr.colliding.is_some() {
                    let msg = NotificationMsg::from(error);
                    nbr.message_send(Message::Notification(msg));
                    nbr.colliding_promote(instance);
                } else {
                    nbr.fsm_event(instance, fsm::Event::RcvdError(error));
                }
            }
        },
    }

    Ok(())
}

// Processes what arrives on a connection colliding with the neighbor's.
//
// The neighbor's OPEN resolves the collision, and when the connection it
// arrived on is the one kept, it is processed as it would be on any other.
// Anything else arriving before it leaves the connection: the neighbor
// closing it, as it would when it resolved the collision first, or sending
// what it had no business sending before its OPEN.
fn process_nbr_colliding_msg(
    instance: &mut InstanceUpView<'_>,
    nbr: &mut Neighbor,
    msg: Result<Message, NbrRxError>,
) {
    match msg {
        Ok(msg) => {
            if nbr.config.trace_opts.packets_resolved.load().rx(&msg) {
                Debug::NbrMsgRx(&nbr.remote_addr, &msg).log();
            }
            nbr.statistics.msgs_rcvd.update(&msg);

            match msg {
                Message::Open(msg) => {
                    if nbr.collision_resolve(instance, msg.identifier) {
                        nbr.fsm_event(instance, fsm::Event::RcvdOpen(msg));
                    }
                }
                Message::Notification(_) => nbr.colliding_close(None),
                _ => {
                    let msg = NotificationMsg::new(
                        ErrorCode::FiniteStateMachineError,
                        FsmErrorSubcode::UnexpectedMessageInOpenSent,
                    );
                    nbr.colliding_close(Some(msg));
                }
            }
        }
        Err(NbrRxError::TcpConnClosed) => nbr.colliding_close(None),
        Err(NbrRxError::MsgDecodeError(error)) => {
            nbr.colliding_close(Some(NotificationMsg::from(error)));
        }
    }
}

fn process_nbr_update(
    instance: &mut InstanceUpView<'_>,
    nbr: &mut Neighbor,
    msg: UpdateMsg,
) -> Result<(), Error> {
    let rib = &mut instance.state.rib;
    let ibus_tx = &instance.tx.ibus;

    // Process IPv4 reachable NLRIs.
    //
    // Use nexthop from the NEXTHOP attribute.
    if let Some(reach) = msg.reach {
        if let Some(attrs) = &msg.attrs {
            let mut attrs = attrs.clone();
            attrs.base.nexthop = Some(reach.nexthop.into());
            process_nbr_reach_prefixes::<Ipv4Unicast>(
                nbr,
                rib,
                reach.prefixes,
                attrs,
                instance.config.asn,
                instance.shared,
                &instance.state.policy_apply_tasks,
            );
        } else {
            // Treat as withdraw.
            process_nbr_unreach_prefixes::<Ipv4Unicast>(
                nbr,
                rib,
                reach.prefixes,
                ibus_tx,
            );
        }
    }

    // Process multiprotocol reachable NLRIs.
    //
    // Use nexthop(s) from the MP_REACH_NLRI attribute.
    if let Some(mp_reach) = msg.mp_reach {
        if let Some(mut attrs) = msg.attrs {
            match mp_reach {
                MpReachNlri::Ipv4Unicast { prefixes, nexthop } => {
                    attrs.base.nexthop = Some(nexthop.into());
                    process_nbr_reach_prefixes::<Ipv4Unicast>(
                        nbr,
                        rib,
                        prefixes,
                        attrs,
                        instance.config.asn,
                        instance.shared,
                        &instance.state.policy_apply_tasks,
                    );
                }
                MpReachNlri::Ipv6Unicast {
                    prefixes,
                    nexthop,
                    ll_nexthop,
                } => {
                    attrs.base.nexthop = Some(nexthop.into());
                    attrs.base.ll_nexthop = ll_nexthop;
                    process_nbr_reach_prefixes::<Ipv6Unicast>(
                        nbr,
                        rib,
                        prefixes,
                        attrs,
                        instance.config.asn,
                        instance.shared,
                        &instance.state.policy_apply_tasks,
                    );
                }
            }
        } else {
            // Treat as withdraw.
            match mp_reach {
                MpReachNlri::Ipv4Unicast { prefixes, .. } => {
                    process_nbr_unreach_prefixes::<Ipv4Unicast>(
                        nbr, rib, prefixes, ibus_tx,
                    );
                }
                MpReachNlri::Ipv6Unicast { prefixes, .. } => {
                    process_nbr_unreach_prefixes::<Ipv6Unicast>(
                        nbr, rib, prefixes, ibus_tx,
                    );
                }
            }
        }
    }

    // Process IPv4 unreachable NLRIs.
    if let Some(unreach) = msg.unreach {
        process_nbr_unreach_prefixes::<Ipv4Unicast>(
            nbr,
            rib,
            unreach.prefixes,
            ibus_tx,
        );
    }

    // Process multiprotocol unreachable NLRIs.
    if let Some(mp_unreach) = msg.mp_unreach {
        match mp_unreach {
            MpUnreachNlri::Ipv4Unicast { prefixes } => {
                process_nbr_unreach_prefixes::<Ipv4Unicast>(
                    nbr, rib, prefixes, ibus_tx,
                );
            }
            MpUnreachNlri::Ipv6Unicast { prefixes } => {
                process_nbr_unreach_prefixes::<Ipv6Unicast>(
                    nbr, rib, prefixes, ibus_tx,
                );
            }
        }
    }

    // Schedule the BGP Decision Process.
    instance.state.schedule_decision_process(instance.tx);

    Ok(())
}

fn process_nbr_reach_prefixes<A>(
    nbr: &Neighbor,
    rib: &mut Rib,
    nlri_prefixes: Vec<A::IpNetwork>,
    mut attrs: Attrs,
    local_asn: u32,
    shared: &InstanceShared,
    policy_apply_tasks: &PolicyApplyTasks,
) where
    A: AddressFamily,
{
    // Check if the address-family is enabled for this session.
    if !nbr.is_af_enabled(A::AFI, A::SAFI) {
        return;
    }

    // Initialize route origin and type.
    let origin = RouteOrigin::Neighbor {
        identifier: nbr.identifier.unwrap(),
        remote_addr: nbr.remote_addr,
    };
    let route_type = match nbr.peer_type {
        PeerType::Internal => RouteType::Internal,
        PeerType::External => RouteType::External,
    };

    if nbr.config.as_path_options.replace_peer_as {
        // Replace occurrences of the peer's AS in the AS_PATH with the local
        // autonomous system number.
        attrs.base.as_path.replace(nbr.config.peer_as, local_asn);
    }

    // Update pre-policy Adj-RIB-In routes.
    let table = A::table(&mut rib.tables);
    let route_attrs = rib.attr_sets.get_route_attr_sets(&attrs);
    let counters = table.prefix_counters.entry(nbr.index).or_default();
    let now = Instant::now();
    for prefix in &nlri_prefixes {
        let dest = table.prefixes.entry(*prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.index).or_default();
        let route = Route::new(route_attrs.clone(), now);
        adj_rib.update_in_pre(origin, route_type, route, counters);
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Enqueue import policy application.
    let rpinfo = RoutePolicyInfo::new(origin, route_type, None, None, attrs);
    let msg = PolicyApplyMsg::Neighbor {
        policy_type: PolicyType::Import,
        nbr_addr: nbr.remote_addr,
        afi_safi: A::AFI_SAFI,
        route: rpinfo,
        prefixes: nlri_prefixes.into_iter().map(Into::into).collect(),
        policies: apply_policy_cfg
            .import_policy
            .iter()
            .map(|policy| shared.policies.get(policy).unwrap().clone())
            .collect(),
        match_sets: shared.policy_match_sets.clone(),
        default_policy: apply_policy_cfg.default_import_policy,
    };
    policy_apply_tasks.enqueue(msg);
}

fn process_nbr_unreach_prefixes<A>(
    nbr: &Neighbor,
    rib: &mut Rib,
    nlri_prefixes: Vec<A::IpNetwork>,
    ibus_tx: &IbusChannelsTx,
) where
    A: AddressFamily,
{
    // Check if the address-family is enabled for this session.
    if !nbr.is_af_enabled(A::AFI, A::SAFI) {
        return;
    }

    // Remove routes from Adj-RIB-In.
    let table = A::table(&mut rib.tables);
    let counters = table.prefix_counters.entry(nbr.index).or_default();
    for prefix in nlri_prefixes {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.index) else {
            continue;
        };
        if let Some(route) = adj_rib.remove_in(counters) {
            let nexthop = route.nexthop::<A>();
            rib::nexthop_untrack(&mut table.nht, &prefix, nexthop, ibus_tx);
        }

        // Enqueue prefix for the BGP Decision Process.
        table.queued_prefixes.insert(prefix);
    }
}

fn process_nbr_route_refresh(
    instance: &mut InstanceUpView<'_>,
    nbr: &mut Neighbor,
    msg: RouteRefreshMsg,
) -> Result<(), Error> {
    let Some(afi) = Afi::from_u16(msg.afi) else {
        // Ignore unknown AFI.
        return Ok(());
    };
    let Some(safi) = Safi::from_u8(msg.safi) else {
        // Ignore unknown SAFI.
        return Ok(());
    };

    // RFC 2918 - Section 4:
    // If a BGP speaker receives from its peer a ROUTE-REFRESH message with
    // the <AFI, SAFI> that the speaker didn't advertise to the peer at the
    // session establishment time via capability advertisement, the speaker
    // shall ignore such a message.
    let cap = Capability::MultiProtocol { afi, safi };
    if !nbr.capabilities_adv.contains(&cap) {
        return Ok(());
    }

    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => {
            nbr.resend_adj_rib_out::<Ipv4Unicast>(instance);
        }
        (Afi::Ipv6, Safi::Unicast) => {
            nbr.resend_adj_rib_out::<Ipv6Unicast>(instance);
        }
        _ => {
            // Ignore unsupported AFI/SAFI combination.
            return Ok(());
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    if !msg_list.is_empty() {
        nbr.message_list_send(msg_list);
    }

    Ok(())
}

// ===== neighbor expired timeout =====

pub(crate) fn process_nbr_timer(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    timer: fsm::Timer,
) -> Result<(), Error> {
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&nbr_addr) else {
        return Ok(());
    };

    // A connection whose hold timer expires while another collides with it
    // gives way to that one, rather than bringing the session down.
    if timer == fsm::Timer::Hold && nbr.colliding.is_some() {
        let msg = NotificationMsg::new(ErrorCode::HoldTimerExpired, 0);
        nbr.message_send(Message::Notification(msg));
        nbr.colliding_promote(instance);
        return Ok(());
    }

    // Invoke FSM event.
    nbr.fsm_event(instance, fsm::Event::Timer(timer));

    Ok(())
}

// ===== neighbor policy import result =====

pub(crate) fn process_nbr_policy_import<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    routes: Vec<(PolicyResult<RoutePolicyInfo>, Vec<IpNetwork>)>,
) -> Result<(), Error>
where
    A: AddressFamily,
{
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&nbr_addr) else {
        return Ok(());
    };
    if nbr.state < fsm::State::Established {
        return Ok(());
    }

    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let ibus_tx = &instance.tx.ibus;
    let now = Instant::now();
    for (result, prefixes) in routes {
        // Intern the attribute sets once for all prefixes sharing the same
        // policy result.
        let route_attrs = match &result {
            PolicyResult::Accept(rpinfo) => {
                Some(rib.attr_sets.get_route_attr_sets(&rpinfo.attrs))
            }
            PolicyResult::Reject => None,
        };

        for prefix in prefixes {
            // Get RIB destination and Adj-RIB entry. If they're gone (e.g. the
            // route was withdrawn while the policy was being applied), ignore
            // the result.
            let prefix = A::IpNetwork::get(prefix).unwrap();
            let Some(dest) = table.prefixes.get_mut(&prefix) else {
                continue;
            };
            let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.index) else {
                continue;
            };

            // Update post-policy Adj-RIB-In routes.
            let nht = &mut table.nht;
            match &route_attrs {
                // The route was accepted by the import policies.
                Some(route_attrs) => {
                    let route = Route::new(route_attrs.clone(), now);
                    let old_nexthop = adj_rib
                        .in_post()
                        .map(|(route, _)| route.nexthop::<A>());
                    let nexthop = route.nexthop::<A>();
                    if adj_rib.update_in_post(route).is_some() {
                        rib::nexthop_retrack(
                            nht,
                            prefix,
                            old_nexthop,
                            nexthop,
                            ibus_tx,
                        );
                    }
                }
                // The route was rejected by the import policies.
                None => {
                    if let Some(route) = adj_rib.remove_in_post() {
                        let nexthop = route.nexthop::<A>();
                        rib::nexthop_untrack(nht, &prefix, nexthop, ibus_tx);
                    }
                }
            }

            // Enqueue prefix for the BGP Decision Process.
            table.queued_prefixes.insert(prefix);
        }
    }

    // Schedule the BGP Decision Process.
    instance.state.schedule_decision_process(instance.tx);

    Ok(())
}

// ===== neighbor policy export result =====

pub(crate) fn process_nbr_policy_export<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    routes: Vec<(PolicyResult<RoutePolicyInfo>, Vec<IpNetwork>)>,
) -> Result<(), Error>
where
    A: AddressFamily,
{
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&nbr_addr) else {
        return Ok(());
    };
    if nbr.state < fsm::State::Established {
        return Ok(());
    }

    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let counters = table.prefix_counters.entry(nbr.index).or_default();
    let now = Instant::now();
    for (result, prefixes) in routes {
        match result {
            PolicyResult::Accept(rpinfo) => {
                // Intern the attribute sets once for all prefixes sharing the
                // same policy result.
                let route_attrs =
                    rib.attr_sets.get_route_attr_sets(&rpinfo.attrs);

                // Update route's attributes before transmission.
                let mut attrs = rpinfo.attrs;
                rib::attrs_tx_update::<A>(&mut attrs, nbr, instance.config.asn);

                let mut advertise = vec![];
                for prefix in prefixes {
                    // Get RIB destination and Adj-RIB entry. If they're gone
                    // (e.g. the route was withdrawn while the policy was being
                    // applied), ignore the result.
                    let prefix = A::IpNetwork::get(prefix).unwrap();
                    let Some(dest) = table.prefixes.get_mut(&prefix) else {
                        continue;
                    };
                    let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.index) else {
                        continue;
                    };

                    // Check if the Adj-RIB-Out was updated.
                    let route = Route::new(route_attrs.clone(), now);
                    let update = adj_rib
                        .out_post()
                        .is_none_or(|old_route| old_route.attrs != route.attrs);

                    // Update post-policy Adj-RIB-Out routes.
                    if update
                        && adj_rib.update_out_post(route, counters).is_some()
                    {
                        advertise.push(prefix);
                    }
                }

                // Update neighbor's Tx queue.
                if !advertise.is_empty() {
                    let update_queue = A::update_queue(&mut nbr.update_queues);
                    update_queue
                        .reach
                        .entry(attrs)
                        .or_default()
                        .extend(advertise);
                }
            }
            PolicyResult::Reject => {
                for prefix in prefixes {
                    // Get RIB destination and Adj-RIB entry. If they're gone
                    // (e.g. the route was withdrawn while the policy was being
                    // applied), ignore the result.
                    let prefix = A::IpNetwork::get(prefix).unwrap();
                    let Some(dest) = table.prefixes.get_mut(&prefix) else {
                        continue;
                    };
                    let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.index) else {
                        continue;
                    };

                    // Update post-policy Adj-RIB-Out routes.
                    if adj_rib.remove_out_post(counters).is_some() {
                        // Update neighbor's Tx queue.
                        let update_queue =
                            A::update_queue(&mut nbr.update_queues);
                        update_queue.unreach.insert(prefix);
                    }
                }
            }
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    if !msg_list.is_empty() {
        nbr.message_list_send(msg_list);
    }

    Ok(())
}

// ===== redistribute policy import result =====

pub(crate) fn process_redistribute_policy_import<A>(
    instance: &mut InstanceUpView<'_>,
    prefix: IpNetwork,
    result: PolicyResult<RoutePolicyInfo>,
) -> Result<(), Error>
where
    A: AddressFamily,
{
    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let prefix = A::IpNetwork::get(prefix).unwrap();

    match result {
        PolicyResult::Accept(rpinfo) => {
            // Get prefix RIB entry.
            let dest = table.prefixes.entry(prefix).or_default();

            // Update redistributed route in the RIB.
            let route_attrs = rib.attr_sets.get_route_attr_sets(&rpinfo.attrs);
            dest.redistribute = Some(Box::new(Redistribute {
                origin: rpinfo.origin,
                route_type: RouteType::Internal,
                attrs: route_attrs,
                last_modified: Instant::now(),
                selection: SelectionState::default(),
            }));
        }
        PolicyResult::Reject => {
            // Remove redistributed route from the RIB.
            if let Some(dest) = table.prefixes.get_mut(&prefix) {
                dest.redistribute = None;
            }
        }
    }

    // Enqueue prefix and schedule the BGP Decision Process.
    table.queued_prefixes.insert(prefix);
    instance.state.schedule_decision_process(instance.tx);

    Ok(())
}

// ===== BGP decision process =====

pub(crate) fn decision_process(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
) -> Result<(), Error> {
    // Run the decision process for all address families.
    decision_process_af::<Ipv4Unicast>(instance, neighbors)?;
    decision_process_af::<Ipv6Unicast>(instance, neighbors)?;

    // Release interned attribute sets no longer referenced by any route.
    instance.state.rib.attr_sets.sweep();

    Ok(())
}

fn decision_process_af<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
) -> Result<(), Error>
where
    A: AddressFamily,
{
    // Get route selection configuration for the address family.
    let selection_cfg = &instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.route_selection)
        .unwrap_or(&instance.config.route_selection);

    // Get multipath configuration for the address family.
    let mpath_cfg = &instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.multipath)
        .unwrap_or(&instance.config.multipath);

    // Phase 2: Route Selection.
    //
    // Process each queued destination in the RIB.
    let table = A::table(&mut instance.state.rib.tables);
    let queued_prefixes = std::mem::take(&mut table.queued_prefixes);
    let mut reach = vec![];
    let mut unreach = vec![];
    for prefix in queued_prefixes.iter().copied() {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };

        // Perform best-path selection for the destination.
        let best_route = rib::best_path::<A>(
            dest,
            instance.config.asn,
            instance.state.router_id,
            neighbors,
            &table.nht,
            selection_cfg,
        );

        // Update the Loc-RIB with the best path.
        let old_origin = dest.local.as_ref().map(|local| local.origin);
        let changed = rib::loc_rib_update::<A>(
            prefix,
            dest,
            best_route.clone(),
            selection_cfg,
            mpath_cfg,
            &instance.config.distance,
            &instance.config.trace_opts,
            &instance.tx.ibus,
        );

        // Update the per-peer installed prefix counters if the origin of the
        // Loc-RIB route has changed.
        let new_origin = dest.local.as_ref().map(|local| local.origin);
        if old_origin != new_origin {
            if let Some(RouteOrigin::Neighbor { remote_addr, .. }) = old_origin
                && let Some(nbr) = neighbors.get(&remote_addr)
                && let Some(counters) =
                    table.prefix_counters.get_mut(&nbr.index)
            {
                counters.installed = counters.installed.saturating_sub(1);
            }
            if let Some(RouteOrigin::Neighbor { remote_addr, .. }) = new_origin
                && let Some(nbr) = neighbors.get(&remote_addr)
            {
                let counters =
                    table.prefix_counters.entry(nbr.index).or_default();
                counters.installed = counters.installed.saturating_add(1);
            }
        }

        // Skip route dissemination if the Loc-RIB entry hasn't changed.
        if !changed {
            continue;
        }

        // Group best routes and unfeasible routes separately.
        match best_route {
            Some(best_route) => reach.push((prefix, best_route)),
            None => unreach.push(prefix),
        }
    }

    // Phase 3: Route Dissemination.
    if !reach.is_empty() || !unreach.is_empty() {
        for nbr in neighbors
            .values_mut()
            .filter(|nbr| nbr.state == fsm::State::Established)
        {
            // Skip neighbors that haven't this address-family enabled.
            if !nbr.is_af_enabled(A::AFI, A::SAFI) {
                continue;
            }

            // Evaluate routes eligible for distribution to this neighbor.
            //
            // Any routes that fail to meet the distribution criteria are
            // marked as unreachable to ensure previous advertisements are
            // withdrawn.
            let mut nbr_unreach = unreach.clone();
            let mut nbr_reach = Vec::with_capacity(reach.len());
            for (prefix, route) in &reach {
                if nbr.distribute_filter(route) {
                    nbr_reach.push((*prefix, route.as_ref()));
                } else {
                    nbr_unreach.push(*prefix);
                }
            }

            // Withdraw unfeasible routes immediately.
            if !nbr_unreach.is_empty() {
                withdraw_routes::<A>(nbr, table, &nbr_unreach);
            }

            // Advertise best routes.
            if !nbr_reach.is_empty() {
                advertise_routes::<A>(
                    nbr,
                    table,
                    nbr_reach,
                    &mut instance.state.rib.attr_sets,
                    instance.state.router_id,
                    instance.shared,
                    &instance.state.policy_apply_tasks,
                );
            }
        }
    }

    // Remove routing table entries that no longer hold any data.
    for prefix in queued_prefixes {
        if let prefix_trie::map::Entry::Occupied(entry) =
            table.prefixes.entry(prefix)
        {
            let dest = entry.get();
            if dest.local.is_none()
                && dest.adj_rib.values().all(|adj_rib| adj_rib.is_empty())
            {
                entry.remove();
            }
        }
    }

    Ok(())
}

fn withdraw_routes<A>(
    nbr: &mut Neighbor,
    table: &mut RoutingTable<A>,
    routes: &[A::IpNetwork],
) where
    A: AddressFamily,
{
    // Update Adj-RIB-Out.
    let counters = table.prefix_counters.entry(nbr.index).or_default();
    for prefix in routes {
        let dest = table.prefixes.get_mut(prefix).unwrap();
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.index) else {
            continue;
        };

        if adj_rib.remove_out(counters) {
            let update_queue = A::update_queue(&mut nbr.update_queues);
            update_queue.unreach.insert(*prefix);
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    if !msg_list.is_empty() {
        nbr.message_list_send(msg_list);
    }
}

pub(crate) fn advertise_routes<A>(
    nbr: &mut Neighbor,
    table: &mut RoutingTable<A>,
    routes: Vec<(A::IpNetwork, &BestRoute)>,
    attr_sets: &mut AttrSetsCxt,
    router_id: Ipv4Addr,
    shared: &InstanceShared,
    policy_apply_tasks: &PolicyApplyTasks,
) where
    A: AddressFamily,
{
    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Update pre-policy Adj-RIB-Out routes, grouping prefixes whose routes
    // share the same origin, type and interned attribute set so a single
    // route policy info is carried per distinct set.
    let mut updated_attrs = HashMap::new();
    let mut groups: BTreeMap<_, (RoutePolicyInfo, Vec<IpNetwork>)> =
        BTreeMap::new();
    for (prefix, route) in routes {
        // Update route's attributes before the export policies are applied.
        let route_attrs = updated_attrs
            .entry((route.attrs.key(), route.origin))
            .or_insert_with(|| {
                let mut attrs = route.attrs.get();
                rib::attrs_export_update::<A>(
                    &mut attrs, nbr, route, router_id,
                );
                attr_sets.get_route_attr_sets(&attrs)
            })
            .clone();

        // Store the route in the neighbor's pre-policy Adj-RIB-Out.
        let dest = table.prefixes.get_mut(&prefix).unwrap();
        let adj_rib = dest.adj_rib.entry(nbr.index).or_default();
        adj_rib.update_out_pre(Route {
            attrs: route_attrs.clone(),
            last_modified: route.last_modified,
        });

        // Add the prefix to the group matching the route's attribute set.
        let key = (route.origin, route.route_type, route_attrs.key());
        let (_, prefixes) = groups.entry(key).or_insert_with(|| {
            let rpinfo = RoutePolicyInfo::new(
                route.origin,
                route.route_type,
                None,
                None,
                route_attrs.get(),
            );
            (rpinfo, vec![])
        });
        prefixes.push(prefix.into());
    }

    // Enqueue export policy application, one message per group. Large groups
    // are split into fixed-size batches so their processing is spread across
    // all policy tasks.
    for (route, prefixes) in groups.into_values() {
        for prefixes in prefixes.chunks(POLICY_APPLY_BATCH_SIZE_MAX) {
            let msg = PolicyApplyMsg::Neighbor {
                policy_type: PolicyType::Export,
                nbr_addr: nbr.remote_addr,
                afi_safi: A::AFI_SAFI,
                prefixes: prefixes.to_vec(),
                route: route.clone(),
                policies: apply_policy_cfg
                    .export_policy
                    .iter()
                    .map(|policy| shared.policies.get(policy).unwrap().clone())
                    .collect(),
                match_sets: shared.policy_match_sets.clone(),
                default_policy: apply_policy_cfg.default_export_policy,
            };
            policy_apply_tasks.enqueue(msg);
        }
    }
}
