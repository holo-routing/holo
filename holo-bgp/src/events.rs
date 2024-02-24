//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use chrono::Utc;
use holo_protocol::InstanceShared;
use holo_utils::bgp::{RouteType, WellKnownCommunities};
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use holo_utils::policy::{PolicyResult, PolicyType};
use holo_utils::socket::{TcpConnInfo, TcpStream};
use ipnetwork::IpNetwork;
use num_traits::FromPrimitive;

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::error::{Error, IoError, NbrRxError};
use crate::instance::{InstanceUpView, PolicyApplyTasks};
use crate::neighbor::{fsm, Neighbor, Neighbors, PeerType};
use crate::packet::attribute::Attrs;
use crate::packet::consts::{Afi, Safi};
use crate::packet::message::{
    Capability, Message, MpReachNlri, MpUnreachNlri, RouteRefreshMsg, UpdateMsg,
};
use crate::policy::RoutePolicyInfo;
use crate::rib::{Rib, Route, RouteOrigin, RoutingTable};
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

    // Workaround to prevent connection collision until collision resolution
    // is implemented.
    if nbr.conn_info.is_some() {
        return Ok(());
    }

    // Initialize the accepted stream.
    network::accepted_stream_init(
        &stream,
        nbr.remote_addr.address_family(),
        nbr.tx_ttl(),
        nbr.config.transport.ttl_security,
        nbr.config.transport.tcp_mss,
    )
    .map_err(IoError::TcpSocketError)?;

    // Invoke FSM event.
    nbr.fsm_event(instance, fsm::Event::Connected(stream, conn_info));

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

    // Workaround to prevent connection collision until collision resolution
    // is implemented.
    if nbr.conn_info.is_some() {
        return Ok(());
    }

    // Invoke FSM event.
    nbr.fsm_event(instance, fsm::Event::Connected(stream, conn_info));

    Ok(())
}

// ===== neighbor message receipt =====

pub(crate) fn process_nbr_msg(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    msg: Result<Message, NbrRxError>,
) -> Result<(), Error> {
    // Lookup neighbor.
    let Some(nbr) = neighbors.get_mut(&nbr_addr) else {
        return Ok(());
    };

    // Process received message.
    match msg {
        Ok(msg) => {
            Debug::NbrMsgRx(&nbr.remote_addr, &msg).log();

            // Update statistics.
            nbr.statistics.msgs_rcvd.update(&msg);

            match msg {
                Message::Open(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdOpen(msg));
                }
                Message::Update(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdUpdate);
                    process_nbr_update(instance, nbr, msg)?;
                }
                Message::Notification(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdNotif(msg.clone()));
                    // Keep track of the last received notification.
                    nbr.notification_rcvd = Some((Utc::now(), msg));
                }
                Message::Keepalive(_) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdKalive);
                }
                Message::RouteRefresh(msg) => {
                    process_nbr_route_refresh(instance, nbr, msg)?;
                }
            }
        }
        Err(error) => match error {
            NbrRxError::TcpConnClosed(_) => {
                nbr.fsm_event(instance, fsm::Event::ConnFail);
            }
            NbrRxError::MsgDecodeError(_, error) => {
                nbr.fsm_event(instance, fsm::Event::RcvdError(error));
            }
        },
    }

    Ok(())
}

fn process_nbr_update(
    instance: &mut InstanceUpView<'_>,
    nbr: &mut Neighbor,
    msg: UpdateMsg,
) -> Result<(), Error> {
    let rib = &mut instance.state.rib;

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
                        nbr, rib, prefixes,
                    );
                }
                MpReachNlri::Ipv6Unicast { prefixes, .. } => {
                    process_nbr_unreach_prefixes::<Ipv6Unicast>(
                        nbr, rib, prefixes,
                    );
                }
            }
        }
    }

    // Process IPv4 unreachable NLRIs.
    if let Some(unreach) = msg.unreach {
        process_nbr_unreach_prefixes::<Ipv4Unicast>(nbr, rib, unreach.prefixes);
    }

    // Process multiprotocol unreachable NLRIs.
    if let Some(mp_unreach) = msg.mp_unreach {
        match mp_unreach {
            MpUnreachNlri::Ipv4Unicast { prefixes } => {
                process_nbr_unreach_prefixes::<Ipv4Unicast>(nbr, rib, prefixes);
            }
            MpUnreachNlri::Ipv6Unicast { prefixes } => {
                process_nbr_unreach_prefixes::<Ipv6Unicast>(nbr, rib, prefixes);
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
    for prefix in &nlri_prefixes {
        let dest = table.prefixes.entry(*prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
        let route = Route::new(origin, route_attrs.clone(), route_type);
        adj_rib.in_pre = Some(Box::new(route));
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Enqueue import policy application.
    let rpinfo = RoutePolicyInfo::new(origin, attrs, route_type);
    let msg = PolicyApplyMsg::Neighbor {
        policy_type: PolicyType::Import,
        nbr_addr: nbr.remote_addr,
        afi_safi: A::AFI_SAFI,
        routes: nlri_prefixes
            .into_iter()
            .map(|prefix| (prefix.into(), rpinfo.clone()))
            .collect(),
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
) where
    A: AddressFamily,
{
    // Check if the address-family is enabled for this session.
    if !nbr.is_af_enabled(A::AFI, A::SAFI) {
        return;
    }

    // Remove routes from Adj-RIB-In.
    let table = A::table(&mut rib.tables);
    for prefix in nlri_prefixes {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.remote_addr) else {
            continue;
        };

        adj_rib.in_pre = None;
        adj_rib.in_post = None;

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
    if nbr.capabilities_adv.get(&cap).is_none() {
        return Ok(());
    }

    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => {
            process_nbr_route_refresh_af::<Ipv4Unicast>(instance, nbr)
        }
        (Afi::Ipv6, Safi::Unicast) => {
            process_nbr_route_refresh_af::<Ipv6Unicast>(instance, nbr)
        }
        _ => {
            // Ignore unsupported AFI/SAFI combination.
            return Ok(());
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    nbr.message_list_send(msg_list);

    Ok(())
}

fn process_nbr_route_refresh_af<A>(
    instance: &mut InstanceUpView<'_>,
    nbr: &mut Neighbor,
) where
    A: AddressFamily,
{
    let table = A::table(&mut instance.state.rib.tables);
    let update_queue = A::update_queue(&mut nbr.update_queues);
    for (prefix, dest) in &table.prefixes {
        let route = dest.local.as_ref().unwrap();
        let attrs = route.attrs.get();
        update_queue.reach.entry(attrs).or_default().insert(*prefix);
    }
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

    // Invoke FSM event.
    nbr.fsm_event(instance, fsm::Event::Timer(timer));

    Ok(())
}

// ===== neighbor policy import result =====

pub(crate) fn process_nbr_policy_import<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
    prefixes: Vec<(IpNetwork, PolicyResult<RoutePolicyInfo>)>,
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
    for (prefix, result) in prefixes {
        // Get RIB destination.
        let prefix = A::IpNetwork::get(prefix).unwrap();
        let dest = table.prefixes.entry(prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();

        // Update post-policy Adj-RIB-In routes.
        match result {
            PolicyResult::Accept(rpinfo) => {
                let route = Route::new(
                    rpinfo.origin,
                    rib.attr_sets.get_route_attr_sets(&rpinfo.attrs),
                    rpinfo.route_type,
                );
                adj_rib.in_post = Some(Box::new(route));
            }
            PolicyResult::Reject => {
                adj_rib.in_post = None;
            }
        }

        // Enqueue prefix for the BGP Decision Process.
        table.queued_prefixes.insert(prefix);
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
    prefixes: Vec<(IpNetwork, PolicyResult<RoutePolicyInfo>)>,
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
    for (prefix, result) in prefixes {
        // Get RIB destination.
        let prefix = A::IpNetwork::get(prefix).unwrap();
        let dest = table.prefixes.entry(prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();

        // Update post-policy Adj-RIB-Out routes.
        match result {
            PolicyResult::Accept(rpinfo) => {
                let route = Route::new(
                    rpinfo.origin,
                    rib.attr_sets.get_route_attr_sets(&rpinfo.attrs),
                    rpinfo.route_type,
                );

                let mut update = false;
                if let Some(adj_rib_route) = &mut adj_rib.out_post {
                    if adj_rib_route.attrs != route.attrs {
                        *adj_rib_route = Box::new(route);
                        update = true;
                    }
                } else {
                    adj_rib.out_post = Some(Box::new(route));
                    update = true;
                }

                // If the Adj-RIB-Out was updated, enqueue the route for
                // transmission.
                if update {
                    // Update route's attributes before transmission.
                    let mut attrs = rpinfo.attrs;
                    attrs_tx_update::<A>(nbr, instance.config.asn, &mut attrs);

                    // Update neighbor's Tx queue.
                    let update_queue = A::update_queue(&mut nbr.update_queues);
                    update_queue.reach.entry(attrs).or_default().insert(prefix);
                }
            }
            PolicyResult::Reject => {
                if adj_rib.out_post.take().is_some() {
                    // Update neighbor's Tx queue.
                    let update_queue = A::update_queue(&mut nbr.update_queues);
                    update_queue.unreach.insert(prefix);
                }
            }
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    nbr.message_list_send(msg_list);

    Ok(())
}

fn attrs_tx_update<A>(nbr: &Neighbor, local_asn: u32, attrs: &mut Attrs)
where
    A: AddressFamily,
{
    match nbr.peer_type {
        PeerType::Internal => {
            // Attach LOCAL_PREF with default value if it's missing.
            if attrs.base.local_pref.is_none() {
                attrs.base.local_pref = Some(rib::DFLT_LOCAL_PREF);
            }
        }
        PeerType::External => {
            // Prepend local AS number.
            attrs.base.as_path.prepend(local_asn);

            // Do not propagate the MULTI_EXIT_DISC attribute.
            attrs.base.med = None;

            // Remove the LOCAL_PREF attribute.
            attrs.base.local_pref = None;
        }
    }

    // Update the next-hop attribute based on the address family if necessary.
    A::nexthop_tx_change(nbr, &mut attrs.base);
}

// ===== BGP decision process =====

pub(crate) fn decision_process<A>(
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
    for prefix in queued_prefixes {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };

        // Perform best-path selection for the destination.
        let best_route =
            rib::best_path(dest, instance.config.asn, selection_cfg);

        // Update the Loc-RIB with the best path.
        rib::loc_rib_update::<A>(
            prefix,
            dest,
            best_route.clone(),
            selection_cfg,
            mpath_cfg,
            &instance.config.distance,
            &instance.tx.ibus,
        );

        // Group best routes and unfeasible routes separately.
        match best_route {
            Some(best_route) => reach.push((prefix, best_route)),
            None => unreach.push(prefix),
        }
    }

    // Phase 3: Route Dissemination.
    for nbr in neighbors
        .values_mut()
        .filter(|nbr| nbr.state == fsm::State::Established)
    {
        // Skip neighbors that haven't this address-family enabled.
        if !nbr.is_af_enabled(A::AFI, A::SAFI) {
            continue;
        }

        // Withdraw unfeasible routes immediately.
        if !unreach.is_empty() {
            withdraw_routes::<A>(nbr, table, &unreach);
        }

        // Advertise best routes.
        if !reach.is_empty() {
            advertise_routes::<A>(
                nbr,
                table,
                &reach,
                instance.shared,
                &instance.state.policy_apply_tasks,
            );
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
    for prefix in routes {
        let dest = table.prefixes.get_mut(prefix).unwrap();
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.remote_addr) else {
            continue;
        };

        adj_rib.out_pre = None;
        if adj_rib.out_post.take().is_some() {
            let update_queue = A::update_queue(&mut nbr.update_queues);
            update_queue.unreach.insert(*prefix);
        }
    }

    // Send UPDATE message(s) to the neighbor.
    let msg_list = nbr.update_queues.build_updates();
    nbr.message_list_send(msg_list);
}

pub(crate) fn advertise_routes<A>(
    nbr: &mut Neighbor,
    table: &mut RoutingTable<A>,
    routes: &[(A::IpNetwork, Box<Route>)],
    shared: &InstanceShared,
    policy_apply_tasks: &PolicyApplyTasks,
) where
    A: AddressFamily,
{
    // Create an iterator over the best routes, filtering out routes that
    // should not be redistributed to this neighbor.
    let routes = routes.iter().filter(|(_, route)| {
        // Suppress advertisements to peers if their AS number is present
        // in the AS path of the route, unless overridden by configuration.
        if !nbr.config.as_path_options.disable_peer_as_filter
            && route.attrs.base.value.as_path.contains(nbr.config.peer_as)
        {
            return false;
        }

        // RFC 4271 - Section 9.2:
        // "When a BGP speaker receives an UPDATE message from an internal
        // peer, the receiving BGP speaker SHALL NOT re-distribute the
        // routing information contained in that UPDATE message to other
        // internal peers".
        if route.route_type == RouteType::Internal
            && let RouteOrigin::Neighbor { remote_addr, .. } = &route.origin
            && *remote_addr == nbr.remote_addr
        {
            return false;
        }

        // Handle well-known communities.
        if let Some(comm) = &route.attrs.comm {
            for comm in comm
                .value
                .iter()
                .filter_map(|comm| WellKnownCommunities::from_u32(comm.0))
            {
                // Do not advertise to any other peer.
                if comm == WellKnownCommunities::NoAdvertise {
                    return false;
                }

                // Do not advertise to external peers.
                if nbr.peer_type == PeerType::External
                    && (comm == WellKnownCommunities::NoExport
                        || comm == WellKnownCommunities::NoExportSubconfed)
                {
                    return false;
                }
            }
        }

        true
    });

    // Update pre-policy Adj-RIB-Out routes.
    for (prefix, route) in routes.clone() {
        let dest = table.prefixes.get_mut(prefix).unwrap();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
        adj_rib.out_pre = Some(route.clone());
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Enqueue export policy application.
    let msg = PolicyApplyMsg::Neighbor {
        policy_type: PolicyType::Export,
        nbr_addr: nbr.remote_addr,
        afi_safi: A::AFI_SAFI,
        routes: routes
            .into_iter()
            .map(|(prefix, route)| ((*prefix).into(), route.policy_info()))
            .collect(),
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
