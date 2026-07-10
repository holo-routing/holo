//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use holo_protocol::InstanceShared;
use holo_utils::bgp::{AfiSafi, RouteType};
use holo_utils::ibus::IbusChannelsTx;
use holo_utils::ip::IpAddrKind;
use holo_utils::mpls::Label;
use holo_utils::policy::{ApplyPolicyCfg, PolicyResult, PolicyType};
use holo_utils::socket::{TcpConnInfo, TcpStream};
use ipnetwork::IpNetwork;
use num_traits::FromPrimitive;

use crate::af::{
    AddressFamily, Ipv4Unicast, Ipv6Unicast, L2vpnEvpn, Vpnv4Prefix,
    Vpnv4Unicast, Vpnv6Prefix, Vpnv6Unicast,
};
use crate::debug::Debug;
use crate::error::{Error, IoError, NbrRxError};
use crate::instance::{InstanceState, InstanceUpView, PolicyApplyTasks};
use crate::neighbor::{Neighbor, Neighbors, PeerType, fsm};
use crate::packet::attribute::Attrs;
use crate::packet::iana::{Afi, CeaseSubcode, ErrorCode, Safi};
use crate::packet::message::{
    Capability, EvpnRoute, Message, MpReachNlri, MpUnreachNlri,
    NotificationMsg, RouteRefreshMsg, UpdateMsg,
};
use crate::policy::RoutePolicyInfo;
use crate::rib::{AttrSetsCxt, Rib, Route, RouteOrigin, RoutingTable};
use crate::tasks::messages::output::PolicyApplyMsg;
use crate::{evpn, network, rib};

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
            if nbr.config.trace_opts.packets_resolved.load().rx(&msg) {
                Debug::NbrMsgRx(&nbr.remote_addr, &msg).log();
            }

            // Update statistics.
            nbr.statistics.msgs_rcvd.update(&msg);

            match msg {
                Message::Open(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdOpen(msg));
                }
                Message::Update(msg) => {
                    nbr.fsm_event(instance, fsm::Event::RcvdUpdate);
                    if nbr.state == fsm::State::Established {
                        if process_nbr_update(instance, nbr, msg)? {
                            let msg = NotificationMsg::new(
                                ErrorCode::Cease,
                                CeaseSubcode::MaximumNumberofPrefixesReached,
                            );
                            nbr.fsm_event(
                                instance,
                                fsm::Event::Stop(Some(msg)),
                            );
                        }
                    }
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
            NbrRxError::TcpConnClosed => {
                nbr.fsm_event(instance, fsm::Event::ConnFail);
            }
            NbrRxError::MsgDecodeError(error) => {
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
) -> Result<bool, Error> {
    let rib = &mut instance.state.rib;
    let ibus_tx = &instance.tx.ibus;

    // Process IPv4 reachable NLRIs.
    //
    // Use nexthop from the NEXTHOP attribute.
    if let Some(reach) = msg.reach {
        if let Some(attrs) = &msg.attrs {
            let mut attrs = attrs.clone();
            attrs.base.nexthop = Some(reach.nexthop.into());
            if process_nbr_reach_prefixes::<Ipv4Unicast>(
                nbr,
                rib,
                reach.prefixes,
                attrs,
                instance.config.asn,
                instance.shared,
                &instance.state.policy_apply_tasks,
            ) {
                return Ok(true);
            }
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
                    if process_nbr_reach_prefixes::<Ipv4Unicast>(
                        nbr,
                        rib,
                        prefixes,
                        attrs,
                        instance.config.asn,
                        instance.shared,
                        &instance.state.policy_apply_tasks,
                    ) {
                        return Ok(true);
                    }
                }
                MpReachNlri::Ipv6Unicast {
                    prefixes,
                    nexthop,
                    ll_nexthop,
                } => {
                    attrs.base.nexthop = Some(nexthop.into());
                    attrs.base.ll_nexthop = ll_nexthop;
                    if process_nbr_reach_prefixes::<Ipv6Unicast>(
                        nbr,
                        rib,
                        prefixes,
                        attrs,
                        instance.config.asn,
                        instance.shared,
                        &instance.state.policy_apply_tasks,
                    ) {
                        return Ok(true);
                    }
                }
                MpReachNlri::L3vpnIpv4Unicast { prefixes, nexthop } => {
                    attrs.base.nexthop = Some(nexthop.into());
                    let prefixes = prefixes
                        .into_iter()
                        .map(|nlri| {
                            (
                                Vpnv4Prefix {
                                    rd: nlri.rd,
                                    prefix: nlri.prefix,
                                },
                                Label::new(nlri.label),
                            )
                        })
                        .collect();
                    if process_nbr_reach_prefixes_pre_policy::<Vpnv4Unicast>(
                        nbr, rib, prefixes, attrs, ibus_tx,
                    ) {
                        return Ok(true);
                    }
                }
                MpReachNlri::L3vpnIpv6Unicast { prefixes, nexthop } => {
                    attrs.base.nexthop = Some(nexthop.into());
                    let prefixes = prefixes
                        .into_iter()
                        .map(|nlri| {
                            (
                                Vpnv6Prefix {
                                    rd: nlri.rd,
                                    prefix: nlri.prefix,
                                },
                                Label::new(nlri.label),
                            )
                        })
                        .collect();
                    if process_nbr_reach_prefixes_pre_policy::<Vpnv6Unicast>(
                        nbr, rib, prefixes, attrs, ibus_tx,
                    ) {
                        return Ok(true);
                    }
                }
                MpReachNlri::L2vpnEvpn { routes, nexthop } => {
                    attrs.base.nexthop = Some(nexthop);
                    let routes = routes
                        .into_iter()
                        .map(|route| (route, Label::new(0)))
                        .collect();
                    if process_nbr_reach_prefixes_pre_policy::<L2vpnEvpn>(
                        nbr, rib, routes, attrs, ibus_tx,
                    ) {
                        return Ok(true);
                    }
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
                MpReachNlri::L3vpnIpv4Unicast { prefixes, .. } => {
                    let prefixes = prefixes
                        .into_iter()
                        .map(|nlri| Vpnv4Prefix {
                            rd: nlri.rd,
                            prefix: nlri.prefix,
                        })
                        .collect();
                    process_nbr_unreach_prefixes::<Vpnv4Unicast>(
                        nbr, rib, prefixes, ibus_tx,
                    );
                }
                MpReachNlri::L3vpnIpv6Unicast { prefixes, .. } => {
                    let prefixes = prefixes
                        .into_iter()
                        .map(|nlri| Vpnv6Prefix {
                            rd: nlri.rd,
                            prefix: nlri.prefix,
                        })
                        .collect();
                    process_nbr_unreach_prefixes::<Vpnv6Unicast>(
                        nbr, rib, prefixes, ibus_tx,
                    );
                }
                MpReachNlri::L2vpnEvpn { routes, .. } => {
                    process_evpn_unreach_routes(nbr, rib, routes, ibus_tx);
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
            MpUnreachNlri::L3vpnIpv4Unicast { prefixes } => {
                let prefixes = prefixes
                    .into_iter()
                    .map(|nlri| Vpnv4Prefix {
                        rd: nlri.rd,
                        prefix: nlri.prefix,
                    })
                    .collect();
                process_nbr_unreach_prefixes::<Vpnv4Unicast>(
                    nbr, rib, prefixes, ibus_tx,
                );
            }
            MpUnreachNlri::L3vpnIpv6Unicast { prefixes } => {
                let prefixes = prefixes
                    .into_iter()
                    .map(|nlri| Vpnv6Prefix {
                        rd: nlri.rd,
                        prefix: nlri.prefix,
                    })
                    .collect();
                process_nbr_unreach_prefixes::<Vpnv6Unicast>(
                    nbr, rib, prefixes, ibus_tx,
                );
            }
            MpUnreachNlri::L2vpnEvpn { routes } => {
                process_evpn_unreach_routes(nbr, rib, routes, ibus_tx);
            }
        }
    }

    // Schedule the BGP Decision Process.
    instance.state.schedule_decision_process(instance.tx);

    Ok(false)
}

fn process_nbr_reach_prefixes<A>(
    nbr: &Neighbor,
    rib: &mut Rib,
    nlri_prefixes: Vec<A::Prefix>,
    attrs: Attrs,
    _local_asn: u32,
    shared: &InstanceShared,
    policy_apply_tasks: &PolicyApplyTasks,
) -> bool
where
    A: AddressFamily,
{
    // Check if the address-family is enabled for this session.
    if !nbr.is_af_enabled(A::AFI, A::SAFI) {
        return false;
    }

    let table = A::table(&mut rib.tables);
    if prefix_limit_exceeded(nbr, table, nlri_prefixes.iter()) {
        return true;
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

    // Update pre-policy Adj-RIB-In routes.
    let route_attrs = rib.attr_sets.get_route_attr_sets(&attrs);
    for prefix in &nlri_prefixes {
        let dest = table.prefixes.entry(*prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
        let route = Route::new(origin, route_attrs.clone(), route_type);
        adj_rib.update_in_pre(Box::new(route), &mut rib.attr_sets);
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Enqueue import policy application.
    let rpinfo =
        RoutePolicyInfo::new(origin, route_type, None, None, None, attrs);
    let mut missing_policy = false;
    let policies = apply_policy_cfg
        .import_policy
        .iter()
        .filter_map(|policy| match shared.policies.get(policy) {
            Some(policy) => Some(policy.clone()),
            None => {
                missing_policy = true;
                None
            }
        })
        .collect();
    let msg = PolicyApplyMsg::Neighbor {
        policy_type: PolicyType::Import,
        nbr_addr: nbr.remote_addr,
        afi_safi: A::AFI_SAFI,
        routes: nlri_prefixes
            .into_iter()
            .map(|prefix| (A::prefix_to_ip_network(prefix), rpinfo.clone()))
            .collect(),
        missing_policy,
        policies,
        match_sets: shared.policy_match_sets.clone(),
        default_policy: apply_policy_cfg.default_import_policy,
    };
    policy_apply_tasks.enqueue(msg);

    false
}

fn process_nbr_reach_prefixes_pre_policy<A>(
    nbr: &Neighbor,
    rib: &mut Rib,
    nlri_prefixes: Vec<(A::Prefix, Label)>,
    attrs: Attrs,
    ibus_tx: &IbusChannelsTx,
) -> bool
where
    A: AddressFamily,
{
    // Check if the address-family is enabled for this session.
    if !nbr.is_af_enabled(A::AFI, A::SAFI) {
        return false;
    }

    let table = A::table(&mut rib.tables);
    if prefix_limit_exceeded(
        nbr,
        table,
        nlri_prefixes.iter().map(|(prefix, _)| prefix),
    ) {
        return true;
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

    // Keep VPN routes in Adj-RIB-In and accept them into post-policy until the
    // import policy path can carry RD-qualified keys instead of plain IP
    // networks.
    let route_attrs = rib.attr_sets.get_route_attr_sets(&attrs);
    for (prefix, label) in nlri_prefixes {
        let dest = table.prefixes.entry(prefix).or_default();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
        let mut route = Route::new(origin, route_attrs.clone(), route_type);
        route.vpn_label = Some(label);

        if let Some(old_route) = adj_rib.in_post() {
            rib::nexthop_untrack(&mut table.nht, &prefix, old_route, ibus_tx);
        }
        rib::nexthop_track(&mut table.nht, prefix, &route, ibus_tx);

        adj_rib.update_in_pre(Box::new(route.clone()), &mut rib.attr_sets);
        adj_rib.update_in_post(Box::new(route), &mut rib.attr_sets);

        // Enqueue the prefix so later decision-process wiring sees all VPN
        // changes that arrived before full import/export support.
        table.queued_prefixes.insert(prefix);
    }

    false
}

fn prefix_limit_exceeded<'a, A, I>(
    nbr: &Neighbor,
    table: &RoutingTable<A>,
    prefixes: I,
) -> bool
where
    A: AddressFamily,
    I: IntoIterator<Item = &'a A::Prefix>,
    A::Prefix: 'a,
{
    let limit = nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.prefix_limit)
        .filter(|limit| limit.max_prefixes.is_some())
        .unwrap_or(&nbr.config.prefix_limit);

    let Some(max_prefixes) = limit.max_prefixes else {
        return false;
    };

    if !limit.teardown {
        return false;
    }

    let current = table
        .prefixes
        .values()
        .filter_map(|dest| dest.adj_rib.get(&nbr.remote_addr))
        .filter(|adj_rib| adj_rib.in_pre().is_some())
        .count();

    let new = prefixes
        .into_iter()
        .filter(|prefix| {
            !table
                .prefixes
                .get(prefix)
                .and_then(|dest| dest.adj_rib.get(&nbr.remote_addr))
                .is_some_and(|adj_rib| adj_rib.in_pre().is_some())
        })
        .copied()
        .collect::<BTreeSet<_>>()
        .len();

    current + new > max_prefixes as usize
}

fn collect_policies(
    apply_policy_cfg: &ApplyPolicyCfg,
    shared: &InstanceShared,
) -> (bool, Vec<std::sync::Arc<holo_utils::policy::Policy>>) {
    let mut missing_policy = false;
    let policies = apply_policy_cfg
        .import_policy
        .iter()
        .filter_map(|policy| match shared.policies.get(policy) {
            Some(policy) => Some(policy.clone()),
            None => {
                missing_policy = true;
                None
            }
        })
        .collect();

    (missing_policy, policies)
}

pub(crate) fn reapply_nbr_import_policy_for_nbr<A>(
    state: &mut InstanceState,
    shared: &InstanceShared,
    nbr: &Neighbor,
) where
    A: AddressFamily,
{
    if nbr.state < fsm::State::Established
        || !nbr.is_af_enabled(A::AFI, A::SAFI)
    {
        return;
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    let (missing_policy, policies) = collect_policies(apply_policy_cfg, shared);

    // Re-evaluate the retained pre-policy Adj-RIB-In, never the previously
    // policy-mutated post-policy copy.
    let table = A::table(&mut state.rib.tables);
    let routes = table
        .prefixes
        .iter()
        .filter_map(|(prefix, dest)| {
            dest.adj_rib
                .get(&nbr.remote_addr)
                .and_then(|adj_rib| adj_rib.in_pre())
                .map(|route| {
                    (A::prefix_to_ip_network(*prefix), route.policy_info())
                })
        })
        .collect::<Vec<_>>();

    if routes.is_empty() {
        return;
    }

    let msg = PolicyApplyMsg::Neighbor {
        policy_type: PolicyType::Import,
        nbr_addr: nbr.remote_addr,
        afi_safi: A::AFI_SAFI,
        routes,
        missing_policy,
        policies,
        match_sets: shared.policy_match_sets.clone(),
        default_policy: apply_policy_cfg.default_import_policy,
    };
    state.policy_apply_tasks.enqueue(msg);
}

pub(crate) fn reapply_nbr_import_policy<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
    nbr_addr: IpAddr,
) where
    A: AddressFamily,
{
    let Some(nbr) = neighbors.get(&nbr_addr) else {
        return;
    };

    reapply_nbr_import_policy_for_nbr::<A>(
        instance.state,
        instance.shared,
        nbr,
    );
}

pub(crate) fn reapply_import_policy_all<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
) where
    A: AddressFamily,
{
    let nbr_addrs = neighbors.keys().copied().collect::<Vec<_>>();
    for nbr_addr in nbr_addrs {
        reapply_nbr_import_policy::<A>(instance, neighbors, nbr_addr);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use holo_protocol::InstanceShared;
    use holo_utils::bgp::{AfiSafi, RouteType};
    use holo_utils::policy::Policy;
    use ipnetwork::Ipv4Network;

    use super::*;
    use crate::af::Ipv4Unicast;
    use crate::instance::{InstanceState, PolicyApplyTasks};
    use crate::neighbor::{Neighbor, PeerType, fsm};
    use crate::northbound::configuration::NeighborAfiSafiCfg;
    use crate::packet::attribute::Attrs;
    use crate::rib::{Rib, RouteOrigin};

    #[test]
    fn import_reapply_uses_retained_adj_rib_in_pre() {
        let remote_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut state = InstanceState {
            router_id: Ipv4Addr::new(192, 0, 2, 1),
            listening_sockets: Vec::new(),
            policy_apply_tasks: PolicyApplyTasks::new_for_testing(tx),
            decision_process_task: None,
            rib: Rib::default(),
            interfaces: Default::default(),
        };
        let mut shared = InstanceShared::default();
        shared.policies.insert(
            "SOFT-IN".to_owned(),
            Arc::new(Policy::new("SOFT-IN".to_owned())),
        );

        let mut nbr = Neighbor::new(remote_addr, PeerType::External);
        nbr.state = fsm::State::Established;
        nbr.identifier = Some(Ipv4Addr::new(192, 0, 2, 2));
        nbr.config
            .afi_safi
            .insert(AfiSafi::Ipv4Unicast, NeighborAfiSafiCfg::default());
        let afi_safi =
            nbr.config.afi_safi.get_mut(&AfiSafi::Ipv4Unicast).unwrap();
        afi_safi.enabled = true;
        afi_safi
            .apply_policy
            .import_policy
            .insert("SOFT-IN".to_owned());

        let origin = RouteOrigin::Neighbor {
            identifier: nbr.identifier.unwrap(),
            remote_addr,
        };
        let attrs = state.rib.attr_sets.get_route_attr_sets(&Attrs::default());
        let table = Ipv4Unicast::table(&mut state.rib.tables);
        for prefix in ["198.51.100.1/32", "198.51.100.2/32"] {
            let prefix: Ipv4Network = prefix.parse().unwrap();
            let route = Route::new(origin, attrs.clone(), RouteType::External);
            table
                .prefixes
                .entry(prefix)
                .or_default()
                .adj_rib
                .entry(remote_addr)
                .or_default()
                .update_in_pre(Box::new(route), &mut state.rib.attr_sets);
        }

        let accepted_prefix: Ipv4Network = "198.51.100.1/32".parse().unwrap();
        let route = Route::new(origin, attrs, RouteType::External);
        table
            .prefixes
            .entry(accepted_prefix)
            .or_default()
            .adj_rib
            .entry(remote_addr)
            .or_default()
            .update_in_post(Box::new(route), &mut state.rib.attr_sets);

        reapply_nbr_import_policy_for_nbr::<Ipv4Unicast>(
            &mut state, &shared, &nbr,
        );

        let msg = rx.try_recv().unwrap();
        let PolicyApplyMsg::Neighbor {
            policy_type,
            nbr_addr,
            afi_safi,
            routes,
            missing_policy,
            policies,
            ..
        } = msg
        else {
            panic!("unexpected policy apply message");
        };
        assert!(matches!(policy_type, PolicyType::Import));
        assert_eq!(nbr_addr, remote_addr);
        assert_eq!(afi_safi, AfiSafi::Ipv4Unicast);
        assert!(!missing_policy);
        assert_eq!(policies.len(), 1);
        assert_eq!(
            routes
                .into_iter()
                .map(|(prefix, _)| prefix)
                .collect::<Vec<_>>(),
            vec![
                "198.51.100.1/32".parse().unwrap(),
                "198.51.100.2/32".parse().unwrap(),
            ]
        );
    }
}

fn process_nbr_unreach_prefixes<A>(
    nbr: &Neighbor,
    rib: &mut Rib,
    nlri_prefixes: Vec<A::Prefix>,
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
    for prefix in nlri_prefixes {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.remote_addr) else {
            continue;
        };

        adj_rib.remove_in_pre(&mut rib.attr_sets);
        if let Some(route) = adj_rib.remove_in_post(&mut rib.attr_sets) {
            rib::nexthop_untrack(&mut table.nht, &prefix, &route, ibus_tx);
        }

        // Enqueue prefix for the BGP Decision Process.
        table.queued_prefixes.insert(prefix);
    }
}

fn process_evpn_unreach_routes(
    nbr: &Neighbor,
    rib: &mut Rib,
    routes: Vec<EvpnRoute>,
    ibus_tx: &IbusChannelsTx,
) {
    let mass_withdraw_esis = routes
        .iter()
        .filter_map(|route| match route {
            EvpnRoute::EthernetAutoDiscovery(route)
                if evpn::ead_per_es(route.ethernet_tag_id, route.label) =>
            {
                Some(route.esi)
            }
            EvpnRoute::EthernetSegment(route) => Some(route.esi),
            _ => None,
        })
        .collect::<Vec<_>>();

    process_nbr_unreach_prefixes::<L2vpnEvpn>(nbr, rib, routes, ibus_tx);

    for esi in mass_withdraw_esis {
        process_evpn_mass_withdraw(nbr, rib, esi, ibus_tx);
    }
}

fn process_evpn_mass_withdraw(
    nbr: &Neighbor,
    rib: &mut Rib,
    esi: [u8; 10],
    ibus_tx: &IbusChannelsTx,
) {
    let table = L2vpnEvpn::table(&mut rib.tables);
    let prefixes = table
        .prefixes
        .iter()
        .filter_map(|(prefix, dest)| {
            if !matches!(prefix, EvpnRoute::MacIpAdvertisement(_)) {
                return None;
            }
            let route = dest
                .adj_rib
                .get(&nbr.remote_addr)
                .and_then(|adj_rib| adj_rib.in_post())?;
            let RouteOrigin::Neighbor { remote_addr, .. } = route.origin else {
                return None;
            };
            Some((remote_addr, *prefix))
        })
        .collect::<Vec<_>>();
    let prefixes =
        evpn::mass_withdraw_mac_routes(prefixes, nbr.remote_addr, esi);

    for prefix in prefixes {
        let Some(dest) = table.prefixes.get_mut(&prefix) else {
            continue;
        };
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.remote_addr) else {
            continue;
        };

        adj_rib.remove_in_pre(&mut rib.attr_sets);
        if let Some(route) = adj_rib.remove_in_post(&mut rib.attr_sets) {
            rib::nexthop_untrack(&mut table.nht, &prefix, &route, ibus_tx);
        }
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
        let prefix = A::prefix_from_ip_network(prefix).unwrap();
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

                // Update nexthop tracking.
                if let Some(old_route) = adj_rib.in_post() {
                    rib::nexthop_untrack(
                        &mut table.nht,
                        &prefix,
                        old_route,
                        &instance.tx.ibus,
                    );
                }
                rib::nexthop_track(
                    &mut table.nht,
                    prefix,
                    &route,
                    &instance.tx.ibus,
                );

                adj_rib.update_in_post(Box::new(route), &mut rib.attr_sets);
            }
            PolicyResult::Reject => {
                if let Some(route) = adj_rib.remove_in_post(&mut rib.attr_sets)
                {
                    rib::nexthop_untrack(
                        &mut table.nht,
                        &prefix,
                        &route,
                        &instance.tx.ibus,
                    );
                }
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
        let prefix = A::prefix_from_ip_network(prefix).unwrap();
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

                // Check if the Adj-RIB-Out was updated.
                let update = if let Some(adj_rib_route) = adj_rib.out_post() {
                    adj_rib_route.attrs != route.attrs
                } else {
                    true
                };

                if update {
                    adj_rib
                        .update_out_post(Box::new(route), &mut rib.attr_sets);

                    // Update route's attributes before transmission.
                    let mut attrs = rpinfo.attrs;
                    rib::attrs_tx_update::<A>(
                        &mut attrs,
                        nbr,
                        instance.config.asn,
                        nbr.config
                            .route_reflector
                            .cluster_id
                            .or(instance.config.identifier),
                        rpinfo.origin,
                        rpinfo.route_type,
                        rpinfo.origin.is_local(),
                    );

                    // Update neighbor's Tx queue.
                    let update_queue = A::update_queue(&mut nbr.update_queues);
                    update_queue.reach.entry(attrs).or_default().insert(prefix);
                }
            }
            PolicyResult::Reject => {
                if adj_rib.remove_out_post(&mut rib.attr_sets).is_some() {
                    // Update neighbor's Tx queue.
                    let update_queue = A::update_queue(&mut nbr.update_queues);
                    update_queue.unreach.insert(prefix);
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
    let prefix = A::prefix_from_ip_network(prefix).unwrap();

    match result {
        PolicyResult::Accept(rpinfo) => {
            // Get prefix RIB entry.
            let dest = table.prefixes.entry(prefix).or_default();

            // Update redistributed route in the RIB.
            let route_attrs = rib.attr_sets.get_route_attr_sets(&rpinfo.attrs);
            let route = Route::new(
                rpinfo.origin,
                route_attrs.clone(),
                RouteType::Internal,
            );
            dest.redistribute = Some(Box::new(route));
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

pub(crate) fn decision_process<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &mut Neighbors,
) -> Result<(), Error>
where
    A: AddressFamily,
{
    sync_default_originate::<A>(instance, neighbors);

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

    let cluster_ids = local_cluster_ids(instance.config.identifier, neighbors);

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
            prefix,
            dest,
            instance.config.asn,
            instance.config.identifier,
            &cluster_ids,
            neighbors,
            &table.nht,
            selection_cfg,
        );

        // Update the Loc-RIB with the best path.
        rib::loc_rib_update::<A>(
            prefix,
            dest,
            best_route.clone(),
            &mut instance.state.rib.attr_sets,
            selection_cfg,
            mpath_cfg,
            &instance.config.distance,
            &instance.config.trace_opts,
            instance.shared,
            &instance.tx.ibus,
        );

        // Group best routes and unfeasible routes separately.
        match best_route {
            Some(best_route) => reach.push((prefix, best_route)),
            None => unreach.push(prefix),
        }
    }

    if A::DISSEMINATE {
        // Phase 3: Route Dissemination.
        let rr_clients = neighbors
            .iter()
            .map(|(addr, nbr)| (*addr, nbr.config.route_reflector.client))
            .collect::<BTreeMap<_, _>>();

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
            let mut nbr_reach = reach.clone();
            nbr_unreach.extend(
                nbr_reach
                    .extract_if(.., |(prefix, route)| {
                        !nbr.distribute_filter::<A>(
                            *prefix,
                            route,
                            source_rr_client(route, &rr_clients),
                        )
                    })
                    .map(|(prefix, _)| prefix),
            );

            // Withdraw unfeasible routes immediately.
            if !nbr_unreach.is_empty() {
                withdraw_routes::<A>(
                    nbr,
                    table,
                    &nbr_unreach,
                    &mut instance.state.rib.attr_sets,
                );
            }

            // Advertise best routes.
            if !nbr_reach.is_empty() {
                advertise_routes::<A>(
                    nbr,
                    table,
                    nbr_reach,
                    instance.config.asn,
                    instance.shared,
                    &mut instance.state.rib.attr_sets,
                    &instance.state.policy_apply_tasks,
                );
            }
        }
    }

    // Remove routing table entries that no longer hold any data.
    for prefix in queued_prefixes {
        if let std::collections::btree_map::Entry::Occupied(entry) =
            table.prefixes.entry(prefix)
        {
            let dest = entry.get();
            if dest.local.is_none()
                && dest.adj_rib.values().all(|adj_rib| {
                    adj_rib.in_pre().is_none()
                        && adj_rib.in_post().is_none()
                        && adj_rib.out_pre().is_none()
                        && adj_rib.out_post().is_none()
                })
            {
                entry.remove();
            }
        }
    }

    Ok(())
}

fn source_rr_client(
    route: &Route,
    rr_clients: &BTreeMap<IpAddr, bool>,
) -> Option<bool> {
    match route.origin {
        RouteOrigin::Neighbor { remote_addr, .. } => {
            rr_clients.get(&remote_addr).copied()
        }
        RouteOrigin::Protocol(_) => None,
    }
}

fn local_cluster_ids(
    identifier: Option<Ipv4Addr>,
    neighbors: &Neighbors,
) -> BTreeSet<Ipv4Addr> {
    neighbors
        .values()
        .filter(|nbr| nbr.config.route_reflector.client)
        .filter_map(|nbr| nbr.config.route_reflector.cluster_id.or(identifier))
        .collect()
}

pub(crate) fn sync_default_originate<A>(
    instance: &mut InstanceUpView<'_>,
    neighbors: &Neighbors,
) where
    A: AddressFamily,
{
    let Some(prefix) = default_originate_prefix::<A>() else {
        return;
    };

    let enabled = neighbors
        .values()
        .any(|nbr| default_originate_neighbor_enabled::<A>(nbr));

    if enabled {
        ensure_default_originate_route::<A>(instance);
    } else {
        let table = A::table(&mut instance.state.rib.tables);
        if let Some(dest) = table.prefixes.get_mut(&prefix)
            && dest.redistribute.take().is_some()
        {
            table.queued_prefixes.insert(prefix);
        }
    }
}

pub(crate) fn ensure_default_originate_route<A>(
    instance: &mut InstanceUpView<'_>,
) where
    A: AddressFamily,
{
    let Some(prefix) = default_originate_prefix::<A>() else {
        return;
    };

    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let dest = table.prefixes.entry(prefix).or_default();
    let mut attrs = Attrs::default();
    attrs.base.origin = holo_utils::bgp::Origin::Igp;
    let route_attrs = rib.attr_sets.get_route_attr_sets(&attrs);
    let route = Route::new(
        RouteOrigin::Protocol(holo_utils::protocol::Protocol::BGP),
        route_attrs,
        RouteType::Internal,
    );
    let update_needed = dest.redistribute.as_deref() != Some(&route);
    dest.redistribute = Some(Box::new(route));
    if update_needed {
        table.queued_prefixes.insert(prefix);
    }
}

pub(crate) fn default_originate_prefix<A>() -> Option<A::Prefix>
where
    A: AddressFamily,
{
    match A::AFI_SAFI {
        AfiSafi::Ipv4Unicast => {
            A::prefix_from_ip_network("0.0.0.0/0".parse().unwrap())
        }
        AfiSafi::Ipv6Unicast => {
            A::prefix_from_ip_network("::/0".parse().unwrap())
        }
        _ => None,
    }
}

pub(crate) fn default_originate_neighbor_enabled<A>(nbr: &Neighbor) -> bool
where
    A: AddressFamily,
{
    nbr.config
        .afi_safi
        .get(&A::AFI_SAFI)
        .is_some_and(|afi_safi| {
            afi_safi.enabled && afi_safi.send_default_route == Some(true)
        })
}

fn withdraw_routes<A>(
    nbr: &mut Neighbor,
    table: &mut RoutingTable<A>,
    routes: &[A::Prefix],
    attr_sets: &mut AttrSetsCxt,
) where
    A: AddressFamily,
{
    // Update Adj-RIB-Out.
    for prefix in routes {
        let dest = table.prefixes.get_mut(prefix).unwrap();
        let Some(adj_rib) = dest.adj_rib.get_mut(&nbr.remote_addr) else {
            continue;
        };

        adj_rib.remove_out_pre(attr_sets);
        if let Some(route) = adj_rib.out_post()
            && let Some(label) = route.vpn_label
        {
            let update_queue = A::update_queue(&mut nbr.update_queues);
            update_queue.labels.insert(*prefix, label);
        }
        if adj_rib.remove_out_post(attr_sets).is_some() {
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
    routes: Vec<(A::Prefix, Box<Route>)>,
    local_asn: u32,
    shared: &InstanceShared,
    attr_sets: &mut AttrSetsCxt,
    policy_apply_tasks: &PolicyApplyTasks,
) where
    A: AddressFamily,
{
    // Update pre-policy Adj-RIB-Out routes.
    for (prefix, route) in &routes {
        let dest = table.prefixes.get_mut(prefix).unwrap();
        let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
        adj_rib.update_out_pre(route.clone(), attr_sets);
    }

    if !A::POLICY_DISSEMINATE {
        for (prefix, route) in routes {
            let mut attrs = route.policy_info().attrs;
            rib::attrs_tx_update::<A>(
                &mut attrs,
                nbr,
                local_asn,
                nbr.config.route_reflector.cluster_id,
                route.origin,
                route.route_type,
                route.origin.is_local(),
            );

            let dest = table.prefixes.get_mut(&prefix).unwrap();
            let adj_rib = dest.adj_rib.entry(nbr.remote_addr).or_default();
            adj_rib.update_out_post(route.clone(), attr_sets);

            let update_queue = A::update_queue(&mut nbr.update_queues);
            if let Some(label) = route.vpn_label {
                update_queue.labels.insert(prefix, label);
            }
            update_queue.reach.entry(attrs).or_default().insert(prefix);
        }

        let msg_list = nbr.update_queues.build_updates();
        if !msg_list.is_empty() {
            nbr.message_list_send(msg_list);
        }
        return;
    }

    // Get policy configuration for the address family.
    let apply_policy_cfg = &nbr
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&nbr.config.apply_policy);

    // Enqueue export policy application.
    let routes = routes
        .into_iter()
        .map(|(prefix, route)| {
            (A::prefix_to_ip_network(prefix), route.policy_info())
        })
        .collect::<Vec<_>>();
    if !routes.is_empty() {
        let mut missing_policy = false;
        let policies = apply_policy_cfg
            .export_policy
            .iter()
            .filter_map(|policy| match shared.policies.get(policy) {
                Some(policy) => Some(policy.clone()),
                None => {
                    missing_policy = true;
                    None
                }
            })
            .collect();
        let msg = PolicyApplyMsg::Neighbor {
            policy_type: PolicyType::Export,
            nbr_addr: nbr.remote_addr,
            afi_safi: A::AFI_SAFI,
            routes,
            missing_policy,
            policies,
            match_sets: shared.policy_match_sets.clone(),
            default_policy: apply_policy_cfg.default_export_policy,
        };
        policy_apply_tasks.enqueue(msg);
    }
}
