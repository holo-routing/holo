//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use derive_new::new;
use holo_utils::bgp::{AfiSafi, RouteType};
use holo_utils::ip::IpNetworkKind;
use holo_utils::policy::{
    BgpNexthop, BgpPolicyAction, BgpPolicyCondition, BgpSetCommMethod,
    BgpSetCommOptions, BgpSetMed, DefaultPolicyType, MatchSetRestrictedType,
    MatchSetType, MatchSets, MetricModification, Policy, PolicyAction,
    PolicyCondition, PolicyResult, PolicyStmt, PolicyType,
};
use holo_utils::southbound::RouteOpaqueAttrs;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tokio::sync::mpsc::UnboundedSender;

use crate::packet::attribute::{Attrs, CommList, CommType};
use crate::rib::RouteOrigin;
use crate::tasks::messages::input::PolicyResultMsg;

enum PolicyActionResult {
    Continue,
    Accept,
    Reject,
}

// Represents a simplified version of `Route`, containing only information
// relevant for the application of routing policies.
#[derive(Clone, Debug)]
#[derive(new)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct RoutePolicyInfo {
    pub origin: RouteOrigin,
    pub route_type: RouteType,
    pub tag: Option<u32>,
    pub opaque_attrs: Option<RouteOpaqueAttrs>,
    pub attrs: Attrs,
}

// ===== global functions =====

// Applies neighbor import or export routing policies to a provided list of
// routes and sends the resulting policy decisions to the specified channel.
pub(crate) fn neighbor_apply(
    policy_type: PolicyType,
    nbr_addr: IpAddr,
    afi_safi: AfiSafi,
    routes: Vec<(IpNetwork, RoutePolicyInfo)>,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
    policy_resultp: &UnboundedSender<PolicyResultMsg>,
) {
    // Process policies for each route and collect the results.
    let routes = routes
        .into_iter()
        .map(|(prefix, rpinfo)| {
            let result = process_policies(
                afi_safi,
                prefix,
                rpinfo,
                policies,
                match_sets,
                default_policy,
            );

            (prefix, result)
        })
        .collect();

    // Send the resulting policy decisions to the specified channel.
    let _ = policy_resultp.send(PolicyResultMsg::Neighbor {
        policy_type,
        nbr_addr,
        afi_safi,
        routes,
    });
}

// Applies redistribution import routing policies to the provided route and
// sends the resulting policy decision to the specified channel.
pub(crate) fn redistribute_apply(
    afi_safi: AfiSafi,
    prefix: IpNetwork,
    rpinfo: RoutePolicyInfo,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
    policy_resultp: &UnboundedSender<PolicyResultMsg>,
) {
    // Process routing policies.
    let result = process_policies(
        afi_safi,
        prefix,
        rpinfo,
        policies,
        match_sets,
        default_policy,
    );

    // Send the resulting policy decision to the specified channel.
    let _ = policy_resultp.send(PolicyResultMsg::Redistribute {
        afi_safi,
        prefix,
        result,
    });
}

// ===== helper functions =====

// Processes routing policies for a specific route and returns the policy
// result.
fn process_policies(
    afi_safi: AfiSafi,
    prefix: IpNetwork,
    mut rpinfo: RoutePolicyInfo,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
) -> PolicyResult<RoutePolicyInfo> {
    let mut matches = false;

    for stmt in policies.iter().flat_map(|policy| policy.stmts_ordered()) {
        // Check if all conditions in the policy statement are satisfied.
        if !stmt.conditions.values().all(|condition| {
            process_stmt_condition(
                afi_safi, &prefix, &rpinfo, stmt, condition, match_sets,
            )
        }) {
            continue;
        }

        matches = true;

        // Process route mutations before terminal accept/reject actions. The
        // action map is keyed for replacement, not semantic evaluation order.
        for action in stmt.actions.values() {
            if matches!(action, PolicyAction::Accept(_)) {
                continue;
            }
            match process_stmt_action(&mut rpinfo.attrs, action, match_sets) {
                PolicyActionResult::Continue => {}
                PolicyActionResult::Accept => {
                    return PolicyResult::Accept(rpinfo);
                }
                PolicyActionResult::Reject => return PolicyResult::Reject,
            }
        }
        for action in stmt.actions.values() {
            if !matches!(action, PolicyAction::Accept(_)) {
                continue;
            }
            match process_stmt_action(&mut rpinfo.attrs, action, match_sets) {
                PolicyActionResult::Continue => {}
                PolicyActionResult::Accept => {
                    return PolicyResult::Accept(rpinfo);
                }
                PolicyActionResult::Reject => return PolicyResult::Reject,
            }
        }
    }

    // Check default policy if no definition in the policy chain was
    // satisfied.
    if !matches && default_policy == DefaultPolicyType::RejectRoute {
        return PolicyResult::Reject;
    }

    PolicyResult::Accept(rpinfo)
}

// Processes a single condition statement within a routing policy.
//
// Returns a boolean value indicating whether the condition is met.
fn process_stmt_condition(
    afi_safi: AfiSafi,
    prefix: &IpNetwork,
    rpinfo: &RoutePolicyInfo,
    stmt: &PolicyStmt,
    condition: &PolicyCondition,
    match_sets: &MatchSets,
) -> bool {
    let attrs = &rpinfo.attrs;
    match condition {
        // "source-protocol"
        PolicyCondition::SrcProtocol(value) => {
            let RouteOrigin::Protocol(protocol) = &rpinfo.origin else {
                return false;
            };

            protocol == value
        }
        // "match-interface"
        PolicyCondition::MatchInterface(_value) => {
            // TODO
            true
        }
        // "match-prefix-set"
        PolicyCondition::MatchPrefixSet(value) => {
            let af = prefix.address_family();
            let matches = match match_sets.prefixes.get(&(value.clone(), af)) {
                Some(set) => set.prefixes.iter().any(|range| {
                    prefix.ip() == range.prefix.ip()
                        && prefix.prefix() >= range.masklen_lower
                        && prefix.prefix() <= range.masklen_upper
                }),
                None => false,
            };
            match stmt.prefix_set_match_type {
                MatchSetRestrictedType::Any => matches,
                MatchSetRestrictedType::Invert => !matches,
            }
        }
        // "match-neighbor-set"
        PolicyCondition::MatchNeighborSet(value) => {
            let RouteOrigin::Neighbor { remote_addr, .. } = &rpinfo.origin
            else {
                return false;
            };

            match match_sets.neighbors.get(value) {
                Some(set) => set.addrs.contains(remote_addr),
                None => false,
            }
        }
        // "match-tag-set"
        PolicyCondition::MatchTagSet(value) => {
            let matches = if let Some(tag) = &rpinfo.tag
                && let Some(set) = match_sets.tags.get(value)
            {
                set.tags.contains(tag)
            } else {
                false
            };
            match stmt.tag_set_match_type {
                MatchSetType::Any | MatchSetType::All => matches,
                MatchSetType::Invert => !matches,
            }
        }
        // "match-route-type"
        PolicyCondition::MatchRouteType(_value) => {
            let Some(_opaque_attrs) = &rpinfo.opaque_attrs else {
                return true;
            };

            // TODO
            true
        }
        // "bgp-conditions"
        PolicyCondition::Bgp(condition) => {
            match condition {
                // "local-pref"
                BgpPolicyCondition::LocalPref { value, op } => {
                    match attrs.base.local_pref {
                        Some(local_pref) => op.compare(value, &local_pref),
                        None => false,
                    }
                }
                // "med"
                BgpPolicyCondition::Med { value, op } => match attrs.base.med {
                    Some(med) => op.compare(value, &med),
                    None => false,
                },
                // "origin-eq"
                BgpPolicyCondition::Origin(origin) => {
                    attrs.base.origin == *origin
                }
                // "match-afi-safi"
                BgpPolicyCondition::MatchAfiSafi { values, match_type } => {
                    match_type.compare(values, &afi_safi)
                }
                // "match-neighbor"
                BgpPolicyCondition::MatchNeighbor { value, match_type } => {
                    let RouteOrigin::Neighbor { remote_addr, .. } =
                        &rpinfo.origin
                    else {
                        return false;
                    };
                    match_type.compare(value, remote_addr)
                }
                // "route-type"
                BgpPolicyCondition::RouteType(value) => {
                    rpinfo.route_type == *value
                }
                // "community-count"
                BgpPolicyCondition::CommCount { value, op } => {
                    match &attrs.comm {
                        Some(comm) => op.compare(value, &(comm.0.len() as u32)),
                        None => false,
                    }
                }
                // "as-path-length"
                BgpPolicyCondition::AsPathLen { value, op } => {
                    op.compare(value, &(attrs.base.as_path.path_length()))
                }
                // "match-community-set"
                BgpPolicyCondition::MatchCommSet { value, match_type } => {
                    if let Some(comm) = &attrs.comm {
                        match_sets.bgp.comms.get(value).is_some_and(|set| {
                            match_comm_set(match_type, set, &comm.0)
                        })
                    } else {
                        false
                    }
                }
                // "match-ext-community-set"
                BgpPolicyCondition::MatchExtCommSet { value, match_type } => {
                    if let Some(ext_comm) = &attrs.ext_comm {
                        match_sets.bgp.ext_comms.get(value).is_some_and(|set| {
                            match_comm_set(match_type, set, &ext_comm.0)
                        })
                    } else {
                        false
                    }
                }
                // "match-ipv6-ext-community-set"
                BgpPolicyCondition::MatchExtv6CommSet { value, match_type } => {
                    if let Some(extv6_comm) = &attrs.extv6_comm {
                        match_sets.bgp.extv6_comms.get(value).is_some_and(
                            |set| {
                                match_comm_set(match_type, set, &extv6_comm.0)
                            },
                        )
                    } else {
                        false
                    }
                }
                // "match-large-community-set"
                BgpPolicyCondition::MatchLargeCommSet { value, match_type } => {
                    if let Some(large_comm) = &attrs.large_comm {
                        match_sets.bgp.large_comms.get(value).is_some_and(
                            |set| {
                                match_comm_set(match_type, set, &large_comm.0)
                            },
                        )
                    } else {
                        false
                    }
                }
                // "match-as-path-set"
                BgpPolicyCondition::MatchAsPathSet { value, match_type } => {
                    match_sets.bgp.as_paths.get(value).is_some_and(|set| {
                        let asns = attrs.base.as_path.iter().collect();
                        match_comm_set(match_type, set, &asns)
                    })
                }
                // "match-next-hop-set"
                BgpPolicyCondition::MatchNexthopSet { value, match_type } => {
                    let nexthop = match attrs.base.nexthop {
                        Some(nexthop) => BgpNexthop::Addr(nexthop),
                        None => BgpNexthop::NexthopSelf,
                    };
                    match_sets
                        .bgp
                        .nexthops
                        .get(value)
                        .is_some_and(|set| match_type.compare(set, &nexthop))
                }
            }
        }
        // Ignore unsupported conditions.
        _ => true,
    }
}

fn match_comm_set<T>(
    match_type: &MatchSetType,
    policy_set: &BTreeSet<T>,
    route_values: &BTreeSet<T>,
) -> bool
where
    T: Eq + Ord + PartialEq + PartialOrd,
{
    match match_type {
        MatchSetType::Any => !policy_set.is_disjoint(route_values),
        MatchSetType::All => route_values.is_superset(policy_set),
        MatchSetType::Invert => policy_set.is_disjoint(route_values),
    }
}

// Processes a single action statement within a routing policy.
//
// Returns the policy flow-control result for this action.
fn process_stmt_action(
    attrs: &mut Attrs,
    action: &PolicyAction,
    match_sets: &MatchSets,
) -> PolicyActionResult {
    match action {
        // "policy-result"
        PolicyAction::Accept(accept) => {
            return if *accept {
                PolicyActionResult::Accept
            } else {
                PolicyActionResult::Reject
            };
        }
        // "set-metric"
        PolicyAction::SetMetric { value, mod_type } => match mod_type {
            MetricModification::Set => {
                attrs.base.med = Some(*value);
            }
            MetricModification::Add => {
                if let Some(med) = &mut attrs.base.med {
                    *med = med.saturating_add(*value);
                }
            }
            MetricModification::Subtract => {
                if let Some(med) = &mut attrs.base.med {
                    *med = med.saturating_sub(*value);
                }
            }
        },
        // "bgp-actions"
        PolicyAction::Bgp(action) => match action {
            // "set-route-origin"
            BgpPolicyAction::SetRouteOrigin(origin) => {
                attrs.base.origin = *origin
            }
            // "set-local-pref"
            BgpPolicyAction::SetLocalPref(local_pref) => {
                attrs.base.local_pref = Some(*local_pref);
            }
            // "set-next-hop"
            BgpPolicyAction::SetNexthop(set_nexthop) => {
                attrs.base.nexthop = match set_nexthop {
                    BgpNexthop::Addr(addr) => Some(*addr),
                    BgpNexthop::NexthopSelf => None,
                };
            }
            // "set-med"
            BgpPolicyAction::SetMed(set_med) => match set_med {
                BgpSetMed::Add(value) => {
                    if let Some(med) = &mut attrs.base.med {
                        *med = med.saturating_add(*value);
                    }
                }
                BgpSetMed::Subtract(value) => {
                    if let Some(med) = &mut attrs.base.med {
                        *med = med.saturating_sub(*value);
                    }
                }
                BgpSetMed::Set(value) => {
                    attrs.base.med = Some(*value);
                }
                BgpSetMed::Igp => {
                    // TODO
                }
                BgpSetMed::MedPlusIgp => {
                    // TODO
                }
            },
            // "set-as-path-prepend"
            BgpPolicyAction::SetAsPathPrepent { asn, repeat } => {
                for _ in 0..repeat.unwrap_or(1) {
                    attrs.base.as_path.prepend(*asn);
                }
            }
            // "set-community"
            BgpPolicyAction::SetComm { options, method } => {
                if !action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.comms,
                    &mut attrs.comm,
                ) {
                    return PolicyActionResult::Reject;
                }
            }
            // "set-ext-community"
            BgpPolicyAction::SetExtComm { options, method } => {
                if !action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.ext_comms,
                    &mut attrs.ext_comm,
                ) {
                    return PolicyActionResult::Reject;
                }
            }
            // "set-ipv6-ext-community"
            BgpPolicyAction::SetExtv6Comm { options, method } => {
                if !action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.extv6_comms,
                    &mut attrs.extv6_comm,
                ) {
                    return PolicyActionResult::Reject;
                }
            }
            // "set-large-community"
            BgpPolicyAction::SetLargeComm { options, method } => {
                if !action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.large_comms,
                    &mut attrs.large_comm,
                ) {
                    return PolicyActionResult::Reject;
                }
            }
        },
        // Ignore unsupported actions.
        _ => {}
    }

    PolicyActionResult::Continue
}

// Modifies the list of communities based on the specified method and options.
fn action_set_comm<T>(
    options: &BgpSetCommOptions,
    method: &BgpSetCommMethod<T>,
    comm_sets: &BTreeMap<String, BTreeSet<T>>,
    comm_list: &mut Option<CommList<T>>,
) -> bool
where
    T: CommType,
{
    // Get list of communities.
    let comms = match method {
        BgpSetCommMethod::Inline(comms) => comms,
        BgpSetCommMethod::Reference(set) => {
            let Some(comms) = comm_sets.get(set) else {
                return false;
            };
            comms
        }
    };

    // Add, remove or replace communities.
    match options {
        BgpSetCommOptions::Add => {
            if let Some(comm_list) = comm_list {
                comm_list.0.extend(comms.clone());
            } else {
                *comm_list = Some(CommList(comms.clone()));
            }
        }
        BgpSetCommOptions::Remove => {
            if let Some(comm_list) = comm_list {
                comm_list.0.retain(|c| !comms.contains(c))
            }
        }
        BgpSetCommOptions::Replace => {
            *comm_list = Some(CommList(comms.clone()));
        }
    }

    // Remove the community list if it exists and is empty.
    if let Some(list) = comm_list.as_ref()
        && list.0.is_empty()
    {
        *comm_list = None;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};

    use holo_utils::ip::AddressFamily;
    use holo_utils::policy::{
        IpPrefixRange, Policy, PolicyAction, PolicyCondition, PolicyStmt,
    };

    use super::*;
    use crate::packet::attribute::{
        AsPath, AsPathSegment, AsPathSegmentType, CommList,
    };

    fn route_info() -> RoutePolicyInfo {
        RoutePolicyInfo::new(
            RouteOrigin::Neighbor {
                identifier: "192.0.2.2".parse().unwrap(),
                remote_addr: "192.0.2.2".parse().unwrap(),
            },
            RouteType::External,
            None,
            None,
            Attrs::default(),
        )
    }

    fn accept_stmt(name: &str) -> PolicyStmt {
        let mut stmt = PolicyStmt::new(name.to_owned());
        stmt.action_add(PolicyAction::Accept(true));
        stmt
    }

    fn reject_stmt(name: &str) -> PolicyStmt {
        let mut stmt = PolicyStmt::new(name.to_owned());
        stmt.action_add(PolicyAction::Accept(false));
        stmt
    }

    #[test]
    fn ordered_statements_are_not_key_sorted() {
        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(accept_stmt("2"));
        policy.stmt_add(reject_stmt("1"));

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route_info(),
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        assert!(matches!(result, PolicyResult::Accept(_)));
    }

    #[test]
    fn prefix_policy_can_mutate_then_accept() {
        let mut stmt1 = PolicyStmt::new("10".to_owned());
        stmt1.condition_add(PolicyCondition::MatchPrefixSet("PL".to_owned()));
        stmt1.action_add(PolicyAction::Bgp(BgpPolicyAction::SetLocalPref(200)));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt1);
        policy.stmt_add(accept_stmt("20"));

        let mut match_sets = MatchSets::default();
        let mut prefixes = BTreeSet::new();
        prefixes.insert(IpPrefixRange {
            prefix: "198.51.100.0/24".parse().unwrap(),
            masklen_lower: 24,
            masklen_upper: 32,
        });
        match_sets.prefixes.insert(
            ("PL".to_owned(), AddressFamily::Ipv4),
            holo_utils::policy::PrefixSet {
                name: "PL".to_owned(),
                mode: AddressFamily::Ipv4,
                prefixes,
            },
        );

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route_info(),
            &[Arc::new(policy)],
            &match_sets,
            DefaultPolicyType::RejectRoute,
        );

        let PolicyResult::Accept(route) = result else {
            panic!("route should be accepted");
        };
        assert_eq!(route.attrs.base.local_pref, Some(200));
    }

    #[test]
    fn statement_actions_mutate_before_accepting() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.action_add(PolicyAction::Accept(true));
        stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetLocalPref(300)));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route_info(),
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        let PolicyResult::Accept(route) = result else {
            panic!("route should be accepted");
        };
        assert_eq!(route.attrs.base.local_pref, Some(300));
    }

    #[test]
    fn missing_bgp_set_reference_is_no_match() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.condition_add(PolicyCondition::Bgp(
            BgpPolicyCondition::MatchCommSet {
                value: "MISSING".to_owned(),
                match_type: MatchSetType::Any,
            },
        ));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let mut route = route_info();
        route.attrs.comm =
            Some(CommList(BTreeSet::from([holo_utils::bgp::Comm(100)])));

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        assert!(matches!(result, PolicyResult::Reject));
    }

    #[test]
    fn community_match_all_requires_all_members_on_route() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.condition_add(PolicyCondition::Bgp(
            BgpPolicyCondition::MatchCommSet {
                value: "COMM".to_owned(),
                match_type: MatchSetType::All,
            },
        ));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let mut match_sets = MatchSets::default();
        match_sets.bgp.comms.insert(
            "COMM".to_owned(),
            BTreeSet::from([
                holo_utils::bgp::Comm(100),
                holo_utils::bgp::Comm(200),
            ]),
        );

        let mut route = route_info();
        route.attrs.comm =
            Some(CommList(BTreeSet::from([holo_utils::bgp::Comm(100)])));
        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy.clone())],
            &match_sets,
            DefaultPolicyType::RejectRoute,
        );
        assert!(matches!(result, PolicyResult::Reject));

        let mut route = route_info();
        route.attrs.comm = Some(CommList(BTreeSet::from([
            holo_utils::bgp::Comm(100),
            holo_utils::bgp::Comm(200),
        ])));
        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &match_sets,
            DefaultPolicyType::RejectRoute,
        );
        assert!(matches!(result, PolicyResult::Accept(_)));
    }

    #[test]
    fn as_path_set_matches_literal_as_membership() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.condition_add(PolicyCondition::Bgp(
            BgpPolicyCondition::MatchAsPathSet {
                value: "ASNS".to_owned(),
                match_type: MatchSetType::Any,
            },
        ));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let mut match_sets = MatchSets::default();
        match_sets
            .bgp
            .as_paths
            .insert("ASNS".to_owned(), BTreeSet::from([65001]));

        let mut route = route_info();
        route.attrs.base.as_path = AsPath {
            segments: VecDeque::from([AsPathSegment {
                seg_type: AsPathSegmentType::Sequence,
                members: VecDeque::from([65000, 65001]),
            }]),
        };

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &match_sets,
            DefaultPolicyType::RejectRoute,
        );

        assert!(matches!(result, PolicyResult::Accept(_)));
    }

    #[test]
    fn set_action_missing_reference_rejects_route() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetComm {
            options: BgpSetCommOptions::Add,
            method: BgpSetCommMethod::Reference("MISSING".to_owned()),
        }));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route_info(),
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        assert!(matches!(result, PolicyResult::Reject));
    }

    #[test]
    fn remove_absent_community_is_noop() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetComm {
            options: BgpSetCommOptions::Remove,
            method: BgpSetCommMethod::Inline(BTreeSet::from([
                holo_utils::bgp::Comm(100),
            ])),
        }));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let mut route = route_info();
        route.attrs.comm =
            Some(CommList(BTreeSet::from([holo_utils::bgp::Comm(200)])));
        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        let PolicyResult::Accept(route) = result else {
            panic!("route should be accepted");
        };
        assert_eq!(
            route.attrs.comm.unwrap().0,
            BTreeSet::from([holo_utils::bgp::Comm(200)])
        );
    }

    #[test]
    fn community_actions_add_and_replace_values() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetComm {
            options: BgpSetCommOptions::Add,
            method: BgpSetCommMethod::Inline(BTreeSet::from([
                holo_utils::bgp::Comm(200),
            ])),
        }));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);
        policy.stmt_add(accept_stmt("20"));

        let mut route = route_info();
        route.attrs.comm =
            Some(CommList(BTreeSet::from([holo_utils::bgp::Comm(100)])));
        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        let PolicyResult::Accept(route) = result else {
            panic!("route should be accepted");
        };
        assert_eq!(
            route.attrs.comm.unwrap().0,
            BTreeSet::from([
                holo_utils::bgp::Comm(100),
                holo_utils::bgp::Comm(200)
            ])
        );

        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.action_add(PolicyAction::Bgp(BgpPolicyAction::SetComm {
            options: BgpSetCommOptions::Replace,
            method: BgpSetCommMethod::Inline(BTreeSet::from([
                holo_utils::bgp::Comm(300),
            ])),
        }));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);
        policy.stmt_add(accept_stmt("20"));

        let mut route = route_info();
        route.attrs.comm =
            Some(CommList(BTreeSet::from([holo_utils::bgp::Comm(100)])));
        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route,
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        let PolicyResult::Accept(route) = result else {
            panic!("route should be accepted");
        };
        assert_eq!(
            route.attrs.comm.unwrap().0,
            BTreeSet::from([holo_utils::bgp::Comm(300)])
        );
    }

    #[test]
    fn afi_safi_condition_filters_routes() {
        let mut stmt = PolicyStmt::new("10".to_owned());
        stmt.condition_add(PolicyCondition::Bgp(
            BgpPolicyCondition::MatchAfiSafi {
                values: BTreeSet::from([AfiSafi::Ipv6Unicast]),
                match_type: MatchSetRestrictedType::Any,
            },
        ));
        stmt.action_add(PolicyAction::Accept(true));

        let mut policy = Policy::new("POLICY".to_owned());
        policy.stmt_add(stmt);

        let result = process_policies(
            AfiSafi::Ipv4Unicast,
            "198.51.100.0/24".parse().unwrap(),
            route_info(),
            &[Arc::new(policy)],
            &MatchSets::default(),
            DefaultPolicyType::RejectRoute,
        );

        assert!(matches!(result, PolicyResult::Reject));
    }
}
