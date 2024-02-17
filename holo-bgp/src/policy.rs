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
use holo_utils::policy::{
    BgpNexthop, BgpPolicyAction, BgpPolicyCondition, BgpSetCommMethod,
    BgpSetCommOptions, BgpSetMed, DefaultPolicyType, MatchSets,
    MetricModification, Policy, PolicyAction, PolicyCondition, PolicyResult,
    PolicyType,
};
use holo_utils::UnboundedSender;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::packet::attribute::{Attrs, CommList, CommType};
use crate::rib::RouteOrigin;
use crate::tasks::messages::input::PolicyResultMsg;

// Represents a simplified version of `Route`, containing only information
// relevant for the application of routing policies.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct RoutePolicyInfo {
    pub origin: RouteOrigin,
    pub attrs: Attrs,
    pub route_type: RouteType,
}

// ===== global functions =====

// Applies neighbor import or export routing policies to a provided list of
// routes and sends the resulting policy decisions to the specified channel.
pub(crate) fn neighbor_apply(
    policy_type: PolicyType,
    nbr_addr: IpAddr,
    afi_safi: AfiSafi,
    routes: Vec<(IpNetwork, RoutePolicyInfo)>,
    policies: &Vec<Arc<Policy>>,
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
    policy_resultp: &UnboundedSender<PolicyResultMsg>,
) {
    // Process policies for each route and collect the results.
    let routes = routes
        .into_iter()
        .map(|(prefix, rpinfo)| {
            let result = process_policies(
                nbr_addr,
                afi_safi,
                prefix,
                rpinfo,
                policies,
                &match_sets,
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

// ===== helper functions =====

// Processes routing policies for a specific route and returns the policy
// result.
fn process_policies(
    nbr_addr: IpAddr,
    afi_safi: AfiSafi,
    prefix: IpNetwork,
    mut rpinfo: RoutePolicyInfo,
    policies: &Vec<Arc<Policy>>,
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
) -> PolicyResult<RoutePolicyInfo> {
    let mut matches = false;

    for stmt in policies.iter().flat_map(|policy| policy.stmts.values()) {
        // Check if all conditions in the policy statement are satisfied.
        if !stmt.conditions.values().all(|condition| {
            process_stmt_condition(
                &nbr_addr, afi_safi, &prefix, &rpinfo, condition, match_sets,
            )
        }) {
            continue;
        }

        matches = true;

        // Process actions defined in the policy statement.
        for action in stmt.actions.values() {
            if !process_stmt_action(&mut rpinfo, action, match_sets) {
                return PolicyResult::Reject;
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
    nbr_addr: &IpAddr,
    afi_safi: AfiSafi,
    _prefix: &IpNetwork,
    rpinfo: &RoutePolicyInfo,
    condition: &PolicyCondition,
    match_sets: &MatchSets,
) -> bool {
    let attrs = &rpinfo.attrs;
    match condition {
        // "match-interface"
        PolicyCondition::MatchInterface(_value) => {
            // TODO
            true
        }
        // "match-prefix-set"
        PolicyCondition::MatchPrefixSet(_value) => {
            // TODO
            true
        }
        // "match-neighbor-set"
        PolicyCondition::MatchNeighborSet(value) => {
            let set = match_sets.neighbors.get(value).unwrap();
            set.addrs.contains(nbr_addr)
        }
        // "bgp-conditions"
        PolicyCondition::Bgp(condition) => match condition {
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
            BgpPolicyCondition::Origin(origin) => attrs.base.origin == *origin,
            // "match-afi-safi"
            BgpPolicyCondition::MatchAfiSafi { values, match_type } => {
                match_type.compare(values, &afi_safi)
            }
            // "match-neighbor"
            BgpPolicyCondition::MatchNeighbor { value, match_type } => {
                match_type.compare(value, nbr_addr)
            }
            // "route-type"
            BgpPolicyCondition::RouteType(value) => rpinfo.route_type == *value,
            // "community-count"
            BgpPolicyCondition::CommCount { value, op } => match &attrs.comm {
                Some(comm) => op.compare(value, &(comm.0.len() as u32)),
                None => false,
            },
            // "as-path-length"
            BgpPolicyCondition::AsPathLen { value, op } => {
                op.compare(value, &(attrs.base.as_path.path_length()))
            }
            // "match-community-set"
            BgpPolicyCondition::MatchCommSet { value, match_type } => {
                if let Some(comm) = &attrs.comm {
                    let set = match_sets.bgp.comms.get(value).unwrap();
                    match_type.compare(&set, &comm.0)
                } else {
                    false
                }
            }
            // "match-ext-community-set"
            BgpPolicyCondition::MatchExtCommSet { value, match_type } => {
                if let Some(ext_comm) = &attrs.ext_comm {
                    let set = match_sets.bgp.ext_comms.get(value).unwrap();
                    match_type.compare(&set, &ext_comm.0)
                } else {
                    false
                }
            }
            // "match-ipv6-ext-community-set"
            BgpPolicyCondition::MatchExtv6CommSet { value, match_type } => {
                if let Some(extv6_comm) = &attrs.extv6_comm {
                    let set = match_sets.bgp.extv6_comms.get(value).unwrap();
                    match_type.compare(&set, &extv6_comm.0)
                } else {
                    false
                }
            }
            // "match-large-community-set"
            BgpPolicyCondition::MatchLargeCommSet { value, match_type } => {
                if let Some(large_comm) = &attrs.large_comm {
                    let set = match_sets.bgp.large_comms.get(value).unwrap();
                    match_type.compare(&set, &large_comm.0)
                } else {
                    false
                }
            }
            // "match-as-path-set"
            BgpPolicyCondition::MatchAsPathSet { value, match_type } => {
                let set = match_sets.bgp.as_paths.get(value).unwrap();
                let asns = attrs.base.as_path.iter().collect();
                match_type.compare(&set, &asns)
            }
            // "match-next-hop-set"
            BgpPolicyCondition::MatchNexthopSet { value, match_type } => {
                let nexthop = match attrs.base.nexthop {
                    Some(nexthop) => BgpNexthop::Addr(nexthop),
                    None => BgpNexthop::NexthopSelf,
                };
                let set = match_sets.bgp.nexthops.get(value).unwrap();
                match_type.compare(&set, &nexthop)
            }
        },
        // Ignore unsupported conditions.
        _ => true,
    }
}

// Processes a single action statement within a routing policy.
//
// Returns a boolean value indicating whether the route should be accepted or
// not.
fn process_stmt_action(
    rpinfo: &mut RoutePolicyInfo,
    action: &PolicyAction,
    match_sets: &MatchSets,
) -> bool {
    let attrs = &mut rpinfo.attrs;
    match action {
        // "policy-result"
        PolicyAction::Accept(accept) => {
            return *accept;
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
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.comms,
                    &mut attrs.comm,
                );
            }
            // "set-ext-community"
            BgpPolicyAction::SetExtComm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.ext_comms,
                    &mut attrs.ext_comm,
                );
            }
            // "set-ipv6-ext-community"
            BgpPolicyAction::SetExtv6Comm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.extv6_comms,
                    &mut attrs.extv6_comm,
                );
            }
            // "set-large-community"
            BgpPolicyAction::SetLargeComm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.large_comms,
                    &mut attrs.large_comm,
                );
            }
        },
        // Ignore unsupported actions.
        _ => {}
    }

    true
}

// Modifies the list of communities based on the specified method and options.
fn action_set_comm<T>(
    options: &BgpSetCommOptions,
    method: &BgpSetCommMethod<T>,
    comm_sets: &BTreeMap<String, BTreeSet<T>>,
    comm_list: &mut Option<CommList<T>>,
) where
    T: CommType,
{
    // Get list of communities.
    let comms = match method {
        BgpSetCommMethod::Inline(comms) => comms,
        BgpSetCommMethod::Reference(set) => comm_sets.get(set).unwrap(),
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
}
