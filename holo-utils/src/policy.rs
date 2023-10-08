//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use holo_yang::TryFromYang;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;
use crate::protocol::Protocol;

// Type aliases.
pub type Policies = BTreeMap<String, Arc<Policy>>;

// Route type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum RouteType {
    IsisLevel1,
    IsisLevel2,
    OspfInternal,
    OspfExternal,
    OspfExternalType1,
    OspfExternalType2,
    OspfNssa,
    OspfNssaType1,
    OspfNssaType2,
    BgpInternal,
    BgpExternal,
}

// Indicates how to modify the metric.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum MetricModification {
    SetMetric,
    AddMetric,
    SubtractMetric,
}

// Route metric types.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum MetricType {
    OspfType1,
    OspfType2,
    IsisInternal,
    IsisExternal,
}

// Route level.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum RouteLevel {
    OspfNormal,
    OspfNssaOnly,
    OspfNormalNssa,
    IsisLevel1,
    IsisLevel2,
    IsisLevel12,
}

// Range of IP prefixes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct IpPrefixRange {
    pub prefix: IpNetwork,
    pub masklen_lower: u8,
    pub masklen_upper: u8,
}

// Behavior of a match statement.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum MatchSetType {
    // Match is true if given value matches any member of the defined set.
    Any,
    // Match is true if given value matches all members of the defined set.
    All,
    // Match is true if given value does not match any member of the defined set.
    Invert,
}

// Behavior of a match statement.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum MatchSetRestrictedType {
    // Match is true if given value matches any member of the defined set.
    Any,
    // Match is true if given value does not match any member of the defined set.
    Invert,
}

// Sets of attributes used in policy match statements.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct MatchSets {
    pub prefixes: BTreeMap<(String, AddressFamily), PrefixSet>,
    pub neighbors: BTreeMap<String, NeighborSet>,
    pub tags: BTreeMap<String, TagSet>,
}

// List of IPv4 or IPv6 prefixes that are matched as part of a policy.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct PrefixSet {
    pub name: String,
    pub mode: AddressFamily,
    pub prefixes: BTreeSet<IpPrefixRange>,
}

// List of IPv4 or IPv6 neighbors that can be matched in a routing policy.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct NeighborSet {
    pub name: String,
    pub addrs: BTreeSet<IpAddr>,
}

// List of tags that can be matched in policies.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct TagSet {
    pub name: String,
    pub tags: BTreeSet<u32>,
}

// Policy definition.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct Policy {
    // Name of the policy.
    pub name: String,
    // List of statements.
    pub stmts: BTreeMap<String, PolicyStmt>,
}

// Policy statements.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct PolicyStmt {
    pub name: String,
    pub prefix_set_match_type: MatchSetRestrictedType,
    pub tag_set_match_type: MatchSetType,
    pub conditions: BTreeMap<PolicyConditionType, PolicyCondition>,
    pub actions: BTreeMap<PolicyActionType, PolicyAction>,
}

// Policy condition statement type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum PolicyConditionType {
    CallPolicy,
    SrcProtocol,
    MatchInterface,
    MatchPrefixSet,
    MatchNeighborSet,
    MatchTagSet,
    MatchRouteType,
}

// Policy condition statement.
#[derive(Clone, Debug, EnumAsInner)]
#[derive(Deserialize, Serialize)]
pub enum PolicyCondition {
    CallPolicy(String),
    SrcProtocol(Protocol),
    MatchInterface(String),
    MatchPrefixSet(String),
    MatchNeighborSet(String),
    MatchTagSet(String),
    MatchRouteType(BTreeSet<RouteType>),
}

// Policy action statement type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum PolicyActionType {
    Accept,
    SetMetric,
    SetMetricMod,
    SetMetricType,
    SetRouteLevel,
    SetRoutePref,
    SetTag,
    SetAppTag,
}

// Policy action statement.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum PolicyAction {
    Accept(bool),
    SetMetric(u32),
    SetMetricMod(MetricModification),
    SetMetricType(MetricType),
    SetRouteLevel(RouteLevel),
    SetRoutePref(u16),
    SetTag(u32),
    SetAppTag(u32),
}

// ===== impl RouteType =====

impl TryFromYang for RouteType {
    fn try_from_yang(identity: &str) -> Option<RouteType> {
        match identity {
            "ietf-routing-policy:isis-level-1-type" => {
                Some(RouteType::IsisLevel1)
            }
            "ietf-routing-policy:isis-level-2-type" => {
                Some(RouteType::IsisLevel2)
            }
            "ietf-routing-policy:ospf-internal-type" => {
                Some(RouteType::OspfInternal)
            }
            "ietf-routing-policy:ospf-external-type" => {
                Some(RouteType::OspfExternal)
            }
            "ietf-routing-policy:ospf-external-t1-type" => {
                Some(RouteType::OspfExternalType1)
            }
            "ietf-routing-policy:ospf-external-t2-type" => {
                Some(RouteType::OspfExternalType2)
            }
            "ietf-routing-policy:ospf-nssa-type" => Some(RouteType::OspfNssa),
            "ietf-routing-policy:ospf-nssa-t1-type" => {
                Some(RouteType::OspfNssaType1)
            }
            "ietf-routing-policy:ospf-nssa-t2-type" => {
                Some(RouteType::OspfNssaType2)
            }
            "ietf-routing-policy:bgp-internal" => Some(RouteType::BgpInternal),
            "ietf-routing-policy:bgp-external" => Some(RouteType::BgpExternal),
            _ => None,
        }
    }
}

// ===== impl MetricModification =====

impl TryFromYang for MetricModification {
    fn try_from_yang(value: &str) -> Option<MetricModification> {
        match value {
            "set-metric" => Some(MetricModification::SetMetric),
            "add-metric" => Some(MetricModification::AddMetric),
            "subtract-metric" => Some(MetricModification::SubtractMetric),
            _ => None,
        }
    }
}

// ===== impl MetricType =====

impl TryFromYang for MetricType {
    fn try_from_yang(identity: &str) -> Option<MetricType> {
        match identity {
            "ietf-routing-policy:ospf-type-1-metric" => {
                Some(MetricType::OspfType1)
            }
            "ietf-routing-policy:ospf-type-2-metric" => {
                Some(MetricType::OspfType2)
            }
            "ietf-routing-policy:isis-internal-metric" => {
                Some(MetricType::IsisInternal)
            }
            "ietf-routing-policy:isis-external-metric" => {
                Some(MetricType::IsisExternal)
            }
            _ => None,
        }
    }
}

// ===== impl RouteLevel =====

impl TryFromYang for RouteLevel {
    fn try_from_yang(identity: &str) -> Option<RouteLevel> {
        match identity {
            "ietf-routing-policy:ospf-normal" => Some(RouteLevel::OspfNormal),
            "ietf-routing-policy:ospf-nssa-only" => {
                Some(RouteLevel::OspfNssaOnly)
            }
            "ietf-routing-policy:ospf-normal-nssa" => {
                Some(RouteLevel::OspfNormalNssa)
            }
            "ietf-routing-policy:isis-level-1" => Some(RouteLevel::IsisLevel1),
            "ietf-routing-policy:isis-level-2" => Some(RouteLevel::IsisLevel2),
            "ietf-routing-policy:isis-level-1-2" => {
                Some(RouteLevel::IsisLevel12)
            }
            _ => None,
        }
    }
}

// ===== impl MatchSetType =====

impl TryFromYang for MatchSetType {
    fn try_from_yang(identity: &str) -> Option<MatchSetType> {
        match identity {
            "any" => Some(MatchSetType::Any),
            "all" => Some(MatchSetType::All),
            "invert" => Some(MatchSetType::Invert),
            _ => None,
        }
    }
}

// ===== impl MatchSetRestrictedType =====

impl TryFromYang for MatchSetRestrictedType {
    fn try_from_yang(identity: &str) -> Option<MatchSetRestrictedType> {
        match identity {
            "any" => Some(MatchSetRestrictedType::Any),
            "invert" => Some(MatchSetRestrictedType::Invert),
            _ => None,
        }
    }
}

// ===== impl PolicyStmt =====

impl PolicyStmt {
    pub fn new(name: String) -> Self {
        // TODO: get defaults from the YANG module.
        let prefix_set_match_type = MatchSetRestrictedType::Any;
        let tag_set_match_type = MatchSetType::Any;

        Self {
            name,
            prefix_set_match_type,
            tag_set_match_type,
            conditions: Default::default(),
            actions: Default::default(),
        }
    }

    pub fn condition_add(&mut self, cond: PolicyCondition) {
        self.conditions.insert(cond.as_type(), cond);
    }

    pub fn condition_remove(&mut self, cond_type: PolicyConditionType) {
        self.conditions.remove(&cond_type);
    }

    pub fn action_add(&mut self, action: PolicyAction) {
        self.actions.insert(action.as_type(), action);
    }

    pub fn action_remove(&mut self, action_type: PolicyActionType) {
        self.actions.remove(&action_type);
    }
}

// ===== impl PolicyCondition =====

impl PolicyCondition {
    fn as_type(&self) -> PolicyConditionType {
        match self {
            PolicyCondition::CallPolicy(..) => PolicyConditionType::CallPolicy,
            PolicyCondition::SrcProtocol(..) => {
                PolicyConditionType::SrcProtocol
            }
            PolicyCondition::MatchInterface(..) => {
                PolicyConditionType::MatchInterface
            }
            PolicyCondition::MatchPrefixSet(..) => {
                PolicyConditionType::MatchPrefixSet
            }
            PolicyCondition::MatchNeighborSet(..) => {
                PolicyConditionType::MatchNeighborSet
            }
            PolicyCondition::MatchTagSet(..) => {
                PolicyConditionType::MatchTagSet
            }
            PolicyCondition::MatchRouteType(..) => {
                PolicyConditionType::MatchRouteType
            }
        }
    }
}

// ===== impl PolicyAction =====

impl PolicyAction {
    fn as_type(&self) -> PolicyActionType {
        match self {
            PolicyAction::Accept(..) => PolicyActionType::Accept,
            PolicyAction::SetMetric(..) => PolicyActionType::SetMetric,
            PolicyAction::SetMetricMod(..) => PolicyActionType::SetMetricMod,
            PolicyAction::SetMetricType(..) => PolicyActionType::SetMetricType,
            PolicyAction::SetRouteLevel(..) => PolicyActionType::SetRouteLevel,
            PolicyAction::SetRoutePref(..) => PolicyActionType::SetRoutePref,
            PolicyAction::SetTag(..) => PolicyActionType::SetTag,
            PolicyAction::SetAppTag(..) => PolicyActionType::SetAppTag,
        }
    }
}
