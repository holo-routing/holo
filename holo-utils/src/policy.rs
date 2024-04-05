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

use crate::bgp::{self, AfiSafi, Comm, ExtComm, Extv6Comm, LargeComm, Origin};
use crate::ip::AddressFamily;
use crate::protocol::Protocol;

// Type aliases.
pub type Policies = BTreeMap<String, Arc<Policy>>;

// Routing policy configuration.
#[derive(Clone, Debug, Default)]
pub struct ApplyPolicyCfg {
    // TODO: "ordered-by user"
    pub import_policy: BTreeSet<String>,
    pub default_import_policy: DefaultPolicyType,
    // TODO: "ordered-by user"
    pub export_policy: BTreeSet<String>,
    pub default_export_policy: DefaultPolicyType,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum PolicyType {
    Import,
    Export,
}

#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum PolicyResult<T> {
    Accept(T),
    Reject,
}

// Default policy type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DefaultPolicyType {
    AcceptRoute,
    #[default]
    RejectRoute,
}

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
    Set,
    Add,
    Subtract,
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
    #[serde(with = "vectorize")]
    pub prefixes: BTreeMap<(String, AddressFamily), PrefixSet>,
    pub neighbors: BTreeMap<String, NeighborSet>,
    pub tags: BTreeMap<String, TagSet>,
    pub bgp: BgpMatchSets,
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

// BGP sets of attributes used in policy match statements.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct BgpMatchSets {
    pub as_paths: BTreeMap<String, BTreeSet<u32>>,
    pub comms: BTreeMap<String, BTreeSet<Comm>>,
    pub ext_comms: BTreeMap<String, BTreeSet<ExtComm>>,
    pub extv6_comms: BTreeMap<String, BTreeSet<Extv6Comm>>,
    pub large_comms: BTreeMap<String, BTreeSet<LargeComm>>,
    pub nexthops: BTreeMap<String, BTreeSet<BgpNexthop>>,
}

// Policy definition.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct Policy {
    // Name of the policy.
    pub name: String,
    // List of statements.
    // TODO: "ordered-by user"
    pub stmts: BTreeMap<String, PolicyStmt>,
}

// Policy statements.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct PolicyStmt {
    pub name: String,
    pub prefix_set_match_type: MatchSetRestrictedType,
    pub tag_set_match_type: MatchSetType,
    #[serde(with = "vectorize")]
    pub conditions: BTreeMap<PolicyConditionType, PolicyCondition>,
    #[serde(with = "vectorize")]
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
    Bgp(BgpPolicyConditionType),
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
    Bgp(BgpPolicyCondition),
}

// BGP policy condition statement type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BgpPolicyConditionType {
    LocalPref,
    Med,
    Origin,
    MatchAfiSafi,
    MatchNeighbor,
    RouteType,
    CommCount,
    AsPathLen,
    MatchCommSet,
    MatchExtCommSet,
    MatchExtv6CommSet,
    MatchLargeCommSet,
    MatchAsPathSet,
    MatchNexthopSet,
}

// BGP policy condition statement.
#[derive(Clone, Debug, EnumAsInner)]
#[derive(Deserialize, Serialize)]
pub enum BgpPolicyCondition {
    LocalPref {
        value: u32,
        op: BgpEqOperator,
    },
    Med {
        value: u32,
        op: BgpEqOperator,
    },
    Origin(Origin),
    MatchAfiSafi {
        values: BTreeSet<AfiSafi>,
        match_type: MatchSetRestrictedType,
    },
    MatchNeighbor {
        value: BTreeSet<IpAddr>,
        match_type: MatchSetRestrictedType,
    },
    RouteType(bgp::RouteType),
    CommCount {
        value: u32,
        op: BgpEqOperator,
    },
    AsPathLen {
        value: u32,
        op: BgpEqOperator,
    },
    MatchCommSet {
        value: String,
        match_type: MatchSetType,
    },
    MatchExtCommSet {
        value: String,
        match_type: MatchSetType,
    },
    MatchExtv6CommSet {
        value: String,
        match_type: MatchSetType,
    },
    MatchLargeCommSet {
        value: String,
        match_type: MatchSetType,
    },
    MatchAsPathSet {
        value: String,
        match_type: MatchSetType,
    },
    MatchNexthopSet {
        value: String,
        match_type: MatchSetRestrictedType,
    },
}

// Policy action statement type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum PolicyActionType {
    Accept,
    SetMetric,
    SetMetricType,
    SetRouteLevel,
    SetRoutePref,
    SetTag,
    SetAppTag,
    Bgp(BgpPolicyActionType),
}

// Policy action statement.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum PolicyAction {
    Accept(bool),
    SetMetric {
        value: u32,
        mod_type: MetricModification,
    },
    SetMetricType(MetricType),
    SetRouteLevel(RouteLevel),
    SetRoutePref(u16),
    SetTag(u32),
    SetAppTag(u32),
    Bgp(BgpPolicyAction),
}

// BGP policy action statement type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BgpPolicyActionType {
    SetRouteOrigin,
    SetLocalPref,
    SetNexthop,
    SetMed,
    SetAsPathPrepent,
    SetComm,
    SetExtComm,
    SetExtv6Comm,
    SetLargeComm,
}

// BGP policy action statement.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum BgpPolicyAction {
    SetRouteOrigin(Origin),
    SetLocalPref(u32),
    SetNexthop(BgpNexthop),
    SetMed(BgpSetMed),
    SetAsPathPrepent {
        asn: u32,
        repeat: Option<u8>,
    },
    SetComm {
        options: BgpSetCommOptions,
        method: BgpSetCommMethod<Comm>,
    },
    SetExtComm {
        options: BgpSetCommOptions,
        method: BgpSetCommMethod<ExtComm>,
    },
    SetExtv6Comm {
        options: BgpSetCommOptions,
        method: BgpSetCommMethod<Extv6Comm>,
    },
    SetLargeComm {
        options: BgpSetCommOptions,
        method: BgpSetCommMethod<LargeComm>,
    },
}

#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum BgpEqOperator {
    Equal,
    LessThanOrEqual,
    GreaterThanOrEqual,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum BgpNexthop {
    Addr(IpAddr),
    NexthopSelf,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum BgpSetMed {
    Add(u32),
    Subtract(u32),
    Set(u32),
    Igp,
    MedPlusIgp,
}

#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub enum BgpSetCommOptions {
    Add,
    Remove,
    Replace,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub enum BgpSetCommMethod<T: Eq + Ord + PartialEq + PartialOrd> {
    Inline(BTreeSet<T>),
    Reference(String),
}

// ===== impl DefaultPolicyType =====

impl TryFromYang for DefaultPolicyType {
    fn try_from_yang(value: &str) -> Option<DefaultPolicyType> {
        match value {
            "accept-route" => Some(DefaultPolicyType::AcceptRoute),
            "reject-route" => Some(DefaultPolicyType::RejectRoute),
            _ => None,
        }
    }
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
            "set-metric" => Some(MetricModification::Set),
            "add-metric" => Some(MetricModification::Add),
            "subtract-metric" => Some(MetricModification::Subtract),
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

impl MatchSetType {
    pub fn compare<T>(&self, a: &BTreeSet<T>, b: &BTreeSet<T>) -> bool
    where
        T: Eq + Ord + PartialEq + PartialOrd,
    {
        match self {
            MatchSetType::Any => !a.is_disjoint(b),
            MatchSetType::All => a.is_superset(b),
            MatchSetType::Invert => a.is_disjoint(b),
        }
    }
}

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

impl MatchSetRestrictedType {
    pub fn compare<T>(&self, a: &BTreeSet<T>, b: &T) -> bool
    where
        T: Eq + Ord + PartialEq + PartialOrd,
    {
        match self {
            MatchSetRestrictedType::Any => a.contains(b),
            MatchSetRestrictedType::Invert => !a.contains(b),
        }
    }
}

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
            PolicyCondition::Bgp(cond) => {
                PolicyConditionType::Bgp(cond.as_type())
            }
        }
    }
}

// ===== impl PolicyAction =====

impl PolicyAction {
    fn as_type(&self) -> PolicyActionType {
        match self {
            PolicyAction::Accept(..) => PolicyActionType::Accept,
            PolicyAction::SetMetric { .. } => PolicyActionType::SetMetric,
            PolicyAction::SetMetricType(..) => PolicyActionType::SetMetricType,
            PolicyAction::SetRouteLevel(..) => PolicyActionType::SetRouteLevel,
            PolicyAction::SetRoutePref(..) => PolicyActionType::SetRoutePref,
            PolicyAction::SetTag(..) => PolicyActionType::SetTag,
            PolicyAction::SetAppTag(..) => PolicyActionType::SetAppTag,
            PolicyAction::Bgp(action) => {
                PolicyActionType::Bgp(action.as_type())
            }
        }
    }
}

// ===== impl BgpPolicyCondition =====

impl BgpPolicyCondition {
    fn as_type(&self) -> BgpPolicyConditionType {
        match self {
            BgpPolicyCondition::LocalPref { .. } => {
                BgpPolicyConditionType::LocalPref
            }
            BgpPolicyCondition::Med { .. } => BgpPolicyConditionType::Med,
            BgpPolicyCondition::Origin(..) => BgpPolicyConditionType::Origin,
            BgpPolicyCondition::MatchAfiSafi { .. } => {
                BgpPolicyConditionType::MatchAfiSafi
            }
            BgpPolicyCondition::MatchNeighbor { .. } => {
                BgpPolicyConditionType::MatchNeighbor
            }
            BgpPolicyCondition::RouteType(..) => {
                BgpPolicyConditionType::RouteType
            }
            BgpPolicyCondition::CommCount { .. } => {
                BgpPolicyConditionType::CommCount
            }
            BgpPolicyCondition::AsPathLen { .. } => {
                BgpPolicyConditionType::AsPathLen
            }
            BgpPolicyCondition::MatchCommSet { .. } => {
                BgpPolicyConditionType::MatchCommSet
            }
            BgpPolicyCondition::MatchExtCommSet { .. } => {
                BgpPolicyConditionType::MatchExtCommSet
            }
            BgpPolicyCondition::MatchExtv6CommSet { .. } => {
                BgpPolicyConditionType::MatchExtv6CommSet
            }
            BgpPolicyCondition::MatchLargeCommSet { .. } => {
                BgpPolicyConditionType::MatchLargeCommSet
            }
            BgpPolicyCondition::MatchAsPathSet { .. } => {
                BgpPolicyConditionType::MatchAsPathSet
            }
            BgpPolicyCondition::MatchNexthopSet { .. } => {
                BgpPolicyConditionType::MatchNexthopSet
            }
        }
    }
}

// ===== impl BgpPolicyAction =====

impl BgpPolicyAction {
    fn as_type(&self) -> BgpPolicyActionType {
        match self {
            BgpPolicyAction::SetRouteOrigin(..) => {
                BgpPolicyActionType::SetRouteOrigin
            }
            BgpPolicyAction::SetLocalPref(..) => {
                BgpPolicyActionType::SetLocalPref
            }
            BgpPolicyAction::SetNexthop(..) => BgpPolicyActionType::SetNexthop,
            BgpPolicyAction::SetMed(..) => BgpPolicyActionType::SetMed,
            BgpPolicyAction::SetAsPathPrepent { .. } => {
                BgpPolicyActionType::SetAsPathPrepent
            }
            BgpPolicyAction::SetComm { .. } => BgpPolicyActionType::SetComm,
            BgpPolicyAction::SetExtComm { .. } => {
                BgpPolicyActionType::SetExtComm
            }
            BgpPolicyAction::SetExtv6Comm { .. } => {
                BgpPolicyActionType::SetExtv6Comm
            }
            BgpPolicyAction::SetLargeComm { .. } => {
                BgpPolicyActionType::SetLargeComm
            }
        }
    }
}

// ===== impl BgpEqOperator =====

impl BgpEqOperator {
    pub fn compare<T>(&self, a: &T, b: &T) -> bool
    where
        T: Eq + Ord + PartialEq + PartialOrd,
    {
        match self {
            BgpEqOperator::Equal => *a == *b,
            BgpEqOperator::LessThanOrEqual => *a <= *b,
            BgpEqOperator::GreaterThanOrEqual => *a >= *b,
        }
    }
}
