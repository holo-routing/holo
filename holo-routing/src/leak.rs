//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// RIB-to-RIB route leaking: routes imported from kernel tables into
// custom RIBs are leaked into default RIBs through import-rib entries,
// filtered by routing policies. Leaked routes are never installed into
// the kernel.

use std::collections::BTreeMap;
use std::sync::Arc;

use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::policy::{MatchSets, Policy, PolicyAction, PolicyCondition};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{RouteMsg, RouteOpaqueAttrs};
use ipnetwork::IpNetwork;

use crate::Master;
use crate::kernel::{KernelEvent, KernelRib};

// Configuration of a RIB, mirrored from the running configuration.
#[derive(Clone, Debug, Default)]
pub struct RibConfig {
    pub address_family: Option<AddressFamily>,
    pub kernel_table_id: Option<u32>,
    // Source RIB name -> import policy name (None: leak everything).
    pub import_ribs: BTreeMap<String, Option<String>>,
}

// Returns whether the given RIB name is one of the default RIBs.
pub fn is_default_rib(name: &str) -> bool {
    matches!(name, "ipv4-unicast" | "ipv6-unicast" | "mpls")
}

// Parses the address-family of a RIB entry, accepting both the plain and
// the module-qualified identity values, e.g. "ipv4", "ietf-ip:ipv4" or
// "ietf-ipv4-unicast-routing:ipv4-unicast".
pub fn rib_address_family(value: &str) -> Option<AddressFamily> {
    match value.rsplit(':').next()? {
        "ipv4" | "ipv4-unicast" => Some(AddressFamily::Ipv4),
        "ipv6" | "ipv6-unicast" => Some(AddressFamily::Ipv6),
        _ => None,
    }
}

// Runs the import policy of an import-rib entry against a route,
// returning whether the route is accepted. No policy accepts everything;
// an unknown policy rejects (fail closed).
pub fn policy_accepts(
    policies: &BTreeMap<String, Arc<Policy>>,
    match_sets: &MatchSets,
    policy_name: Option<&str>,
    prefix: IpNetwork,
    src_protocol: Protocol,
    tag: Option<u32>,
) -> bool {
    let Some(policy_name) = policy_name else {
        return true;
    };
    let Some(policy) = policies.get(policy_name) else {
        return false;
    };

    for stmt in policy.stmts.values() {
        // Check if all conditions in the policy statement are satisfied.
        if !stmt.conditions.values().all(|condition| {
            condition_matches(condition, prefix, src_protocol, tag, match_sets)
        }) {
            continue;
        }
        // The first matching statement decides the route's fate.
        for action in stmt.actions.values() {
            if let PolicyAction::Accept(accept) = action {
                return *accept;
            }
        }
    }

    // Default policy: reject routes no statement accepted.
    false
}

// Evaluates a single policy condition against a route being leaked.
fn condition_matches(
    condition: &PolicyCondition,
    prefix: IpNetwork,
    src_protocol: Protocol,
    tag: Option<u32>,
    match_sets: &MatchSets,
) -> bool {
    match condition {
        PolicyCondition::SrcProtocol(value) => src_protocol == *value,
        PolicyCondition::MatchPrefixSet(value) => {
            let af = prefix.address_family();
            match match_sets.prefixes.get(&(value.clone(), af)) {
                Some(set) => set.matches(&prefix),
                None => false,
            }
        }
        PolicyCondition::MatchTagSet(value) => {
            if let Some(tag) = tag
                && let Some(set) = match_sets.tags.get(value)
            {
                set.tags.contains(&tag)
            } else {
                false
            }
        }
        // Conditions that can't apply to leaked kernel routes.
        PolicyCondition::MatchInterface(_)
        | PolicyCondition::MatchNeighborSet(_)
        | PolicyCondition::MatchRouteType(_)
        | PolicyCondition::CallPolicy(_)
        | PolicyCondition::Bgp(_) => false,
    }
}

// Returns whether the import-rib graph contains a cycle, which would
// make routes leak in a loop between RIBs.
pub fn import_graph_has_cycle(
    rib_config: &BTreeMap<String, RibConfig>,
) -> bool {
    // Depth-first search over target -> source edges.
    fn visit(
        rib: &str,
        rib_config: &BTreeMap<String, RibConfig>,
        stack: &mut Vec<String>,
        done: &mut Vec<String>,
    ) -> bool {
        if done.iter().any(|name| name == rib) {
            return false;
        }
        if stack.iter().any(|name| name == rib) {
            return true;
        }
        stack.push(rib.to_string());
        if let Some(config) = rib_config.get(rib) {
            for source in config.import_ribs.keys() {
                if visit(source, rib_config, stack, done) {
                    return true;
                }
            }
        }
        stack.pop();
        done.push(rib.to_string());
        false
    }

    let mut stack = Vec::new();
    let mut done = Vec::new();
    rib_config
        .keys()
        .any(|rib| visit(rib.as_str(), rib_config, &mut stack, &mut done))
}

// What a candidate-set change implies for the default RIB projection.
#[derive(Clone, Debug)]
pub enum Projection {
    // Project this candidate route as the leaked route.
    Set(RouteMsg),
    // No candidates remain: withdraw the leaked route.
    Withdraw,
    // Nothing changed for this prefix.
    Noop,
}

// Per-source candidate store for leaked routes. Each default RIB
// (target) keeps, per prefix, one candidate route per source RIB that
// leaks it, so removing, rejecting, unbinding or deleting one source
// never withdraws a surviving route from another source, and the
// projected route is the deterministic best candidate rather than
// whatever BTreeMap order happened to replay last.
#[derive(Default)]
pub struct LeakEngine {
    // target rib -> prefix -> source rib -> candidate route.
    candidates:
        BTreeMap<String, BTreeMap<IpNetwork, BTreeMap<String, RouteMsg>>>,
}

impl LeakEngine {
    // Best candidate: lowest distance, then lowest metric; ties break
    // on source name because BTreeMap iteration is name-sorted and
    // min_by_key keeps the first minimum.
    fn pick(by_source: &BTreeMap<String, RouteMsg>) -> Option<&RouteMsg> {
        by_source
            .values()
            .min_by_key(|msg| (msg.distance, msg.metric))
    }

    // Returns the currently projected best candidate, if any.
    #[cfg(test)]
    pub fn best(&self, target: &str, prefix: IpNetwork) -> Option<&RouteMsg> {
        self.candidates
            .get(target)
            .and_then(|rib| rib.get(&prefix))
            .and_then(Self::pick)
    }

    // Records (Some) or withdraws (None) one source's candidate for a
    // prefix and returns the resulting projection for the target RIB.
    pub fn update(
        &mut self,
        target: &str,
        prefix: IpNetwork,
        source: &str,
        candidate: Option<RouteMsg>,
    ) -> Projection {
        let rib = self.candidates.entry(target.to_string()).or_default();
        let by_source = rib.entry(prefix).or_default();
        let removed = by_source.remove(source);
        let inserted = candidate.is_some();
        if let Some(msg) = candidate {
            by_source.insert(source.to_string(), msg);
        }
        if !inserted && removed.is_none() {
            if by_source.is_empty() {
                rib.remove(&prefix);
            }
            return Projection::Noop;
        }
        if by_source.is_empty() {
            rib.remove(&prefix);
            return Projection::Withdraw;
        }
        Projection::Set(Self::pick(by_source).unwrap().clone())
    }

    // Drops every candidate provided by `source` to `target`.
    pub fn drop_source(
        &mut self,
        target: &str,
        source: &str,
    ) -> Vec<(IpNetwork, Projection)> {
        let mut actions = Vec::new();
        if let Some(rib) = self.candidates.get_mut(target) {
            for (prefix, by_source) in rib.iter_mut() {
                if by_source.remove(source).is_some() {
                    let projection = match Self::pick(by_source) {
                        Some(msg) => Projection::Set(msg.clone()),
                        None => Projection::Withdraw,
                    };
                    actions.push((*prefix, projection));
                }
            }
            rib.retain(|_, by_source| !by_source.is_empty());
        }
        actions
    }

    // Drops every candidate provided by `source`, across all targets.
    pub fn drop_source_everywhere(
        &mut self,
        source: &str,
    ) -> Vec<(String, IpNetwork, Projection)> {
        let mut actions = Vec::new();
        let targets: Vec<String> = self.candidates.keys().cloned().collect();
        for target in targets {
            for (prefix, projection) in self.drop_source(&target, source) {
                actions.push((target.clone(), prefix, projection));
            }
        }
        actions
    }

    // Drops everything projected into `target` (its import config or
    // the RIB itself is going away).
    pub fn drop_target(
        &mut self,
        target: &str,
    ) -> Vec<(IpNetwork, Projection)> {
        self.candidates
            .remove(target)
            .map(|rib| {
                rib.keys()
                    .copied()
                    .map(|prefix| (prefix, Projection::Withdraw))
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ===== impl Master =====

impl Master {
    // Processes a route event imported from a kernel routing table:
    // updates the custom RIB bound to that table, then reevaluates the
    // routes leaked from it into default RIBs.
    pub(crate) fn process_kernel_event(&mut self, event: KernelEvent) {
        match event {
            KernelEvent::Add(add) => {
                let af = add.prefix.address_family();
                let Some(rib_name) = self.kernel_rib_name(af, add.table) else {
                    return;
                };
                let route = crate::kernel::kernel_route(&add);
                if let Some(rib) = self.kernel_ribs.get_mut(&rib_name) {
                    // A route confirmed by an ongoing dump is not stale.
                    if let Some(pending) = rib.dump_pending.as_mut() {
                        pending.remove(&add.prefix);
                    }
                    rib.routes.insert(add.prefix, route);
                }
                self.leak_prefix(&rib_name, add.prefix);
            }
            KernelEvent::DumpStart { af, table } => {
                let Some(rib_name) = self.kernel_rib_name(af, table) else {
                    return;
                };
                if let Some(rib) = self.kernel_ribs.get_mut(&rib_name) {
                    rib.dump_pending =
                        Some(rib.routes.keys().copied().collect());
                }
            }
            KernelEvent::DumpEnd { af, table, ok } => {
                let Some(rib_name) = self.kernel_rib_name(af, table) else {
                    return;
                };
                if !ok {
                    // Failed dump: keep the prior RIB contents and
                    // wait for the next successful dump or resync.
                    if let Some(rib) = self.kernel_ribs.get_mut(&rib_name) {
                        rib.abort_dump();
                    }
                    return;
                }
                let stale = self
                    .kernel_ribs
                    .get_mut(&rib_name)
                    .map(|rib| rib.complete_dump())
                    .unwrap_or_default();
                // The kernel no longer has these routes: withdraw them.
                for prefix in stale {
                    if let Some(rib) = self.kernel_ribs.get_mut(&rib_name) {
                        rib.routes.remove(&prefix);
                    }
                    self.unleak_prefix(&rib_name, prefix);
                }
            }
            KernelEvent::Del(del) => {
                let af = del.prefix.address_family();
                let Some(rib_name) = self.kernel_rib_name(af, del.table) else {
                    return;
                };
                if let Some(rib) = self.kernel_ribs.get_mut(&rib_name) {
                    rib.routes.remove(&del.prefix);
                }
                self.unleak_prefix(&rib_name, del.prefix);
            }
        }
    }

    // Returns the name of the custom RIB bound to the given kernel table.
    fn kernel_rib_name(&self, af: AddressFamily, table: u32) -> Option<String> {
        self.kernel_ribs
            .iter()
            .find(|(_, rib)| rib.address_family == af && rib.table_id == table)
            .map(|(name, _)| name.clone())
    }

    // Registers a custom RIB bound to a kernel table, and unregisters
    // the RIB it replaces if any.
    pub(crate) fn set_kernel_rib(
        &mut self,
        name: &str,
        af: AddressFamily,
        table_id: u32,
    ) {
        self.kernel_ribs.insert(
            name.to_string(),
            KernelRib {
                address_family: af,
                table_id,
                routes: Default::default(),
                dump_pending: None,
            },
        );
    }

    // Removes a custom RIB, withdrawing everything leaked from it.
    pub(crate) fn remove_kernel_rib(&mut self, name: &str) {
        self.kernel_ribs.remove(name);
        // Every candidate sourced from this RIB is gone: reproject or
        // withdraw whatever they projected into default RIBs.
        let actions = self.leak_engine.drop_source_everywhere(name);
        for (_target, prefix, projection) in actions {
            self.apply_projection(&projection, prefix);
        }
    }

    // Reevaluates every route of a source RIB, leaking or unleaking as
    // import policies and RIB contents dictate. Called after the source
    // RIB's importers or their policies change.
    pub(crate) fn reevaluate_leaks(&mut self, source: &str) {
        let prefixes: Vec<IpNetwork> = self
            .kernel_ribs
            .get(source)
            .map(|rib| rib.routes.keys().copied().collect())
            .unwrap_or_default();
        for prefix in prefixes {
            self.leak_prefix(source, prefix);
        }
    }

    // Reevaluates every route of every source RIB imported through the
    // given policy. Called when the policy definition changes.
    pub(crate) fn reevaluate_policy_leaks(&mut self, policy_name: &str) {
        let sources: Vec<String> = self
            .rib_config
            .values()
            .flat_map(|config| config.import_ribs.iter())
            .filter(|(_, policy)| policy.as_deref() == Some(policy_name))
            .map(|(source, _)| source.clone())
            .collect();
        for source in sources {
            self.reevaluate_leaks(&source);
        }
    }

    // Leaks the route of the given source RIB and prefix into every
    // default RIB importing from the source, if its import policy
    // accepts it.
    fn leak_prefix(&mut self, source: &str, prefix: IpNetwork) {
        let route = self
            .kernel_ribs
            .get(source)
            .and_then(|rib| rib.routes.get(&prefix))
            .cloned();
        let af = prefix.address_family();
        for (target, config) in self.rib_config.clone() {
            if !config.import_ribs.contains_key(source) {
                continue;
            }
            if !is_default_rib(&target) || config.address_family != Some(af) {
                continue;
            }
            let policy = config.import_ribs[source].as_deref();
            // A rejected or vanished route clears this source's
            // candidate; the projection then falls to the best
            // surviving source, if any.
            let candidate = route.as_ref().and_then(|route| {
                if policy_accepts(
                    &self.shared.policies,
                    &self.shared.policy_match_sets,
                    policy,
                    prefix,
                    route.protocol,
                    route.tag,
                ) {
                    Some(RouteMsg {
                        protocol: Protocol::KERNEL,
                        kind: route.kind,
                        prefix,
                        distance: route.distance,
                        metric: route.metric,
                        tag: route.tag,
                        opaque_attrs: RouteOpaqueAttrs::None,
                        nexthops: route.nexthops.to_vec(),
                    })
                } else {
                    None
                }
            });
            let projection =
                self.leak_engine.update(&target, prefix, source, candidate);
            self.apply_projection(&projection, prefix);
        }
    }

    // Applies a candidate-set projection to the default RIBs.
    pub(crate) fn apply_projection(
        &mut self,
        projection: &Projection,
        prefix: IpNetwork,
    ) {
        match projection {
            Projection::Set(msg) => self.rib.leaked_route_add(msg.clone()),
            Projection::Withdraw => self.rib.leaked_route_del(prefix),
            Projection::Noop => (),
        }
    }

    // Withdraws the route leaked from the given source RIB and prefix
    // from every default RIB importing from the source.
    fn unleak_prefix(&mut self, source: &str, prefix: IpNetwork) {
        for (target, config) in self.rib_config.clone() {
            if !config.import_ribs.contains_key(source) {
                continue;
            }
            if !is_default_rib(&target) {
                continue;
            }
            let projection =
                self.leak_engine.update(&target, prefix, source, None);
            self.apply_projection(&projection, prefix);
        }
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use holo_utils::policy::{
        IpPrefixRange, MatchSetRestrictedType, PolicyStmt, PrefixSet, TagSet,
    };
    use holo_utils::southbound::{RouteKind, RouteOpaqueAttrs};

    use super::*;

    fn match_sets_with_ts_prefixes() -> MatchSets {
        let mut prefixes = BTreeMap::new();
        prefixes.insert(
            ("TS-IPV4".to_string(), AddressFamily::Ipv4),
            PrefixSet {
                name: "TS-IPV4".to_string(),
                mode: AddressFamily::Ipv4,
                prefixes: [IpPrefixRange {
                    prefix: "100.64.0.0/10".parse().unwrap(),
                    masklen_lower: 32,
                    masklen_upper: 32,
                }]
                .into_iter()
                .collect(),
            },
        );
        MatchSets {
            prefixes,
            neighbors: Default::default(),
            tags: Default::default(),
            bgp: Default::default(),
        }
    }

    fn policy_accepting_prefix_set() -> Policy {
        let mut stmts = BTreeMap::new();
        let mut conditions = BTreeMap::new();
        conditions.insert(
            holo_utils::policy::PolicyConditionType::MatchPrefixSet,
            PolicyCondition::MatchPrefixSet("TS-IPV4".to_string()),
        );
        let mut actions = BTreeMap::new();
        actions.insert(
            holo_utils::policy::PolicyActionType::Accept,
            PolicyAction::Accept(true),
        );
        stmts.insert(
            "10".to_string(),
            PolicyStmt {
                name: "10".to_string(),
                prefix_set_match_type: MatchSetRestrictedType::Any,
                tag_set_match_type: holo_utils::policy::MatchSetType::Any,
                conditions,
                actions,
            },
        );
        Policy {
            name: "IMPORT-TAILSCALE".to_string(),
            stmts,
        }
    }

    #[test]
    fn policy_filters_prefixes_within_table() {
        let match_sets = match_sets_with_ts_prefixes();
        let mut policies = BTreeMap::new();
        policies.insert(
            "IMPORT-TAILSCALE".to_string(),
            Arc::new(policy_accepting_prefix_set()),
        );
        let policy = Some("IMPORT-TAILSCALE");

        // 100.64.0.42/32 passes.
        let prefix: IpNetwork = "100.64.0.42/32".parse().unwrap();
        assert!(policy_accepts(
            &policies,
            &match_sets,
            policy,
            prefix,
            Protocol::KERNEL,
            None,
        ));

        // 192.168.1.0/24 from the same table is blocked.
        let prefix: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert!(!policy_accepts(
            &policies,
            &match_sets,
            policy,
            prefix,
            Protocol::KERNEL,
            None,
        ));
    }

    #[test]
    fn unknown_policy_rejects() {
        let match_sets = match_sets_with_ts_prefixes();
        let prefix: IpNetwork = "100.64.0.42/32".parse().unwrap();
        assert!(!policy_accepts(
            &BTreeMap::new(),
            &match_sets,
            Some("MISSING"),
            prefix,
            Protocol::KERNEL,
            None,
        ));
    }

    #[test]
    fn no_policy_accepts_everything() {
        let match_sets = match_sets_with_ts_prefixes();
        let prefix: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert!(policy_accepts(
            &BTreeMap::new(),
            &match_sets,
            None,
            prefix,
            Protocol::KERNEL,
            None,
        ));
    }

    #[test]
    fn cyclic_import_graph_is_detected() {
        let mut rib_config = BTreeMap::new();
        let mut a = RibConfig::default();
        a.import_ribs.insert("b".to_string(), None);
        let mut b = RibConfig::default();
        b.import_ribs.insert("a".to_string(), None);
        rib_config.insert("a".to_string(), a);
        rib_config.insert("b".to_string(), b);
        assert!(import_graph_has_cycle(&rib_config));
    }

    #[test]
    fn acyclic_import_graph_passes() {
        let mut rib_config = BTreeMap::new();
        let mut target = RibConfig::default();
        target.import_ribs.insert("source".to_string(), None);
        rib_config.insert("ipv4-unicast".to_string(), target);
        rib_config.insert("source".to_string(), RibConfig::default());
        assert!(!import_graph_has_cycle(&rib_config));
    }

    #[test]
    fn tag_set_condition_supported() {
        let mut tags = BTreeMap::new();
        tags.insert(
            "TS-TAGS".to_string(),
            TagSet {
                name: "TS-TAGS".to_string(),
                tags: [42].into_iter().collect(),
            },
        );
        let match_sets = MatchSets {
            prefixes: Default::default(),
            neighbors: Default::default(),
            tags,
            bgp: Default::default(),
        };
        let mut stmts = BTreeMap::new();
        let mut conditions = BTreeMap::new();
        conditions.insert(
            holo_utils::policy::PolicyConditionType::MatchTagSet,
            PolicyCondition::MatchTagSet("TS-TAGS".to_string()),
        );
        let mut actions = BTreeMap::new();
        actions.insert(
            holo_utils::policy::PolicyActionType::Accept,
            PolicyAction::Accept(true),
        );
        stmts.insert(
            "10".to_string(),
            PolicyStmt {
                name: "10".to_string(),
                prefix_set_match_type: MatchSetRestrictedType::Any,
                tag_set_match_type: holo_utils::policy::MatchSetType::Any,
                conditions,
                actions,
            },
        );
        let mut policies = BTreeMap::new();
        policies.insert(
            "TAG-POLICY".to_string(),
            Arc::new(Policy {
                name: "TAG-POLICY".to_string(),
                stmts,
            }),
        );
        let prefix: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(policy_accepts(
            &policies,
            &match_sets,
            Some("TAG-POLICY"),
            prefix,
            Protocol::KERNEL,
            Some(42),
        ));
        assert!(!policy_accepts(
            &policies,
            &match_sets,
            Some("TAG-POLICY"),
            prefix,
            Protocol::KERNEL,
            Some(43),
        ));
    }

    #[test]
    fn rib_address_family_parses_plain_and_qualified() {
        assert_eq!(rib_address_family("ipv4"), Some(AddressFamily::Ipv4));
        assert_eq!(
            rib_address_family("ietf-ip:ipv4"),
            Some(AddressFamily::Ipv4)
        );
        assert_eq!(
            rib_address_family("ietf-ipv4-unicast-routing:ipv4-unicast"),
            Some(AddressFamily::Ipv4)
        );
        assert_eq!(
            rib_address_family("ietf-ip:ipv6"),
            Some(AddressFamily::Ipv6)
        );
        assert_eq!(
            rib_address_family("ietf-ipv6-unicast-routing:ipv6-unicast"),
            Some(AddressFamily::Ipv6)
        );
        assert_eq!(rib_address_family("mpls"), None);
    }

    fn cand(metric: u32, tag: u32) -> RouteMsg {
        RouteMsg {
            protocol: Protocol::KERNEL,
            kind: RouteKind::Unicast,
            prefix: "10.0.0.0/24".parse().unwrap(),
            distance: 10,
            metric,
            tag: Some(tag),
            opaque_attrs: RouteOpaqueAttrs::None,
            nexthops: vec![],
        }
    }

    fn projected(p: Projection) -> Option<(u32, u32)> {
        match p {
            Projection::Set(msg) => Some((msg.metric, msg.tag.unwrap())),
            _ => None,
        }
    }

    #[test]
    fn second_source_survives_first_removal() {
        let prefix: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let mut engine = LeakEngine::default();
        // src-a leaks a worse route first, then src-b a better one.
        assert_eq!(
            projected(engine.update("t", prefix, "src-a", Some(cand(5, 1)))),
            Some((5, 1))
        );
        assert_eq!(
            projected(engine.update("t", prefix, "src-b", Some(cand(1, 2)))),
            Some((1, 2))
        );
        // Removing the winning source reprojects the survivor.
        assert_eq!(
            projected(engine.update("t", prefix, "src-b", None)),
            Some((5, 1))
        );
        // Removing the last source withdraws.
        assert!(matches!(
            engine.update("t", prefix, "src-a", None),
            Projection::Withdraw
        ));
        // Removing an unknown source changes nothing.
        assert!(matches!(
            engine.update("t", prefix, "src-z", None),
            Projection::Noop
        ));
    }

    #[test]
    fn candidate_selection_is_deterministic() {
        let prefix: IpNetwork = "10.0.0.0/24".parse().unwrap();
        // Equal distance and metric: the tie breaks on source name,
        // independent of insertion order.
        for order in [["src-a", "src-b"], ["src-b", "src-a"]] {
            let mut engine = LeakEngine::default();
            for source in order {
                let tag = if source == "src-a" { 1 } else { 2 };
                engine.update("t", prefix, source, Some(cand(0, tag)));
            }
            let best = engine.best("t", prefix).unwrap();
            assert_eq!(
                (best.metric, best.tag.unwrap()),
                (0, 1),
                "src-a must win regardless of insertion order"
            );
        }
    }

    #[test]
    fn policy_rejection_only_clears_own_source() {
        let prefix: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let mut engine = LeakEngine::default();
        engine.update("t", prefix, "src-a", Some(cand(1, 1)));
        engine.update("t", prefix, "src-b", Some(cand(2, 2)));
        // src-b's route gets rejected by a policy update: only its
        // candidate is cleared; src-a's route stays projected.
        assert_eq!(
            projected(engine.update("t", prefix, "src-b", None)),
            Some((1, 1))
        );
    }

    #[test]
    fn drop_source_and_target_cover_shared_prefixes() {
        let shared: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let solo: IpNetwork = "10.0.1.0/24".parse().unwrap();
        let mut engine = LeakEngine::default();
        engine.update("t", shared, "src-a", Some(cand(1, 1)));
        engine.update("t", shared, "src-b", Some(cand(2, 2)));
        engine.update("t", solo, "src-b", Some(cand(2, 3)));
        let actions = engine.drop_source("t", "src-b");
        // shared falls back to src-a; solo is withdrawn.
        assert_eq!(actions.len(), 2);
        for (prefix, projection) in actions {
            if prefix == shared {
                assert_eq!(projected(projection), Some((1, 1)));
            } else {
                assert!(matches!(projection, Projection::Withdraw));
            }
        }
        // Dropping the target withdraws everything it projected.
        let actions = engine.drop_target("t");
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].1, Projection::Withdraw));
    }
}
