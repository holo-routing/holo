//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::{btree_map, BTreeSet};
use std::sync::{Arc, LazyLock as Lazy};

use async_trait::async_trait;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    self, Callbacks, CallbacksBuilder, Provider,
};
use holo_northbound::paths::routing_policy;
use holo_utils::ibus::IbusMsg;
use holo_utils::ip::AddressFamily;
use holo_utils::policy::{
    IpPrefixRange, MatchSetRestrictedType, MatchSetType, MetricModification,
    MetricType, NeighborSet, Policy, PolicyAction, PolicyActionType,
    PolicyCondition, PolicyConditionType, PolicyStmt, PrefixSet, RouteLevel,
    RouteType, TagSet,
};
use holo_utils::protocol::Protocol;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;

use crate::Master;

static CALLBACKS: Lazy<configuration::Callbacks<Master>> =
    Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
    PrefixSet(String, AddressFamily),
    NeighborSet(String),
    TagSet(String),
    Policy(String),
    PolicyStmt(String, String),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    MatchSetsUpdate,
    PolicyChange(String),
    PolicyDelete(String),
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::<Master>::default()
        .path(routing_policy::defined_sets::prefix_sets::prefix_set::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("./name").unwrap();
            let mode = args.dnode.get_string_relative("./mode").unwrap();
            let mode = match mode.as_str() {
                "ipv4" => AddressFamily::Ipv4,
                "ipv6" => AddressFamily::Ipv6,
                _ => unreachable!(),
            };
            let set = PrefixSet {
                name: name.clone(),
                mode,
                prefixes: Default::default(),
            };
            master.match_sets.prefixes.insert((name, mode), set);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_prefix_set().unwrap();
            master.match_sets.prefixes.remove(&name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("./name").unwrap();
            let mode = dnode.get_string_relative("./mode").unwrap();
            let mode = match mode.as_str() {
                "ipv4" => AddressFamily::Ipv4,
                "ipv6" => AddressFamily::Ipv6,
                _ => unreachable!(),
            };
            ListEntry::PrefixSet(name, mode)
        })
        .path(routing_policy::defined_sets::prefix_sets::prefix_set::prefixes::prefix_list::PATH)
        .create_apply(|master, args| {
            let name = args.list_entry.into_prefix_set().unwrap();
            let set = master.match_sets.prefixes.get_mut(&name).unwrap();

            let prefix = args.dnode.get_prefix_relative("./ip-prefix").unwrap();
            let masklen_lower = args.dnode.get_u8_relative("./mask-length-lower").unwrap();
            let masklen_upper = args.dnode.get_u8_relative("./mask-length-upper").unwrap();
            let prefix_range = IpPrefixRange {
                prefix,
                masklen_lower,
                masklen_upper,
            };
            set.prefixes.insert(prefix_range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_prefix_set().unwrap();
            let set = master.match_sets.prefixes.get_mut(&name).unwrap();

            let prefix = args.dnode.get_prefix_relative("./ip-prefix").unwrap();
            let masklen_lower = args.dnode.get_u8_relative("./mask-length-lower").unwrap();
            let masklen_upper = args.dnode.get_u8_relative("./mask-length-upper").unwrap();
            let prefix_range = IpPrefixRange {
                prefix,
                masklen_lower,
                masklen_upper,
            };
            set.prefixes.remove(&prefix_range);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .lookup(|_master, _list_entry, _dnode| {
            ListEntry::None
        })
        .path(routing_policy::defined_sets::neighbor_sets::neighbor_set::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("./name").unwrap();
            let set = NeighborSet {
                name: name.clone(),
                addrs: Default::default(),
            };
            master.match_sets.neighbors.insert(name, set);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_neighbor_set().unwrap();
            master.match_sets.neighbors.remove(&name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("./name").unwrap();
            ListEntry::NeighborSet(name)
        })
        .path(routing_policy::defined_sets::neighbor_sets::neighbor_set::address::PATH)
        .create_apply(|master, args| {
            let name = args.list_entry.into_neighbor_set().unwrap();
            let set = master.match_sets.neighbors.get_mut(&name).unwrap();

            let addr = args.dnode.get_ip();
            set.addrs.insert(addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_neighbor_set().unwrap();
            let set = master.match_sets.neighbors.get_mut(&name).unwrap();

            let addr = args.dnode.get_ip();
            set.addrs.remove(&addr);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .path(routing_policy::defined_sets::tag_sets::tag_set::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("./name").unwrap();
            let set = TagSet {
                name: name.clone(),
                tags: Default::default(),
            };
            master.match_sets.tags.insert(name, set);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_tag_set().unwrap();
            master.match_sets.tags.remove(&name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("./name").unwrap();
            ListEntry::TagSet(name)
        })
        .path(routing_policy::defined_sets::tag_sets::tag_set::tag_value::PATH)
        .create_apply(|master, args| {
            let name = args.list_entry.into_tag_set().unwrap();
            let set = master.match_sets.tags.get_mut(&name).unwrap();

            let tag = args.dnode.get_string();
            let tag: u32 = tag.parse().unwrap();
            set.tags.insert(tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_tag_set().unwrap();
            let set = master.match_sets.tags.get_mut(&name).unwrap();

            let tag = args.dnode.get_string();
            let tag: u32 = tag.parse().unwrap();
            set.tags.remove(&tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::MatchSetsUpdate);
        })
        .path(routing_policy::policy_definitions::policy_definition::PATH)
        .create_apply(|master, args| {
            let name = args.dnode.get_string_relative("./name").unwrap();
            let policy = Policy {
                name: name.clone(),
                stmts: Default::default(),
            };
            master.policies.insert(name, policy);
        })
        .delete_apply(|master, args| {
            let name = args.list_entry.into_policy().unwrap();
            master.policies.remove(&name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyDelete(name.clone()));
        })
        .lookup(|_master, _list_entry, dnode| {
            let name = dnode.get_string_relative("./name").unwrap();
            ListEntry::Policy(name)
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::PATH)
        .create_apply(|master, args| {
            let policy_name = args.list_entry.into_policy().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();

            let stmt_name = args.dnode.get_string_relative("./name").unwrap();
            let stmt = PolicyStmt::new(stmt_name.clone());
            policy.stmts.insert(stmt_name, stmt);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();

            policy.stmts.remove(&stmt_name);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .lookup(|_master, list_entry, dnode| {
            let policy_name = list_entry.into_policy().unwrap();

            let stmt_name = dnode.get_string_relative("./name").unwrap();
            ListEntry::PolicyStmt(policy_name, stmt_name)
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::call_policy::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let call_policy = args.dnode.get_string();
            stmt.condition_add(PolicyCondition::CallPolicy(call_policy));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::CallPolicy);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::source_protocol::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let protocol = args.dnode.get_string();
            let protocol = Protocol::try_from_yang(&protocol).unwrap();
            stmt.condition_add(PolicyCondition::SrcProtocol(protocol));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::SrcProtocol);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_interface::interface::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let interface = args.dnode.get_string();
            stmt.condition_add(PolicyCondition::MatchInterface(interface));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::MatchInterface);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_prefix_set::prefix_set::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let prefix_set = args.dnode.get_string();
            stmt.condition_add(PolicyCondition::MatchPrefixSet(prefix_set));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::MatchPrefixSet);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_prefix_set::match_set_options::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let match_type = args.dnode.get_string();
            let match_type = MatchSetRestrictedType::try_from_yang(&match_type).unwrap();
            stmt.prefix_set_match_type = match_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_neighbor_set::neighbor_set::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let neighbor_set = args.dnode.get_string();
            stmt.condition_add(PolicyCondition::MatchNeighborSet(neighbor_set));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::MatchNeighborSet);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_tag_set::tag_set::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let tag_set = args.dnode.get_string();
            stmt.condition_add(PolicyCondition::MatchTagSet(tag_set));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.condition_remove(PolicyConditionType::MatchTagSet);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_tag_set::match_set_options::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let match_type = args.dnode.get_string();
            let match_type = MatchSetType::try_from_yang(&match_type).unwrap();
            stmt.tag_set_match_type = match_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_route_type::route_type::PATH)
        .create_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let route_type = args.dnode.get_string();
            let route_type = RouteType::try_from_yang(&route_type).unwrap();
            stmt.conditions
                .entry(PolicyConditionType::MatchRouteType)
                .or_insert_with(|| PolicyCondition::MatchRouteType(BTreeSet::new()))
                .as_match_route_type_mut()
                .unwrap()
                .insert(route_type);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let route_type = args.dnode.get_string();
            let route_type = RouteType::try_from_yang(&route_type).unwrap();
            if let btree_map::Entry::Occupied(mut entry) =
                stmt.conditions.entry(PolicyConditionType::MatchRouteType)
            {
                let route_types =
                    entry.get_mut().as_match_route_type_mut().unwrap();
                route_types.remove(&route_type);
                if route_types.is_empty() {
                    entry.remove();
                }
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::policy_result::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let policy_result = args.dnode.get_string();
            let accept = policy_result == "accept-route";
            stmt.action_add(PolicyAction::Accept(accept));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::Accept);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_metric::metric_modification::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let metric_mod = args.dnode.get_string();
            let metric_mod = MetricModification::try_from_yang(&metric_mod).unwrap();
            stmt.action_add(PolicyAction::SetMetricMod(metric_mod));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetMetricMod);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_metric::metric::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let metric = args.dnode.get_u32();
            stmt.action_add(PolicyAction::SetMetric(metric));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetMetric);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_metric_type::metric_type::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let metric_type = args.dnode.get_string();
            let metric_type = MetricType::try_from_yang(&metric_type).unwrap();
            stmt.action_add(PolicyAction::SetMetricType(metric_type));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetMetricType);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_route_level::route_level::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let route_level = args.dnode.get_string();
            let route_level = RouteLevel::try_from_yang(&route_level).unwrap();
            stmt.action_add(PolicyAction::SetRouteLevel(route_level));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetRouteLevel);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_route_preference::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let route_pref = args.dnode.get_u16();
            stmt.action_add(PolicyAction::SetRoutePref(route_pref));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetRoutePref);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_tag::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let tag = args.dnode.get_string();
            let tag: u32 = tag.parse().unwrap();
            stmt.action_add(PolicyAction::SetTag(tag));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetTag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::set_application_tag::PATH)
        .modify_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            let app_tag = args.dnode.get_string();
            let app_tag: u32 = app_tag.parse().unwrap();
            stmt.action_add(PolicyAction::SetAppTag(app_tag));

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .delete_apply(|master, args| {
            let (policy_name, stmt_name) = args.list_entry.into_policy_stmt().unwrap();
            let policy = master.policies.get_mut(&policy_name).unwrap();
            let stmt = policy.stmts.get_mut(&stmt_name).unwrap();

            stmt.action_remove(PolicyActionType::SetAppTag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::PolicyChange(policy.name.clone()));
        })
        .build()
}

// ===== impl Master =====

#[async_trait]
impl Provider for Master {
    type ListEntry = ListEntry;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }

    async fn process_event(&mut self, event: Event) {
        match event {
            Event::MatchSetsUpdate => {
                // Create a reference-counted copy of the policy match sets to
                // be shared among all protocol instances.
                let match_sets = Arc::new(self.match_sets.clone());

                // Notify protocols that the policy match sets have been
                // updated.
                let msg = IbusMsg::PolicyMatchSetsUpd(match_sets);
                let _ = self.ibus_tx.send(msg);
            }
            Event::PolicyChange(name) => {
                let policy = self.policies.get_mut(&name).unwrap();

                // Create a reference-counted copy of the policy definition to
                // be shared among all protocol instances.
                let policy = Arc::new(policy.clone());

                // Notify protocols that the policy has been updated.
                let msg = IbusMsg::PolicyUpd(policy);
                let _ = self.ibus_tx.send(msg);
            }
            Event::PolicyDelete(name) => {
                // Notify protocols that the policy definition has been deleted.
                let msg = IbusMsg::PolicyDel(name);
                let _ = self.ibus_tx.send(msg);
            }
        }
    }
}
