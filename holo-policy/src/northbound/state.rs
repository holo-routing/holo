//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use enum_as_inner::EnumAsInner;
use holo_northbound::paths::routing_policy;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};

use crate::Master;

pub static CALLBACKS: Lazy<Callbacks<Master>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry {
    #[default]
    None,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Master> {
    CallbacksBuilder::default()
        .path(routing_policy::defined_sets::prefix_sets::prefix_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::prefix_sets::prefix_set::prefixes::prefix_list::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::neighbor_sets::neighbor_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::neighbor_sets::neighbor_set::address::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::tag_sets::tag_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::tag_sets::tag_set::tag_value::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::as_path_sets::as_path_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::as_path_sets::as_path_set::member::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::community_sets::community_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::community_sets::community_set::member::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::ext_community_sets::ext_community_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::ext_community_sets::ext_community_set::member::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::ipv6_ext_community_sets::ipv6_ext_community_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::ipv6_ext_community_sets::ipv6_ext_community_set::member::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::large_community_sets::large_community_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::large_community_sets::large_community_set::member::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::next_hop_sets::next_hop_set::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::defined_sets::bgp_defined_sets::next_hop_sets::next_hop_set::next_hop::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::match_route_type::route_type::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::bgp_conditions::match_afi_safi::afi_safi_in::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::conditions::bgp_conditions::match_neighbor::neighbor_eq::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::bgp_actions::set_as_path_prepend::asn::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::bgp_actions::set_community::communities::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::bgp_actions::set_ext_community::communities::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::bgp_actions::set_ipv6_ext_community::communities::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .path(routing_policy::policy_definitions::policy_definition::statements::statement::actions::bgp_actions::set_large_community::communities::PATH)
        .get_iterate(|_master, _args| {
            // No operational data under this list.
            None
        })
        .build()
}

// ===== impl Master =====

impl Provider for Master {
    const STATE_PATH: &'static str = "/ietf-routing-policy:routing-policy";

    type ListEntry<'a> = ListEntry;

    fn callbacks() -> Option<&'static Callbacks<Master>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
        }
    }
}
