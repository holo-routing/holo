//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use yang3::data::Data;

use crate::adjacency::AdjacencyEvent;
use crate::instance::{Instance, InstanceArenas, InstanceUpView};
use crate::packet::LevelType;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(yang::clear_adjacency::PATH)
        .rpc(|instance, args| {
            let rpc = args.data.find_path(args.rpc_path).unwrap();

            // Parse input parameters.
            let ifname = rpc.get_string_relative("./interface");

            // Clear adjacencies.
            if let Some((mut instance, arenas)) = instance.as_up() {
                clear_adjacencies(&mut instance, arenas, ifname);
            }

            Ok(())
        })
        .path(yang::isis_clear_database::PATH)
        .rpc(|instance, args| {
            let rpc = args.data.find_path(args.rpc_path).unwrap();

            // Parse input parameters.
            let level_type = rpc
                .get_string_relative("./level")
                .and_then(|level_type| LevelType::try_from_yang(&level_type))
                .unwrap_or(LevelType::All);

            // Clear database.
            if let Some((mut instance, arenas)) = instance.as_up() {
                clear_database(&mut instance, arenas, level_type);
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }
}

// ===== helper functions =====

fn clear_adjacencies(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    ifname: Option<String>,
) {
    // Kill adjacencies.
    for iface in arenas
        .interfaces
        .iter_mut()
        // Filter by interface name.
        .filter(|iface| {
            ifname.is_none() || *ifname.as_ref().unwrap() == iface.name
        })
    {
        let event = AdjacencyEvent::Kill;
        iface.clear_adjacencies(instance, &mut arenas.adjacencies, event);
    }
}

fn clear_database(
    instance: &mut InstanceUpView<'_>,
    arenas: &mut InstanceArenas,
    level_type: LevelType,
) {
    // Kill all adjacencies.
    for iface in arenas.interfaces.iter_mut() {
        let event = AdjacencyEvent::Kill;
        iface.clear_adjacencies(instance, &mut arenas.adjacencies, event);
    }

    // Clear database.
    for level in level_type {
        let lsdb = instance.state.lsdb.get_mut(level);
        lsdb.clear(&mut arenas.lsp_entries);
    }
}
