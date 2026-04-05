//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};

use crate::adjacency::AdjacencyEvent;
use crate::instance::Instance;
use crate::northbound::{yang_gen, yang_gen as yang};
use crate::packet::LevelType;

impl Provider for Instance {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}

// ===== YANG impls =====

impl YangRpc<Instance> for yang::clear_adjacency::ClearAdjacency {
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((mut instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        for iface in arenas.interfaces.iter_mut() {
            // Filter by interface name.
            if let Some(interface) = &self.input.interface
                && *interface != iface.name
            {
                continue;
            }

            // Clear adjacencies.
            let event = AdjacencyEvent::Kill;
            iface.clear_adjacencies(&mut instance, &mut arenas.adjacencies, event);
        }

        Ok(())
    }
}

impl YangRpc<Instance> for yang::clear_database::ClearDatabase {
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((mut instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        // Kill all adjacencies.
        for iface in arenas.interfaces.iter_mut() {
            let event = AdjacencyEvent::Kill;
            iface.clear_adjacencies(&mut instance, &mut arenas.adjacencies, event);
        }

        // Clear database.
        let level_type = self.input.level.unwrap_or(LevelType::All);
        for level in level_type {
            let lsdb = instance.state.lsdb.get_mut(level);
            lsdb.clear(&mut arenas.lsp_entries);
        }

        Ok(())
    }
}
