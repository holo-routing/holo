//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};
use holo_utils::yang::DataNodeRefExt;
use holo_yang::TryFromYang;
use yang4::data::{Data, DataTree};

use crate::adjacency::AdjacencyEvent;
use crate::instance::Instance;
use crate::northbound::{yang_gen, yang_gen as yang};
use crate::packet::LevelType;

impl Provider for Instance {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}

// ===== YANG impls =====

impl YangRpc<Instance> for yang::clear_adjacency::ClearAdjacency {
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((mut instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let ifname = rpc.get_string_relative("./interface");

        // Clear adjacencies.
        for iface in arenas
            .interfaces
            .iter_mut()
            // Filter by interface name.
            .filter(|iface| ifname.is_none() || *ifname.as_ref().unwrap() == iface.name)
        {
            let event = AdjacencyEvent::Kill;
            iface.clear_adjacencies(&mut instance, &mut arenas.adjacencies, event);
        }

        Ok(())
    }
}

impl YangRpc<Instance> for yang::clear_database::ClearDatabase {
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((mut instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let level_type = rpc.get_string_relative("./level").and_then(|level_type| LevelType::try_from_yang(&level_type)).unwrap_or(LevelType::All);

        // Kill all adjacencies.
        for iface in arenas.interfaces.iter_mut() {
            let event = AdjacencyEvent::Kill;
            iface.clear_adjacencies(&mut instance, &mut arenas.adjacencies, event);
        }

        // Clear database.
        for level in level_type {
            let lsdb = instance.state.lsdb.get_mut(level);
            lsdb.clear(&mut arenas.lsp_entries);
        }

        Ok(())
    }
}
