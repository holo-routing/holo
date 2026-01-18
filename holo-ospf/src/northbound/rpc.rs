//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};
use holo_utils::yang::DataNodeRefExt;
use yang4::data::{Data, DataTree};

use crate::instance::Instance;
use crate::neighbor::nsm;
use crate::northbound::yang_gen as yang;
use crate::version::Version;

impl<V> Provider for Instance<V>
where
    V: Version,
{
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_RPC;
}

// ===== YANG impls =====

impl<V: Version> YangRpc<Instance<V>> for yang::clear_neighbor::ClearNeighbor {
    fn invoke(instance: &mut Instance<V>, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let ifname = rpc.get_string_relative("./interface");

        // Clear neighbors.
        for area in arenas.areas.iter() {
            for iface in area
                .interfaces
                .iter(&arenas.interfaces)
                // Filter by interface name.
                .filter(|iface| ifname.is_none() || *ifname.as_ref().unwrap() == iface.name)
            {
                // Kill neighbors from this interface.
                for nbr in iface.state.neighbors.iter(&arenas.neighbors) {
                    instance.tx.protocol_input.nsm_event(area.id, iface.id, nbr.id, nsm::Event::Kill);
                }
            }
        }

        Ok(())
    }
}

impl<V: Version> YangRpc<Instance<V>> for yang::clear_database::ClearDatabase {
    fn invoke(instance: &mut Instance<V>, _data: &mut DataTree<'static>, _rpc_path: &str) -> Result<(), String> {
        let Some((instance, arenas)) = instance.as_up() else {
            return Ok(());
        };

        // Clear AS-scope LSDB.
        instance.state.lsdb.clear(&mut arenas.lsa_entries);

        for area in arenas.areas.iter_mut() {
            // Clear area-scope LSDB.
            area.state.lsdb.clear(&mut arenas.lsa_entries);

            for iface_idx in area.interfaces.indexes() {
                let iface = &mut arenas.interfaces[iface_idx];

                // Clear interface-scope LSDB.
                iface.state.lsdb.clear(&mut arenas.lsa_entries);

                // Kill neighbors from this interface.
                for nbr in iface.state.neighbors.iter(&arenas.neighbors) {
                    instance.tx.protocol_input.nsm_event(area.id, iface.id, nbr.id, nsm::Event::Kill);
                }
            }
        }

        Ok(())
    }
}
