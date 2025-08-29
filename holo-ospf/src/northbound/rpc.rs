//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang;
use holo_utils::yang::DataNodeRefExt;
use yang3::data::Data;

use crate::instance::{Instance, InstanceArenas, InstanceUpView};
use crate::neighbor::nsm;
use crate::version::{Ospfv2, Ospfv3, Version};

pub static CALLBACKS_OSPFV2: Lazy<Callbacks<Instance<Ospfv2>>> =
    Lazy::new(load_callbacks);
pub static CALLBACKS_OSPFV3: Lazy<Callbacks<Instance<Ospfv3>>> =
    Lazy::new(load_callbacks);

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(yang::clear_neighbor::PATH)
        .rpc(|instance, args| {
            let rpc = args.data.find_path(args.rpc_path).unwrap();

            // Parse input parameters.
            let ifname = rpc.get_string_relative("./interface");

            // Clear neighbors.
            if let Some((instance, arenas)) = instance.as_up() {
                clear_neighbors(&instance, arenas, ifname);
            }

            Ok(())
        })
        .path(yang::clear_database::PATH)
        .rpc(|instance, _args| {
            // Clear database.
            if let Some((mut instance, arenas)) = instance.as_up() {
                clear_database(&mut instance, arenas);
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::rpc_callbacks()
    }
}

// ===== helper functions =====

fn clear_neighbors<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &InstanceArenas<V>,
    ifname: Option<String>,
) where
    V: Version,
{
    for area in arenas.areas.iter() {
        for iface in area
            .interfaces
            .iter(&arenas.interfaces)
            // Filter by interface name.
            .filter(|iface| {
                ifname.is_none() || *ifname.as_ref().unwrap() == iface.name
            })
        {
            // Kill neighbors from this interface.
            for nbr in iface.state.neighbors.iter(&arenas.neighbors) {
                instance.tx.protocol_input.nsm_event(
                    area.id,
                    iface.id,
                    nbr.id,
                    nsm::Event::Kill,
                );
            }
        }
    }
}

fn clear_database<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
) where
    V: Version,
{
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
                instance.tx.protocol_input.nsm_event(
                    area.id,
                    iface.id,
                    nbr.id,
                    nsm::Event::Kill,
                );
            }
        }
    }
}
