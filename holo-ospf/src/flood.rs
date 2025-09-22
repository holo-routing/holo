//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::btree_map;
use std::sync::Arc;

use crate::area::Area;
use crate::collections::{
    Areas, Arena, InterfaceIndex, LsdbIndex, NeighborIndex,
};
use crate::instance::InstanceUpView;
use crate::interface::{Interface, ism};
use crate::lsdb;
use crate::neighbor::{Neighbor, nsm};
use crate::packet::lsa::{Lsa, LsaHdrVersion};
use crate::version::Version;

// ===== global functions =====

pub(crate) fn flood<V>(
    instance: &InstanceUpView<'_, V>,
    areas: &Areas<V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsdb_idx: LsdbIndex,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
) -> bool
where
    V: Version,
{
    // Iterate over eligible interfaces.
    //
    // For OSPFv3, the LSDB index already takes into consideration the U-bit of
    // the LSA, so there's no need to check it here.
    match lsdb_idx {
        LsdbIndex::Link(area_idx, iface_idx) => {
            let area = &areas[area_idx];
            flood_interface(
                iface_idx, area, instance, interfaces, neighbors, lsa, src,
            )
        }
        LsdbIndex::Area(area_idx) => {
            let area = &areas[area_idx];
            flood_area(area, instance, interfaces, neighbors, lsa, src)
        }
        LsdbIndex::As => {
            flood_as(instance, areas, interfaces, neighbors, lsa, src)
        }
    }
}

// ===== helper functions =====

fn flood_interface<V>(
    iface_idx: InterfaceIndex,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
) -> bool
where
    V: Version,
{
    let iface = &mut interfaces[iface_idx];
    let lsa_key = lsa.hdr.key();

    // Keep track that this LSA was flooded back out the receiving interface.
    // This information is relevant when deciding whether or not to send a
    // delayed ack later.
    let mut flooded_back = false;

    // 1) Each of the neighbors attached to this interface are examined.
    let mut rxmt_added = false;
    for nbr_idx in iface.state.neighbors.indexes() {
        let nbr = &mut neighbors[nbr_idx];

        // 1.a) Skip neighbors in a lesser state than Exchange.
        if nbr.state < nsm::State::Exchange {
            continue;
        }

        // Check if the LSA type is valid for this neighbor.
        if !V::lsa_type_is_valid(
            None,
            Some(iface.config.if_type),
            nbr.options,
            lsa.hdr.lsa_type(),
        ) {
            continue;
        }

        // 1.b) Handle adjacencies that are not full.
        if nbr.state != nsm::State::Full {
            use btree_map::Entry::Occupied;

            // Examine the Link state request list associated with this
            // adjacency.
            match (
                nbr.lists.ls_request.entry(lsa_key),
                nbr.lists.ls_request_pending.entry(lsa_key),
            ) {
                (Occupied(o), _) | (_, Occupied(o)) => {
                    let req = o.get();
                    let cmp = lsdb::lsa_compare::<V>(&lsa.hdr, req);
                    match cmp {
                        Ordering::Less => continue,
                        Ordering::Equal | Ordering::Greater => {
                            // Delete the LSA from the Link state request list.
                            o.remove();

                            // Check if the neighbor can transition to Full.
                            nbr.loading_done_check(iface, area, instance);

                            // Examine the next neighbor if the two copies are
                            // the same instance.
                            if cmp == Ordering::Equal {
                                continue;
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        // 1.c) If the new LSA was received from this neighbor, examine the
        // next neighbor.
        if let Some((_, nbr_src_idx)) = src
            && nbr_src_idx == nbr_idx
        {
            continue;
        }

        // 1.d) Add LSA to the neighbor's rxmt list (or update the old version).
        nbr.lists.ls_rxmt.insert(lsa_key, lsa.clone());
        nbr.rxmt_lsupd_start_check(iface, area, instance);
        rxmt_added = true;
    }
    // 2) If in the previous step, the LSA was NOT added to any of the Link
    // state retransmission lists, there is no need to flood the LSA out the
    // interface and the next interface should be examined.
    if !rxmt_added {
        return flooded_back;
    }

    if let Some((iface_src_idx, nbr_src_idx)) = src
        && iface_src_idx == iface_idx
    {
        let nbr_src = &neighbors[nbr_src_idx];
        let nbr_src_net_id = nbr_src.network_id();

        // 3) If the new LSA was received on this interface, and it was
        // received from either the DR or the BDR, chances are
        // that all the neighbors have received the LSA already.
        // Therefore, examine the next interface.
        if iface.state.dr == Some(nbr_src_net_id)
            || iface.state.bdr == Some(nbr_src_net_id)
        {
            return flooded_back;
        }

        // 4) If the new LSA was received on this interface, and the
        // interface state is BDR, examine the next interface.
        if iface.state.ism_state == ism::State::Backup {
            return flooded_back;
        }

        flooded_back = true;
    }

    // Flood the LSA out the interface. Schedule the transmission as an attempt
    // to group more LSAs into the same message.
    iface.enqueue_ls_update(area, instance, lsa_key, lsa.clone());

    flooded_back
}

fn flood_area<V>(
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
) -> bool
where
    V: Version,
{
    let mut flooded_back = false;
    for iface_idx in area.interfaces.indexes() {
        flooded_back |= flood_interface(
            iface_idx, area, instance, interfaces, neighbors, lsa, src,
        );
    }

    flooded_back
}

fn flood_as<V>(
    instance: &InstanceUpView<'_, V>,
    areas: &Areas<V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
) -> bool
where
    V: Version,
{
    let mut flooded_back = false;
    for area in areas
        .iter()
        // Check if the LSA type is valid for this area.
        .filter(|area| {
            V::lsa_type_is_valid(
                Some(area.config.area_type),
                None,
                None,
                lsa.hdr.lsa_type(),
            )
        })
    {
        flooded_back |=
            flood_area(area, instance, interfaces, neighbors, lsa, src);
    }

    flooded_back
}
