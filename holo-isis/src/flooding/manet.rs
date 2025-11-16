//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::{BTreeMap, BTreeSet, HashMap};

use num_traits::FromPrimitive;

use crate::adjacency::{Adjacency, AdjacencyState};
use crate::collections::{Arena, Interfaces};
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::lsdb::LspEntry;
use crate::packet::consts::FloodingAlgo;
use crate::packet::{LevelNumber, LspId, SystemId};
use crate::spf::{self, MetricMode, Spt};

#[derive(Debug, Default)]
pub struct FloodingReduction {
    // Cached data for each neighbor.
    neighbors: HashMap<SystemId, NeighborCache>,
}

#[derive(Debug, Default)]
pub struct NeighborCache {
    // SPT computed with the hop count metric.
    pub spt_hopcount: Spt,
    // Remote Neighbor List (RNL).
    pub remote_nbr_list: BTreeMap<SystemId, FloodingAlgo>,
}

// ===== global functions =====

pub(crate) fn init_cache(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
    lsp_entries: &Arena<LspEntry>,
) {
    // Process all adjacencies on active interfaces.
    for adj in interfaces
        .iter()
        .filter(|iface| iface.state.active)
        .flat_map(|iface| {
            iface
                .adjacencies(adjacencies)
                .filter(|adj| adj.state == AdjacencyState::Up)
        })
    {
        let mut cache = NeighborCache::default();

        // Compute a hop count SPT rooted at this neighbor.
        cache.spt_hopcount = spf::compute_spt(
            level,
            adj.system_id,
            false,
            None,
            MetricMode::HopCount,
            instance,
            interfaces,
            adjacencies,
            lsp_entries,
        );

        // Compute the remote neighbors list and each neighbor's advertised
        // flooding algorithm.
        for vertex in cache.spt_hopcount.first_hops() {
            let rnl_system_id = vertex.id.lan_id.system_id;
            let lsdb = instance.state.lsdb.get(level);
            let flood_algo = lsdb
                .iter_for_system_id(lsp_entries, rnl_system_id)
                .map(|lse| &lse.data)
                .filter(|lsp| lsp.rem_lifetime != 0)
                .filter(|lsp| lsp.seqno != 0)
                .find_map(|lsp| lsp.tlvs.flooding_algo())
                .and_then(|stlv| FloodingAlgo::from_u8(stlv.get()))
                .unwrap_or(FloodingAlgo::ZeroPruner);
            cache.remote_nbr_list.insert(rnl_system_id, flood_algo);
        }

        // Store the computed cache for this neighbor.
        *instance
            .state
            .flooding_reduction
            .get_mut(level)
            .manet
            .neighbors
            .entry(adj.system_id)
            .or_default() = cache;
    }
}

pub(crate) fn reflood_list(
    instance: &InstanceUpView<'_>,
    level: LevelNumber,
    tn: &SystemId,
    lsp_id: &LspId,
) -> BTreeSet<SystemId> {
    let Some(cache) = instance
        .state
        .flooding_reduction
        .get(level)
        .manet
        .neighbors
        .get(tn)
    else {
        return BTreeSet::default();
    };
    if cache.remote_nbr_list.is_empty() {
        return BTreeSet::default();
    }

    // Build the Two-Hop List (THL).
    let mut two_hop_list = cache
        .spt_hopcount
        .second_hops()
        // Skip LSP originator.
        .filter(|vertex| vertex.id.lan_id.system_id != lsp_id.system_id)
        // Skip nodes on the shortest path from the TN towards the LSP originator.
        .filter(|vertex| {
            !cache
                .spt_hopcount
                .is_on_path(vertex.id.lan_id.system_id, lsp_id.system_id)
        })
        .map(|vertex| vertex.id.lan_id.system_id)
        .collect::<BTreeSet<_>>();

    // Use the double hashing algorithm.
    let hash =
        flood_reduction_hash(*lsp_id.system_id.as_ref(), lsp_id.fragment);

    // Set N to the H MOD of RNum (N=H MOD RNum)
    let rnum = cache.remote_nbr_list.len();
    let n = hash as usize % rnum;

    // Iterate over the RNL in circular order beginning at index N.
    let mut reflood_list = BTreeSet::default();
    for (rnl, rnl_algo) in
        cache.remote_nbr_list.iter().cycle().skip(n).take(rnum)
    {
        // Stop when the THL is empty.
        if two_hop_list.is_empty() {
            break;
        }

        // If the current RNL entry is the local system, reflood to all
        // remaining THL members that are adjacent to it.
        if *rnl == instance.config.system_id.unwrap() {
            for thl_node in two_hop_list {
                if cache.spt_hopcount.is_on_path(*rnl, thl_node) {
                    reflood_list.insert(thl_node);
                }
            }
            break;
        }

        // Skip RNL members that are not using Modified MANET.
        if *rnl_algo != FloodingAlgo::ModifiedManet {
            continue;
        }

        // Remove from the THL any nodes connected to this RNL member.
        two_hop_list
            .retain(|thl_node| !cache.spt_hopcount.is_on_path(*rnl, *thl_node));
    }

    reflood_list
}

// Returns true if the interface has any adjacency in the reflood list.
pub(crate) fn should_flood(
    iface: &Interface,
    reflood_list: &BTreeSet<SystemId>,
    adjacencies: &Arena<Adjacency>,
) -> bool {
    iface
        .adjacencies(adjacencies)
        .filter(|adj| adj.state == AdjacencyState::Up)
        .any(|adj| reflood_list.contains(&adj.system_id))
}

// ===== helper functions =====

// Unmodified hash algorithm from draft-ietf-lsr-cache-11 section 1.2.4.
fn flood_reduction_hash(systemid: [u8; 6], fragment_nr: u8) -> u32 {
    fn log2(v: u8) -> u8 {
        let r = v.trailing_zeros() as _;
        assert_eq!(v, 1u8 << r);
        r
    }

    // reduce fragment number to ignore lowest bits
    let fragment_downshift = [fragment_nr >> log2(8)];

    // two iterators basically reversing order of hashing values in
    let hashiters: Vec<Box<dyn Iterator<Item = (usize, &u8)>>> = vec![
        Box::new(
            (0..)
                .step_by(2)
                .zip(fragment_downshift.iter().chain(systemid.iter())),
        ),
        Box::new(
            (0..)
                .step_by(5)
                .zip(systemid.iter().rev().chain(fragment_downshift.iter())),
        ),
    ];

    // compute same type of hash over all iterators, fold the hash value on itself
    // and then XOR all the hashes together again
    hashiters
        .into_iter()
        .map(move |iter| {
            iter.fold(0u32, |previous, (offset, value)| {
                (previous << 4) ^ (offset as u32 + (*value as u32))
            })
        })
        .map(move |hash| hash ^ (hash >> 14))
        .fold(0, |previous, hash| previous ^ hash)
}

// ===== unit tests =====

#[cfg(test)]
mod tests {
    use super::*;

    // Tests the hash algorithm against reference values from
    // draft-ietf-lsr-cache-11 section 1.2.4.
    #[test]
    fn test_flood_reduction_hash() {
        let cases = [
            ([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 0x00, 0x0699B13A),
            ([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 0x07, 0x0699B13A),
            ([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 0x08, 0x0799B53B),
            ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05], 0x07, 0x05B99999),
            ([0x01, 0x02, 0x03, 0x04, 0x05, 0x07], 0x08, 0x0699B13A),
            ([0xFF, 0x05, 0x04, 0x03, 0x02, 0x01], 0x00, 0x1165D6C5),
            ([0xFF, 0x05, 0x04, 0x03, 0x02, 0x01], 0xFE, 0x0E65AAE6),
            ([0xFF, 0x05, 0x04, 0x03, 0x02, 0x01], 0xFD, 0x0E65AAE6),
            ([0x1F, 0x48, 0x00, 0x00, 0x00, 0x07], 0x00, 0x0506D336),
            ([0x1F, 0x48, 0x00, 0x00, 0x00, 0x07], 0x0F, 0x0406D737),
            ([0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 0x00, 0x006E8CA8),
            ([0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 0x08, 0x016E88A9),
        ];

        for (systemid, fragment, expected) in cases {
            let result = flood_reduction_hash(systemid, fragment);
            assert_eq!(
                result, expected,
                "Failed for system ID {:?} fragment {}",
                systemid, fragment
            );
        }
    }
}
