//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! IS-IS Aggregated SNP Hash (ASH) support (draft-prz-lsr-ash-packets).
//!
//! ASH packets compress traditional SNP exchanges into a dynamic Merkle
//! tree-like structure. Each fragment is hashed into a 64-bit value, and
//! the fragment hashes of all systems in a range are XOR-combined into a
//! Node Range Hash. Complete ASH (CASH) PDUs replace periodic CSNPs, while
//! Partial ASH (PASH) PDUs are exchanged to refine mismatched ranges into
//! progressively more specific ones. Once a mismatch is narrowed down to a
//! single system ID, the fragments of that system are flooded directly.
//!
//! Since the XOR combination is self-inverse, hashes for arbitrary ranges
//! are cheap to compute on the fly, and no agreement on range boundaries
//! is needed between neighbors.

use crate::collections::{Arena, Lsdb};
use crate::instance::InstanceUpView;
use crate::interface::{Interface, InterfaceType};
use crate::lsdb::LspEntry;
use crate::packet::pdu::{Ash, AshEntry, Pdu};
use crate::packet::{LanId, LevelNumber, LspId, SystemId};

// Maximum number of CASH PDUs used to describe the full LSDB.
//
// This is a local policy value balancing compression against collision
// probability and vulnerability to packet drops (see Sections 9.2 to 9.4
// of the draft).
const CASH_TARGET_PDUS: usize = 4;

// Mismatched ranges containing up to this number of local systems are split
// directly into single-system ranges (local policy).
const SPLIT_SINGLE_THRESHOLD: usize = 16;

// Number of subranges larger mismatched ranges are split into (local policy).
const SPLIT_FACTOR: usize = 16;

// ===== global functions =====

// Sends CASH PDU(s) describing the entire LSDB.
//
// This is used in place of periodic CSNPs when ASH support was negotiated
// on the interface.
pub(crate) fn send_cash(
    instance: &InstanceUpView<'_>,
    lsp_entries: &Arena<LspEntry>,
    iface: &mut Interface,
    level: LevelNumber,
) {
    let system_id = instance.config.system_id.unwrap();
    let source = LanId::from((system_id, iface.state.circuit_id));

    // Compute the node hashes for the entire LSDB.
    let lsdb = instance.state.lsdb.get(level);
    let nodes = node_hashes_range(
        lsdb,
        lsp_entries,
        SystemId::from([0x00; 6]),
        SystemId::from([0xff; 6]),
    );
    if nodes.is_empty() {
        return;
    }

    // Group the nodes into as many single-system ranges as possible, limited
    // by the maximum number of CASH PDUs used to describe the full LSDB.
    let max_entries = Ash::max_entries(
        instance.config.lsp_mtu as usize - Ash::CASH_HEADER_LEN as usize,
    );
    let nodes_per_range =
        nodes.len().div_ceil(CASH_TARGET_PDUS * max_entries).max(1);
    let entries = nodes
        .chunks(nodes_per_range)
        .map(|chunk| AshEntry {
            start: chunk.first().unwrap().0,
            end: chunk.last().unwrap().0,
            hash: finalize_hash(
                chunk
                    .iter()
                    .fold(0, |hash, (_, node_hash)| hash ^ node_hash),
            ),
        })
        .collect::<Vec<_>>();

    // Send as many CASH PDUs as necessary.
    //
    // The first CASH starts at 0000.0000.0000 and the last one ends at
    // ffff.ffff.ffff so that missing nodes are detectable. The header ranges
    // of consecutive CASHes are contiguous for the same reason.
    let mut start = SystemId::from([0x00; 6]);
    let mut chunks = entries.chunks(max_entries).peekable();
    while let Some(chunk) = chunks.next() {
        let end = if chunks.peek().is_none() {
            SystemId::from([0xff; 6])
        } else {
            chunk.last().unwrap().end
        };
        let pdu = Pdu::Ash(Ash::new(
            level,
            source,
            Some((start, end)),
            chunk.to_vec(),
        ));
        iface.enqueue_pdu(pdu, level);
        start = system_id_incr(end);
    }
}

// Sends PASH PDU(s) containing the provided Node Range Hash Entries.
pub(crate) fn send_pash(
    instance: &InstanceUpView<'_>,
    iface: &mut Interface,
    level: LevelNumber,
    entries: Vec<AshEntry>,
) {
    let system_id = instance.config.system_id.unwrap();
    let source = LanId::from((system_id, iface.state.circuit_id));

    // Send as many PASH PDUs as necessary.
    let max_entries = Ash::max_entries(
        instance.config.lsp_mtu as usize - Ash::PASH_HEADER_LEN as usize,
    );
    for chunk in entries.chunks(max_entries) {
        let pdu = Pdu::Ash(Ash::new(level, source, None, chunk.to_vec()));
        iface.enqueue_pdu(pdu, level);
    }
}

// Computes the response to a received Node Range Hash Entry.
//
// Returns the PASH entries (if any) that should be sent back to the
// originator of the received entry.
pub(crate) fn process_entry(
    instance: &InstanceUpView<'_>,
    lsp_entries: &Arena<LspEntry>,
    iface: &mut Interface,
    level: LevelNumber,
    entry: &AshEntry,
) -> Vec<AshEntry> {
    let lsdb = instance.state.lsdb.get(level);

    // Compute the local hash for the received range.
    let nodes = node_hashes_range(lsdb, lsp_entries, entry.start, entry.end);
    let local_hash = if nodes.is_empty() {
        0
    } else {
        finalize_hash(
            nodes
                .iter()
                .fold(0, |hash, (_, node_hash)| hash ^ node_hash),
        )
    };

    // If the hashes match, both databases contain the exact same fragments
    // for the range, so pending retransmissions in the range are acknowledged.
    if entry.hash == local_hash {
        if entry.hash != 0 {
            srm_list_del_range(iface, level, entry.start, entry.end);
        }
        return vec![];
    }

    // A zero hash indicates that the range is not covered by ASH compression
    // and must be resolved through SNP exchanges or flooding. Flood all local
    // fragments in the range.
    if entry.hash == 0 {
        flood_range(
            instance,
            lsp_entries,
            iface,
            level,
            entry.start,
            entry.end,
        );
        return vec![];
    }

    // If the mismatched hash has no matching fragments in the local database,
    // send back a PASH with a zero hash to request the remote node to either
    // refine the range or use normal IS-IS procedures to synchronize the
    // database.
    if local_hash == 0 {
        return vec![AshEntry {
            start: entry.start,
            end: entry.end,
            hash: 0,
        }];
    }

    // If the mismatched hash covers a single system ID (including its
    // pseudonodes), flood all fragments of that system directly. The local
    // hash is also sent back so the peer floods its own fragments of the
    // system, ensuring both nodes end up with the full set of fragments.
    if entry.start == entry.end {
        flood_range(
            instance,
            lsp_entries,
            iface,
            level,
            entry.start,
            entry.end,
        );
        return vec![AshEntry {
            start: entry.start,
            end: entry.end,
            hash: local_hash,
        }];
    }

    // Split the mismatched range into more specific subranges and send back
    // their hashes.
    let nodes_per_range = if nodes.len() <= SPLIT_SINGLE_THRESHOLD {
        1
    } else {
        nodes.len().div_ceil(SPLIT_FACTOR)
    };
    nodes
        .chunks(nodes_per_range)
        .map(|chunk| AshEntry {
            start: chunk.first().unwrap().0,
            end: chunk.last().unwrap().0,
            hash: finalize_hash(
                chunk
                    .iter()
                    .fold(0, |hash, (_, node_hash)| hash ^ node_hash),
            ),
        })
        .collect()
}

// Floods all LSPs whose system IDs fall within the CASH header range but are
// not covered by any of the received Node Range Hash Entries.
//
// Uncovered node IDs must be treated as missing from the peer's database,
// the same way LSPs absent from a CSNP are.
pub(crate) fn flood_uncovered_ranges(
    instance: &InstanceUpView<'_>,
    lsp_entries: &Arena<LspEntry>,
    iface: &mut Interface,
    level: LevelNumber,
    ash: &Ash,
) {
    let Some((start, end)) = ash.summary else {
        return;
    };
    if start > end {
        return;
    }

    let lsdb = instance.state.lsdb.get(level);
    for lsp in lsdb
        .range(lsp_entries, lspid_range(start, end))
        .map(|lse| &lse.data)
        // Exclude LSPs with zero Remaining Lifetime.
        .filter(|lsp| lsp.rem_lifetime != 0)
        // Exclude LSPs with zero sequence number.
        .filter(|lsp| lsp.seqno != 0)
        // The entries are sorted and non-overlapping, so a binary search is
        // used to check whether the LSP's system ID is covered.
        .filter(|lsp| {
            let system_id = lsp.lsp_id.system_id;
            let idx =
                ash.entries.partition_point(|entry| entry.end < system_id);
            !ash.entries
                .get(idx)
                .is_some_and(|entry| entry.start <= system_id)
        })
    {
        iface.srm_list_add(instance, level, lsp, false);
    }
}

// ===== helper functions =====

// Returns the range of LSP IDs corresponding to the given system ID range.
fn lspid_range(
    start: SystemId,
    end: SystemId,
) -> std::ops::RangeInclusive<LspId> {
    LspId::from((start, 0, 0))..=LspId::from((end, 255, 255))
}

// Replaces a zero hash with the constant 1.
//
// A zero hash would otherwise assume the semantics of "no fragments present
// for those nodes".
const fn finalize_hash(hash: u64) -> u64 {
    if hash == 0 { 1 } else { hash }
}

// Computes the node hashes for all systems in the given range.
//
// Only systems with at least one eligible fragment are returned, ordered by
// system ID. The returned hashes are raw XOR combinations of the fragment
// hashes - zero replacement is left to the callers so that hashes of wider
// ranges can be derived by XOR.
//
// Fragments in purge state (zero Remaining Lifetime) or with a zero sequence
// number are not included in the hash computation, consistent with their
// treatment in CSNP exchanges.
fn node_hashes_range(
    lsdb: &Lsdb,
    lsp_entries: &Arena<LspEntry>,
    start: SystemId,
    end: SystemId,
) -> Vec<(SystemId, u64)> {
    let mut nodes: Vec<(SystemId, u64)> = vec![];
    for lsp in lsdb
        .range(lsp_entries, lspid_range(start, end))
        .map(|lse| &lse.data)
        .filter(|lsp| lsp.rem_lifetime != 0)
        .filter(|lsp| lsp.seqno != 0)
    {
        let fragment_hash = lsp.ash_fragment_hash();
        match nodes.last_mut() {
            Some((system_id, node_hash))
                if *system_id == lsp.lsp_id.system_id =>
            {
                *node_hash ^= fragment_hash;
            }
            _ => nodes.push((lsp.lsp_id.system_id, fragment_hash)),
        }
    }
    nodes
}

// Floods all eligible LSPs whose system IDs fall within the given range.
fn flood_range(
    instance: &InstanceUpView<'_>,
    lsp_entries: &Arena<LspEntry>,
    iface: &mut Interface,
    level: LevelNumber,
    start: SystemId,
    end: SystemId,
) {
    let lsdb = instance.state.lsdb.get(level);
    for lsp in lsdb
        .range(lsp_entries, lspid_range(start, end))
        .map(|lse| &lse.data)
        // Exclude LSPs with zero Remaining Lifetime.
        .filter(|lsp| lsp.rem_lifetime != 0)
        // Exclude LSPs with zero sequence number.
        .filter(|lsp| lsp.seqno != 0)
    {
        iface.srm_list_add(instance, level, lsp, false);
    }
}

// Removes all LSPs whose system IDs fall within the given range from the
// interface's SRM list.
fn srm_list_del_range(
    iface: &mut Interface,
    level: LevelNumber,
    start: SystemId,
    end: SystemId,
) {
    // LSPs are only kept in the SRM list awaiting acknowledgment on
    // point-to-point interfaces.
    if iface.config.interface_type != InterfaceType::PointToPoint {
        return;
    }

    let srm_list = iface.state.srm_list.get_mut(level);
    let lsp_ids = srm_list
        .range(lspid_range(start, end))
        .map(|(lsp_id, _)| *lsp_id)
        .collect::<Vec<_>>();
    for lsp_id in lsp_ids {
        srm_list.remove(&lsp_id);
    }
}

// Returns the given system ID incremented by one, saturating at the maximum
// value.
fn system_id_incr(system_id: SystemId) -> SystemId {
    let mut bytes: [u8; 6] = *system_id.as_ref();
    for byte in bytes.iter_mut().rev() {
        let (value, overflow) = byte.overflowing_add(1);
        *byte = value;
        if !overflow {
            return SystemId::from(bytes);
        }
    }
    SystemId::from([0xff; 6])
}
