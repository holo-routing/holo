//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use pickledb::PickleDb;
use tracing::error;

use crate::northbound::core::Transaction;

const TRANSACTION_KEY_PREFIX: &str = "transaction";

// Records a transaction in the rollback log, then prunes the oldest
// transactions so that at most `max_entries` are kept (zero means unlimited).
pub(crate) fn transaction_record(
    db: &mut PickleDb,
    transaction: &mut Transaction,
    max_entries: u32,
) {
    transaction.id = transaction_next_key(db);
    let key = transaction_key(transaction.id);
    if let Err(error) = db.set(&key, transaction) {
        error!(%error, "failed to record transaction in the rollback log");
    }
    transaction_prune(db, max_entries);
}

// Retrieves a transaction from the rollback log, identified by its ID.
pub(crate) fn transaction_get(
    db: &PickleDb,
    transaction_id: u32,
) -> Option<Transaction> {
    let key = transaction_key(transaction_id);
    db.get(&key)
}

// Retrieves all transactions from the rollback log.
pub(crate) fn transaction_get_all(db: &PickleDb) -> Vec<Transaction> {
    db.iter()
        .filter(|entry| entry.get_key().starts_with(TRANSACTION_KEY_PREFIX))
        .map(|entry| entry.get_value::<Transaction>().unwrap())
        .collect()
}

// Retrieves the next available transaction ID and updates it.
fn transaction_next_key(db: &mut PickleDb) -> u32 {
    let mut next_id = db.get("next_id").unwrap_or(0);
    next_id += 1;
    if let Err(error) = db.set("next_id", &next_id) {
        error!(%error, "failed to update the next transaction ID in the rollback log");
    }
    next_id
}

// Removes the oldest transactions from the rollback log so that at most
// `max_entries` are kept. A `max_entries` of zero disables pruning.
//
// Returns the number of transactions removed.
pub(crate) fn transaction_prune(db: &mut PickleDb, max_entries: u32) -> usize {
    if max_entries == 0 {
        return 0;
    }

    let mut ids = db
        .get_all()
        .iter()
        .filter_map(|key| key.strip_prefix(TRANSACTION_KEY_PREFIX))
        .filter_map(|id| id.parse::<u32>().ok())
        .collect::<Vec<_>>();
    let excess = ids.len().saturating_sub(max_entries as usize);
    ids.sort_unstable();

    let mut pruned = 0;
    for id in &ids[..excess] {
        if let Err(error) = db.rem(&transaction_key(*id)) {
            // If the database can't be written, the remaining removals would
            // fail the same way, so leave them for the next commit.
            error!(%error, %id, "failed to prune transaction from the rollback log");
            break;
        }
        pruned += 1;
    }
    pruned
}

// Returns the database key of the given transaction.
fn transaction_key(transaction_id: u32) -> String {
    format!("{TRANSACTION_KEY_PREFIX}{transaction_id}")
}

// ===== unit tests =====

#[cfg(test)]
mod tests {
    use pickledb::{PickleDbDumpPolicy, SerializationMethod};

    use super::*;

    // In-memory database (never written to disk) with the given transaction
    // IDs plus an unrelated key that must survive pruning.
    fn test_db(ids: &[u32]) -> PickleDb {
        let mut db = PickleDb::new(
            "unused.db",
            PickleDbDumpPolicy::NeverDump,
            SerializationMethod::Bin,
        );
        for id in ids {
            db.set(&transaction_key(*id), id).unwrap();
        }
        db.set("next_id", &ids.iter().max().copied().unwrap_or(0))
            .unwrap();
        db
    }

    fn remaining_ids(db: &PickleDb) -> Vec<u32> {
        let mut ids = db
            .get_all()
            .iter()
            .filter_map(|key| key.strip_prefix(TRANSACTION_KEY_PREFIX))
            .map(|id| id.parse().unwrap())
            .collect::<Vec<u32>>();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn prune_keeps_newest() {
        // Non-contiguous IDs, with 10 sorting before 9 as strings.
        let mut db = test_db(&[1, 2, 5, 9, 10, 11]);
        assert_eq!(transaction_prune(&mut db, 3), 3);
        assert_eq!(remaining_ids(&db), vec![9, 10, 11]);
        assert_eq!(db.get::<u32>("next_id"), Some(11));
    }

    #[test]
    fn prune_under_limit() {
        let mut db = test_db(&[1, 2, 3]);
        assert_eq!(transaction_prune(&mut db, 3), 0);
        assert_eq!(remaining_ids(&db), vec![1, 2, 3]);
    }

    #[test]
    fn prune_unlimited() {
        let mut db = test_db(&[1, 2, 3, 4]);
        assert_eq!(transaction_prune(&mut db, 0), 0);
        assert_eq!(remaining_ids(&db), vec![1, 2, 3, 4]);
    }

    #[test]
    fn prune_write_failure() {
        // Database whose file can no longer be written, as its directory was
        // removed.
        let dir = std::env::temp_dir()
            .join(format!("holod-test-prune-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut db = PickleDb::new(
            dir.join("holo.db"),
            PickleDbDumpPolicy::AutoDump,
            SerializationMethod::Bin,
        );
        for id in 1..=4 {
            db.set(&transaction_key(id), &id).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();

        // No transaction is reported as removed, and none is lost.
        assert_eq!(transaction_prune(&mut db, 2), 0);
        assert_eq!(remaining_ids(&db), vec![1, 2, 3, 4]);
    }
}
