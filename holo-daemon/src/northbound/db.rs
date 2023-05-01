//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::path::Path;

use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
use tracing::error;

use crate::northbound::core::Transaction;

// Loads a rollback log from a file, or initialize a new rollback log if one
// doesn't exist.
pub(crate) fn init<P: AsRef<Path>>(
    path: P,
) -> Result<PickleDb, pickledb::error::Error> {
    let dump_policy = PickleDbDumpPolicy::AutoDump;
    let serialization_method = SerializationMethod::Bin;
    match path.as_ref().exists() {
        true => PickleDb::load(path, dump_policy, serialization_method),
        false => Ok(PickleDb::new(path, dump_policy, serialization_method)),
    }
}

// Records a transaction in the rollback log.
pub(crate) fn transaction_record(
    db: &mut PickleDb,
    transaction: &mut Transaction,
) {
    transaction.id = transaction_next_key(db);
    let key = format!("transaction{}", transaction.id);
    if let Err(error) = db.set(&key, transaction) {
        error!(%error, "failed to record transaction in the rollback log");
    }
}

// Retrieves a transaction from the rollback log, identified by its ID.
pub(crate) fn transaction_get(
    db: &PickleDb,
    transaction_id: u32,
) -> Option<Transaction> {
    let key = format!("transaction{}", transaction_id);
    db.get(&key)
}

// Retrieves all transactions from the rollback log.
pub(crate) fn transaction_get_all(db: &PickleDb) -> Vec<Transaction> {
    db.iter()
        .filter(|entry| entry.get_key().starts_with("transaction"))
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
