//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]

use std::sync::{Arc, Mutex};

use pickledb::PickleDb;

pub mod bfd;
pub mod bgp;
pub mod bier;
pub mod bytes;
pub mod capabilities;
pub mod crypto;
pub mod ibus;
pub mod ip;
pub mod keychain;
pub mod mac_addr;
pub mod mpls;
pub mod num;
pub mod option;
pub mod policy;
pub mod protocol;
pub mod socket;
pub mod southbound;
pub mod sr;
pub mod task;
pub mod yang;

pub type Database = Arc<Mutex<PickleDb>>;
pub type DatabaseError = pickledb::error::Error;
