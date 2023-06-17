//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

#![warn(rust_2018_idioms)]
#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![allow(clippy::single_match, clippy::too_many_arguments)]
#![allow(type_alias_bounds)]
#![feature(btree_extract_if, hash_extract_if, ip, let_chains, lazy_cell)]

pub mod area;
pub mod collections;
pub mod debug;
pub mod error;
pub mod events;
pub mod flood;
pub mod instance;
pub mod interface;
pub mod lsdb;
pub mod neighbor;
pub mod network;
pub mod northbound;
pub mod ospfv2;
pub mod ospfv3;
pub mod output;
pub mod packet;
pub mod route;
pub mod southbound;
pub mod spf;
pub mod sr;
pub mod tasks;
pub mod version;
