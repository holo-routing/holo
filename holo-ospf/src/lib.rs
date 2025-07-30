//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![allow(type_alias_bounds)]

pub mod area;
pub mod bier;
pub mod collections;
pub mod debug;
pub mod error;
pub mod events;
pub mod flood;
pub mod gr;
pub mod ibus;
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
pub mod spf;
pub mod sr;
pub mod tasks;
pub mod version;
