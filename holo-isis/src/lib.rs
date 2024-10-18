//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![feature(let_chains)]

pub mod adjacency;
pub mod collections;
pub mod debug;
pub mod error;
pub mod events;
pub mod instance;
pub mod interface;
pub mod lsdb;
pub mod network;
pub mod northbound;
pub mod packet;
pub mod southbound;
pub mod spf;
pub mod tasks;
