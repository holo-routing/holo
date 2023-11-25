//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![feature(ip, lazy_cell)]
#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]

pub mod collections;
pub mod debug;
pub mod discovery;
pub mod error;
pub mod events;
pub mod fec;
pub mod instance;
pub mod interface;
pub mod neighbor;
pub mod network;
pub mod northbound;
pub mod packet;
pub mod southbound;
pub mod tasks;
