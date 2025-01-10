//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![feature(let_chains)]

pub mod debug;
pub mod error;
pub mod events;
pub mod instance;
pub mod interface;
pub mod neighbor;
pub mod network;
pub mod northbound;
pub mod output;
pub mod packet;
pub mod ripng;
pub mod ripv2;
pub mod route;
pub mod southbound;
pub mod tasks;
pub mod version;
