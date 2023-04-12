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
#![feature(let_chains, lazy_cell)]
#![allow(clippy::too_many_arguments)]

pub mod debug;
pub mod error;
pub mod events;
pub mod master;
pub mod network;
pub mod northbound;
pub mod packet;
pub mod session;
pub mod southbound;
pub mod tasks;
