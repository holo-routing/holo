//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

#![forbid(unsafe_code)]
#![feature(ip, lazy_cell)]
#![warn(rust_2018_idioms)]
#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]

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
