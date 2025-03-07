//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]
#![feature(extract_if, if_let_guard, let_chains)]

pub mod af;
pub mod debug;
pub mod error;
pub mod events;
pub mod instance;
pub mod neighbor;
pub mod network;
pub mod northbound;
pub mod packet;
pub mod policy;
pub mod rib;
pub mod southbound;
pub mod tasks;
