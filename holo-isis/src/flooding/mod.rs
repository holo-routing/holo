//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

pub mod manet;

#[derive(Debug, Default)]
pub struct FloodingReduction {
    pub manet: manet::FloodingReduction,
}
