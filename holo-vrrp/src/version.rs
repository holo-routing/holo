//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[derive(PartialOrd, Ord)]
pub enum VrrpVersion {
    V2,
    V3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[derive(PartialOrd, Ord)]
pub enum IpVersion {
    V4,
    V6,
}
