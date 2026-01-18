//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps};

use crate::interface::Interface;
use crate::northbound::yang_gen;

impl Provider for Interface {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}
