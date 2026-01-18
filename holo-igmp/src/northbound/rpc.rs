//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps};

use crate::instance::Instance;
use crate::northbound::yang_gen;

impl Provider for Instance {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}
