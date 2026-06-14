//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::state::{Provider, YangOps};

use crate::Master;
use crate::northbound::yang_gen;

impl Provider for Master {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        "/ietf-routing-policy:routing-policy".to_owned()
    }
}
