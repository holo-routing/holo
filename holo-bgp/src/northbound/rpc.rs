//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};

use crate::instance::Instance;
use crate::northbound::yang_gen::{self, bgp};

impl Provider for Instance {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClearType {
    Admin,
    Hard,
    Soft,
    SoftInbound,
}

// ===== YANG impls =====

impl YangRpc<Instance> for bgp::neighbors::clear::Clear {
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((mut instance, neighbors)) = instance.as_up() else {
            return Ok(());
        };

        let clear_type = if self.input.hard.is_some() {
            ClearType::Hard
        } else if self.input.soft.is_some() {
            ClearType::Soft
        } else if self.input.soft_inbound.is_some() {
            ClearType::SoftInbound
        } else {
            ClearType::Admin
        };

        // Clear peers.
        match &self.input.remote_addr {
            Some(remote_addr) => {
                if let Some(nbr) = neighbors.get_mut(remote_addr) {
                    nbr.clear_session(&mut instance, clear_type);
                }
            }
            None => {
                for nbr in neighbors.values_mut() {
                    nbr.clear_session(&mut instance, clear_type);
                }
            }
        }

        Ok(())
    }
}
