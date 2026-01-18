//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};
use holo_utils::yang::DataNodeRefExt;
use yang4::data::{Data, DataTree};

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
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((mut instance, neighbors)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let remote_addr = rpc.get_ip_relative("./remote-addr");
        let clear_type = if rpc.exists("./hard") {
            ClearType::Hard
        } else if rpc.exists("./soft") {
            ClearType::Soft
        } else if rpc.exists("./soft-inbound") {
            ClearType::SoftInbound
        } else {
            ClearType::Admin
        };

        // Clear peers.
        match remote_addr {
            Some(remote_addr) => {
                if let Some(nbr) = neighbors.get_mut(&remote_addr) {
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
