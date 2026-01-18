//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};
use holo_utils::yang::DataNodeRefExt;
use yang4::data::{Data, DataTree};

use crate::discovery;
use crate::instance::Instance;
use crate::neighbor::{self, Neighbor};
use crate::northbound::{yang_gen, yang_gen as yang};
use crate::packet::messages::notification::StatusCode;

impl Provider for Instance {
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_RPC;
}

// ===== YANG impls =====

impl YangRpc<Instance> for yang::mpls_ldp_clear_peer::MplsLdpClearPeer {
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((mut instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let (lsr_id, lspace_id) = (rpc.get_ipv4_relative("./lsr-id"), rpc.get_u16_relative("./label-space-id"));

        // Clear peers.
        for nbr_idx in instance.state.neighbors.indexes().collect::<Vec<_>>() {
            let nbr = &mut instance.state.neighbors[nbr_idx];

            // Skip uninitialized neighbors.
            if nbr.state == neighbor::fsm::State::NonExistent {
                continue;
            }

            // Filter by LSR-ID.
            if let Some(lsr_id) = lsr_id
                && nbr.lsr_id != lsr_id
            {
                continue;
            }
            if let Some(lspace_id) = lspace_id
                && lspace_id != 0
            {
                continue;
            }

            // Send Shutdown notification.
            nbr.send_shutdown(&instance.state.msg_id, None);
            Neighbor::fsm(&mut instance, nbr_idx, neighbor::fsm::Event::ErrorSent);
        }

        Ok(())
    }
}

impl YangRpc<Instance> for yang::mpls_ldp_clear_hello_adjacency::MplsLdpClearHelloAdjacency {
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((mut instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let (nexthop_ifname, nexthop_addr, tnbr_addr) = (
            rpc.get_string_relative("./hello-adjacency/link/next-hop-interface"),
            rpc.get_ip_relative("./hello-adjacency/link/next-hop-address"),
            rpc.get_ip_relative("./hello-adjacency/targeted/target-address"),
        );

        // Clear adjacencies.
        for adj_idx in instance.state.ipv4.adjacencies.indexes().collect::<Vec<_>>() {
            let adjacencies = &mut instance.state.ipv4.adjacencies;
            let adj = &adjacencies[adj_idx];

            // Filter by source.
            if let Some(ifname) = &adj.source.ifname {
                if let Some(nexthop_ifname) = &nexthop_ifname
                    && *ifname != *nexthop_ifname
                {
                    continue;
                }
                if let Some(nexthop_addr) = &nexthop_addr
                    && adj.source.addr != *nexthop_addr
                {
                    continue;
                }
            } else if let Some(tnbr_addr) = &tnbr_addr
                && adj.source.addr != *tnbr_addr
            {
                continue;
            }

            // Delete adjacency.
            discovery::adjacency_delete(&mut instance, adj_idx, StatusCode::Shutdown);
        }

        Ok(())
    }
}

impl YangRpc<Instance> for yang::mpls_ldp_clear_peer_statistics::MplsLdpClearPeerStatistics {
    fn invoke(instance: &mut Instance, data: &mut DataTree<'static>, rpc_path: &str) -> Result<(), String> {
        let Some((instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        // Parse input parameters.
        let rpc = data.find_path(rpc_path).unwrap();
        let (lsr_id, lspace_id) = (rpc.get_ipv4_relative("./lsr-id"), rpc.get_u16_relative("./label-space-id"));

        // Clear peers.
        for nbr in instance.state.neighbors.iter_mut() {
            // Filter by LSR-ID.
            if let Some(lsr_id) = lsr_id
                && nbr.lsr_id != lsr_id
            {
                continue;
            }
            if let Some(lspace_id) = lspace_id
                && lspace_id != 0
            {
                continue;
            }

            // Clear neighbor statistics.
            nbr.statistics = Default::default();
        }

        Ok(())
    }
}
