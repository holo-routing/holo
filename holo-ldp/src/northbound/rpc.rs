//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::{Provider, YangOps, YangRpc};

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
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((mut instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        // Clear peers.
        for nbr_idx in instance.state.neighbors.indexes().collect::<Vec<_>>() {
            let nbr = &mut instance.state.neighbors[nbr_idx];

            // Skip uninitialized neighbors.
            if nbr.state == neighbor::fsm::State::NonExistent {
                continue;
            }

            // Filter by LSR-ID.
            if let Some(lsr_id) = self.input.lsr_id
                && nbr.lsr_id != lsr_id
            {
                continue;
            }
            if let Some(lspace_id) = self.input.label_space_id
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
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((mut instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        for adj_idx in instance.state.ipv4.adjacencies.indexes().collect::<Vec<_>>() {
            let adj = &instance.state.ipv4.adjacencies[adj_idx];

            // Filter by source.
            if let Some(input) = &self.input.hello_adjacency {
                // Filter by adjacency type.
                if input.targeted.is_some() && adj.source.ifname.is_some() {
                    continue;
                }
                if input.link.is_some() && adj.source.ifname.is_none() {
                    continue;
                }

                // Filter targeted adjacency by target address.
                if let Some(targeted) = &input.targeted
                    && let Some(target_address) = targeted.target_address
                    && adj.source.addr != target_address
                {
                    continue;
                }

                if let Some(link) = &input.link {
                    // Filter link adjacency by next-hop interface.
                    if let Some(next_hop_interface) = link.next_hop_interface.as_ref()
                        && adj.source.ifname.as_ref() != Some(next_hop_interface)
                    {
                        continue;
                    }

                    // Filter link adjacency by next-hop address.
                    if let Some(next_hop_address) = link.next_hop_address
                        && adj.source.addr != next_hop_address
                    {
                        continue;
                    }
                }
            }

            // Delete adjacency.
            discovery::adjacency_delete(&mut instance, adj_idx, StatusCode::Shutdown);
        }

        Ok(())
    }
}

impl YangRpc<Instance> for yang::mpls_ldp_clear_peer_statistics::MplsLdpClearPeerStatistics {
    fn invoke(&mut self, instance: &mut Instance) -> Result<(), String> {
        let Some((instance, _, _)) = instance.as_up() else {
            return Ok(());
        };

        // Clear peers.
        for nbr in instance.state.neighbors.iter_mut() {
            // Filter by LSR-ID.
            if let Some(lsr_id) = self.input.lsr_id
                && nbr.lsr_id != lsr_id
            {
                continue;
            }
            if let Some(lspace_id) = self.input.label_space_id
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
