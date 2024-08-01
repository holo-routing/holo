//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_northbound::rpc::Provider;
use holo_northbound::yang::control_plane_protocol;
use holo_northbound::{CallbackKey, NbDaemonSender};
use holo_utils::protocol::Protocol;
use holo_utils::yang::DataNodeRefExt;
use yang3::data::DataNodeRef;

use crate::Master;

impl Provider for Master {
    fn nested_callbacks() -> Option<Vec<CallbackKey>> {
        let keys: Vec<Vec<CallbackKey>> = vec![
            #[cfg(feature = "bgp")]
            holo_bgp::northbound::rpc::CALLBACKS.keys(),
            #[cfg(feature = "ldp")]
            holo_ldp::northbound::rpc::CALLBACKS.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::rpc::CALLBACKS_OSPFV2.keys(),
            #[cfg(feature = "ospf")]
            holo_ospf::northbound::rpc::CALLBACKS_OSPFV3.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::rpc::CALLBACKS_RIPV2.keys(),
            #[cfg(feature = "rip")]
            holo_rip::northbound::rpc::CALLBACKS_RIPNG.keys(),
        ];

        Some(keys.concat())
    }

    fn relay_rpc(
        &self,
        rpc: DataNodeRef<'_>,
    ) -> Result<Option<Vec<NbDaemonSender>>, String> {
        let (protocol, name) = find_instance(rpc)?;

        let mut child_tasks = vec![];
        for (instance_id, sender) in &self.instances {
            // Filter by protocol type.
            if instance_id.protocol != protocol {
                continue;
            }

            // Filter by protocol name.
            if let Some(name) = &name {
                if instance_id.name != *name {
                    continue;
                }
            }

            child_tasks.push(sender.clone());
        }

        Ok(Some(child_tasks))
    }
}

// ===== helper functions =====

// Using top-level RPCs in the IETF IGP modules was a mistake, since there's no
// easy way to identify the protocol type and name. YANG actions would greatly
// simplify this.
fn find_instance(
    rpc: DataNodeRef<'_>,
) -> Result<(Protocol, Option<String>), String> {
    let (protocol, name) = match rpc.schema().module().name() {
        "ietf-bgp" => {
            let protocol = Protocol::BGP;
            let name = rpc.get_string_relative(
                control_plane_protocol::name::PATH.as_ref(),
            );
            (protocol, name)
        }
        "ietf-mpls-ldp" => {
            let protocol = Protocol::LDP;
            let name = match rpc.path().as_ref() {
                "/ietf-mpls-ldp:mpls-ldp-clear-peer"
                | "/ietf-mpls-ldp:mpls-ldp-clear-peer-statistics" => {
                    rpc.get_string_relative("./protocol-name")
                }
                "/ietf-mpls-ldp:mpls-ldp-clear-hello-adjacency" => {
                    rpc.get_string_relative("./hello-adjacency/protocol-name")
                }
                _ => None,
            };
            (protocol, name)
        }
        "ietf-ospf" => {
            // TODO
            let protocol = Protocol::OSPFV2;
            let name = rpc.get_string_relative("./routing-protocol-name");
            (protocol, name)
        }
        "ietf-rip" => {
            // TODO
            let protocol = Protocol::RIPV2;
            let name = rpc.get_string_relative("./rip-instance");
            (protocol, name)
        }
        _ => return Err("unknown instance protocol".to_string()),
    };

    Ok((protocol, name))
}
