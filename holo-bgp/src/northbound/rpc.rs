//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_northbound::rpc::{Callbacks, CallbacksBuilder, Provider};
use holo_northbound::yang::control_plane_protocol::bgp;
use holo_utils::yang::DataNodeRefExt;
use yang3::data::Data;

use crate::instance::Instance;

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClearType {
    Admin,
    Hard,
    Soft,
    SoftInbound,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(bgp::neighbors::clear::PATH)
        .rpc(|instance, args| {
            let rpc = args.data.find_path(args.rpc_path).unwrap();

            // Parse input parameters.
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
            let Some((mut instance, neighbors)) = instance.as_up() else {
                return Ok(());
            };
            if let Some(remote_addr) = remote_addr {
                let nbr = neighbors.get_mut(&remote_addr).unwrap();
                nbr.clear_session(&mut instance, clear_type);
            } else {
                for nbr in neighbors.values_mut() {
                    nbr.clear_session(&mut instance, clear_type);
                }
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }
}
