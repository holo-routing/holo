//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use ipnetwork::IpNetwork;

use crate::dataplane::Dataplane;
use crate::interface::Interfaces;
use crate::rib::Route;

// Handle used to program the null dataplane.
//
// There's no dataplane to program, so all operations are no-ops.
#[derive(Debug)]
pub struct NullDataplane;

// ===== impl NullDataplane =====

impl Dataplane for NullDataplane {
    fn init() -> NullDataplane {
        NullDataplane
    }

    fn ip_route_install(
        &self,
        _prefix: &IpNetwork,
        _route: &Route,
        _interfaces: &Interfaces,
    ) {
    }

    fn ip_route_uninstall(&self, _prefix: &IpNetwork, _protocol: Protocol) {}

    fn mpls_route_install(
        &self,
        _local_label: Label,
        _route: &Route,
        _interfaces: &Interfaces,
    ) {
    }

    fn mpls_route_uninstall(&self, _local_label: Label, _protocol: Protocol) {}

    async fn purge_stale_routes(&self) {}

    fn flush(self) {}
}
