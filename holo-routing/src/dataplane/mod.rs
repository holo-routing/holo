//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use ipnetwork::IpNetwork;

use crate::interface::Interfaces;
use crate::rib::Route;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod null;

// Dataplane backend selected for this platform.
#[cfg(target_os = "linux")]
pub type Backend = linux::LinuxDataplane;
#[cfg(not(target_os = "linux"))]
pub type Backend = null::NullDataplane;

// Operations every dataplane backend provides to program the forwarding
// state.
//
// Programming operations are asynchronous: they may return before the
// forwarding state is updated, and a failure is logged by the backend rather
// than reported to the caller.
pub(crate) trait Dataplane: Sized {
    // Initialize the dataplane.
    fn init() -> Self;

    // Install an IP route, replacing any existing route for the same prefix.
    fn ip_route_install(
        &self,
        prefix: &IpNetwork,
        route: &Route,
        interfaces: &Interfaces,
    );

    // Uninstall the IP route installed by the given protocol.
    fn ip_route_uninstall(&self, prefix: &IpNetwork, protocol: Protocol);

    // Install an MPLS route, replacing any existing route for the same
    // local label.
    fn mpls_route_install(
        &self,
        local_label: Label,
        route: &Route,
        interfaces: &Interfaces,
    );

    // Uninstall the MPLS route installed by the given protocol.
    fn mpls_route_uninstall(&self, local_label: Label, protocol: Protocol);

    // Purge stale routes that may have been left behind by a previous Holo
    // instance.
    async fn purge_stale_routes(&self);

    // Wait until all enqueued requests have been executed.
    fn flush(self);
}
