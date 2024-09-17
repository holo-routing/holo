//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use capctl::caps::CapState;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::Nexthop;
use ipnetwork::IpNetwork;
use netlink_packet_route::route::RouteProtocol;
use rtnetlink::{new_connection, Handle, RouteAddRequest};
use tracing::error;

use crate::rib::Route;

fn netlink_protocol(protocol: Protocol) -> RouteProtocol {
    match protocol {
        Protocol::BGP => RouteProtocol::Bgp,
        Protocol::OSPFV2 | Protocol::OSPFV3 => RouteProtocol::Ospf,
        Protocol::RIPV2 | Protocol::RIPNG => RouteProtocol::Rip,
        Protocol::STATIC => RouteProtocol::Static,
        _ => RouteProtocol::Unspec,
    }
}

pub(crate) async fn ip_route_install(
    handle: &Handle,
    prefix: &IpNetwork,
    route: &Route,
) {
    // Create netlink request.
    let mut request = handle.route().add();

    // Set route protocol.
    let protocol = netlink_protocol(route.protocol);
    request = request.protocol(protocol);

    match prefix {
        IpNetwork::V4(prefix) => {
            // Set destination prefix.
            let mut request = request
                .v4()
                .replace()
                .destination_prefix(prefix.ip(), prefix.prefix());

            // Add nexthops.
            request = add_nexthops_ipv4(request, route.nexthops.iter());

            // Execute request.
            if let Err(error) = request.execute().await {
                error!(%prefix, %error, "failed to install route");
            }
        }
        IpNetwork::V6(prefix) => {
            // Set destination prefix.
            let mut request = request
                .v6()
                .replace()
                .destination_prefix(prefix.ip(), prefix.prefix());

            // Add nexthops.
            request = add_nexthops_ipv6(request, route.nexthops.iter());

            // Execute request.
            if let Err(error) = request.execute().await {
                error!(%prefix, %error, "failed to install route");
            }
        }
    }
}

fn add_nexthops_ipv4<'a>(
    mut request: RouteAddRequest<Ipv4Addr>,
    nexthops: impl Iterator<Item = &'a Nexthop>,
) -> RouteAddRequest<Ipv4Addr> {
    for nexthop in nexthops {
        request = match nexthop {
            Nexthop::Address { addr, ifindex, .. } => {
                if let IpAddr::V4(addr) = addr {
                    request.gateway(*addr).output_interface(*ifindex)
                } else {
                    request
                }
            }
            Nexthop::Interface { ifindex } => {
                request.output_interface(*ifindex)
            }
            Nexthop::Special(_) => {
                // TODO: not supported by the `rtnetlink` crate yet.
                request
            }
            Nexthop::Recursive { resolved, .. } => {
                add_nexthops_ipv4(request, resolved.iter())
            }
        };
    }

    request
}

fn add_nexthops_ipv6<'a>(
    mut request: RouteAddRequest<Ipv6Addr>,
    nexthops: impl Iterator<Item = &'a Nexthop>,
) -> RouteAddRequest<Ipv6Addr> {
    for nexthop in nexthops {
        request = match nexthop {
            Nexthop::Address { addr, ifindex, .. } => {
                if let IpAddr::V6(addr) = addr {
                    request.gateway(*addr).output_interface(*ifindex)
                } else {
                    request
                }
            }
            Nexthop::Interface { ifindex } => {
                request.output_interface(*ifindex)
            }
            Nexthop::Special(_) => {
                // TODO: not supported by the `rtnetlink` crate yet.
                request
            }
            Nexthop::Recursive { resolved, .. } => {
                add_nexthops_ipv6(request, resolved.iter())
            }
        };
    }

    request
}

pub(crate) async fn ip_route_uninstall(
    handle: &Handle,
    prefix: &IpNetwork,
    protocol: Protocol,
) {
    // Create netlink request.
    let mut request = handle.route().add();

    // Set route protocol.
    let protocol = netlink_protocol(protocol);
    request = request.protocol(protocol);

    match prefix {
        IpNetwork::V4(prefix) => {
            // Set destination prefix.
            let mut request = request
                .v4()
                .destination_prefix(prefix.ip(), prefix.prefix());

            // Execute request.
            let request = handle.route().del(request.message_mut().clone());
            if let Err(error) = request.execute().await {
                error!(%prefix, %error, "failed to uninstall route");
            }
        }
        IpNetwork::V6(prefix) => {
            // Set destination prefix.
            let mut request = request
                .v6()
                .destination_prefix(prefix.ip(), prefix.prefix());

            // Execute request.
            let request = handle.route().del(request.message_mut().clone());
            if let Err(error) = request.execute().await {
                error!(%prefix, %error, "failed to uninstall route");
            }
        }
    }
}

pub(crate) async fn mpls_route_install(
    _handle: &Handle,
    _local_label: Label,
    _route: &Route,
) {
    // TODO: not supported by the `rtnetlink` crate yet.
}

pub(crate) async fn mpls_route_uninstall(
    _handle: &Handle,
    _local_label: Label,
    _protocol: Protocol,
) {
    // TODO: not supported by the `rtnetlink` crate yet.
}

pub(crate) fn init() -> Handle {
    // Create netlink connection.
    let (conn, handle, _) = new_connection().unwrap();

    // Spawn the netlink connection on a separate thread with permanent elevated
    // capabilities.
    std::thread::spawn(|| {
        // Raise capabilities.
        let mut caps = CapState::get_current().unwrap();
        caps.effective = caps.permitted;
        if let Err(error) = caps.set_current() {
            error!("failed to update current capabilities: {}", error);
        }

        // Serve requests initiated by the netlink handle.
        futures::executor::block_on(conn)
    });

    // Return handle used to send netlink requests to the kernel.
    handle
}
