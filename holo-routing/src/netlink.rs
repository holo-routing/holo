//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::num::NonZeroI32;

use capctl::caps::CapState;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKind};
use ipnetwork::IpNetwork;
use netlink_packet_core::ErrorMessage;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{RouteNextHop, RouteProtocol, RouteType};
use rtnetlink::{
    Error, Handle, RouteMessageBuilder, RouteNextHopBuilder, new_connection,
};
use tracing::error;

use crate::rib::Route;

fn netlink_protocol(protocol: Protocol) -> RouteProtocol {
    match protocol {
        Protocol::BGP => RouteProtocol::Bgp,
        Protocol::ISIS => RouteProtocol::Isis,
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
    // Create netlink message.
    let protocol = netlink_protocol(route.protocol);
    let af = match prefix {
        IpNetwork::V4(_) => AddressFamily::Inet,
        IpNetwork::V6(_) => AddressFamily::Inet6,
    };
    let nexthops = add_nexthops(af, route.nexthops.iter());
    let msg = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(prefix.ip(), prefix.prefix())
        .unwrap()
        .protocol(protocol)
        .kind(match route.kind {
            RouteKind::Unicast => RouteType::Unicast,
            RouteKind::Blackhole => RouteType::BlackHole,
            RouteKind::Unreachable => RouteType::Unreachable,
            RouteKind::Prohibit => RouteType::Prohibit,
        })
        .multipath(nexthops)
        .build();

    // Execute netlink request.
    if let Err(error) = handle.route().add(msg).replace().execute().await {
        error!(%prefix, %error, "failed to install route");
    }
}

fn add_nexthops<'a>(
    af: AddressFamily,
    nexthops: impl Iterator<Item = &'a Nexthop>,
) -> Vec<RouteNextHop> {
    let mut nl_nexthops = vec![];
    for nexthop in nexthops {
        match nexthop {
            Nexthop::Address { addr, ifindex, .. } => {
                let nl_nexthop = RouteNextHopBuilder::new(af)
                    .interface(*ifindex)
                    .via(*addr)
                    .unwrap()
                    .build();
                nl_nexthops.push(nl_nexthop);
            }
            Nexthop::Interface { ifindex } => {
                let nl_nexthop =
                    RouteNextHopBuilder::new(af).interface(*ifindex).build();
                nl_nexthops.push(nl_nexthop);
            }
            Nexthop::Recursive { resolved, .. } => {
                nl_nexthops.extend(add_nexthops(af, resolved.iter()))
            }
        };
    }

    nl_nexthops
}

pub(crate) async fn ip_route_uninstall(
    handle: &Handle,
    prefix: &IpNetwork,
    protocol: Protocol,
) {
    // Create netlink message.
    let protocol = netlink_protocol(protocol);
    let msg = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(prefix.ip(), prefix.prefix())
        .unwrap()
        .protocol(protocol)
        .kind(RouteType::Unspec)
        .build();

    // Execute netlink request.
    if let Err(error) = handle.route().del(msg).execute().await
        // Ignore "No such process" error (route is already gone).
        && !matches!(
            error,
            Error::NetlinkError(ErrorMessage {
                code: Some(code),
                ..
            })
            if code == NonZeroI32::new(-libc::ESRCH).unwrap()
        )
    {
        error!(%prefix, ?error, "failed to uninstall route");
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
