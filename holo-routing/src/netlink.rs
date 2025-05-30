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
use netlink_packet_route::route::{
    MplsLabel, RouteNextHop, RouteProtocol, RouteType,
};
use rtnetlink::{
    Error, Handle, RouteMessageBuilder, RouteNextHopBuilder, new_connection,
};
use tracing::error;

use crate::rib::Route;

// ===== global functions =====

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
    let nexthops = netlink_nexthops(af, route.nexthops.iter());
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
    handle: &Handle,
    local_label: Label,
    route: &Route,
) {
    // Create netlink message.
    let label = MplsLabel {
        label: local_label.get(),
        traffic_class: 0,
        bottom_of_stack: true,
        ttl: 0,
    };
    let protocol = netlink_protocol(route.protocol);
    let nexthops = netlink_nexthops(AddressFamily::Mpls, route.nexthops.iter());
    let msg = RouteMessageBuilder::<MplsLabel>::new()
        .label(label)
        .protocol(protocol)
        .multipath(nexthops)
        .build();

    // Execute netlink request.
    if let Err(error) = handle.route().add(msg).replace().execute().await {
        error!(?label, %error, "failed to install MPLS route");
    }
}

pub(crate) async fn mpls_route_uninstall(
    handle: &Handle,
    local_label: Label,
    protocol: Protocol,
) {
    // Create netlink message.
    let label = MplsLabel {
        label: local_label.get(),
        traffic_class: 0,
        bottom_of_stack: true,
        ttl: 0,
    };
    let protocol = netlink_protocol(protocol);
    let msg = RouteMessageBuilder::<MplsLabel>::new()
        .label(label)
        .protocol(protocol)
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
        error!(?label, %error, "failed to uninstall MPLS route");
    }
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

// ===== helper functions =====

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

fn netlink_nexthops<'a>(
    af: AddressFamily,
    nexthops: impl Iterator<Item = &'a Nexthop>,
) -> Vec<RouteNextHop> {
    let mut nl_nexthops = vec![];

    for nexthop in nexthops {
        match nexthop {
            Nexthop::Address {
                addr,
                ifindex,
                labels,
            } => {
                let mut nl_nexthop = RouteNextHopBuilder::new(af)
                    .interface(*ifindex)
                    .via(*addr)
                    .unwrap();

                // Add MPLS labels if present.
                if !labels.is_empty() {
                    nl_nexthop = nl_nexthop.mpls(netlink_label_stack(labels));
                }

                nl_nexthops.push(nl_nexthop.build());
            }
            Nexthop::Interface { ifindex } => {
                let nl_nexthop =
                    RouteNextHopBuilder::new(af).interface(*ifindex);
                nl_nexthops.push(nl_nexthop.build());
            }
            Nexthop::Recursive { resolved, .. } => {
                nl_nexthops.extend(netlink_nexthops(af, resolved.iter()))
            }
        };
    }

    nl_nexthops
}

fn netlink_label_stack(labels: &[Label]) -> Vec<MplsLabel> {
    let mut labels = labels
        .iter()
        .filter(|label| !label.is_implicit_null())
        .map(|label| MplsLabel {
            label: label.get(),
            traffic_class: 0,
            bottom_of_stack: false,
            ttl: 0,
        })
        .collect::<Vec<_>>();
    if let Some(label) = labels.last_mut() {
        label.bottom_of_stack = true;
    }
    labels
}
