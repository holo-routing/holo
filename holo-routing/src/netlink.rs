//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;
use std::num::NonZeroI32;

use capctl::caps::CapState;
use futures::TryStreamExt;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKind};
use ipnetwork::IpNetwork;
use netlink_packet_core::ErrorMessage;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{
    MplsLabel, RouteMessage, RouteNextHop, RouteProtocol, RouteType,
};
use rtnetlink::{
    Error, Handle, RouteMessageBuilder, RouteNextHopBuilder, new_connection,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, warn};

use crate::interface::Interfaces;
use crate::rib::Route;

pub enum NetlinkRequest {
    RouteAdd(RouteMessage),
    RouteDel(RouteMessage),
}

// ===== impl NetlinkRequest =====

impl NetlinkRequest {
    pub(crate) async fn execute(self, handle: &Handle) {
        match self {
            NetlinkRequest::RouteAdd(msg) => {
                let request = handle.route().add(msg).replace();
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to install route");
                }
            }
            NetlinkRequest::RouteDel(msg) => {
                let request = handle.route().del(msg);
                if let Err(error) = request.execute().await
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
                    error!(%error, "failed to uninstall route");
                }
            }
        }
    }
}

// ===== global functions =====

pub(crate) fn ip_route_install(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    prefix: &IpNetwork,
    route: &Route,
    interfaces: &Interfaces,
) {
    // Create netlink message.
    let protocol = netlink_protocol(route.protocol);
    let af = match prefix {
        IpNetwork::V4(_) => AddressFamily::Inet,
        IpNetwork::V6(_) => AddressFamily::Inet6,
    };
    let nexthops = netlink_nexthops(af, route.nexthops.iter(), interfaces);
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

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::RouteAdd(msg)).unwrap();
}

pub(crate) fn ip_route_uninstall(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
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

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::RouteDel(msg)).unwrap();
}

pub(crate) fn mpls_route_install(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    local_label: Label,
    route: &Route,
    interfaces: &Interfaces,
) {
    // Create netlink message.
    let label = MplsLabel {
        label: local_label.get(),
        traffic_class: 0,
        bottom_of_stack: true,
        ttl: 0,
    };
    let protocol = netlink_protocol(route.protocol);
    let nexthops = netlink_nexthops(
        AddressFamily::Mpls,
        route.nexthops.iter(),
        interfaces,
    );
    let msg = RouteMessageBuilder::<MplsLabel>::new()
        .label(label)
        .protocol(protocol)
        .multipath(nexthops)
        .build();

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::RouteAdd(msg)).unwrap();
}

pub(crate) fn mpls_route_uninstall(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
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

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::RouteDel(msg)).unwrap();
}

// Purge stale routes that may have been left behind by a previous Holo
// instance.
//
// Normally, `holo-routing` removes all installed routes before exiting. In some
// cases, however, such as a panic or termination by a signal like SIGKILL, the
// process may exit abruptly, leaving routes in the kernel routing table.
//
// This function should be called during startup to clean up any such stale
// routes. It filters routes by protocol type (e.g., BGP, OSPF), assuming that
// only Holo installs routes using those protocols.
pub(crate) async fn purge_stale_routes(handle: &Handle) {
    let msg = RouteMessageBuilder::<IpAddr>::new().build();
    let mut routes = handle.route().get(msg).execute();
    while let Ok(Some(route)) = routes.try_next().await {
        // Only target routes installed by Holo.
        let protocol = route.header.protocol;
        if !matches!(
            protocol,
            RouteProtocol::Bgp
                | RouteProtocol::Isis
                | RouteProtocol::Ospf
                | RouteProtocol::Rip
                | RouteProtocol::Static
        ) {
            continue;
        }

        // Attempt to uninstall the stale route.
        if let Err(error) = handle.route().del(route).execute().await {
            warn!(?protocol, ?error, "failed to purge stale route");
        }
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
    interfaces: &Interfaces,
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

                // Use 'onlink' for IPv4 with unnumbered interface.
                if addr.is_ipv4()
                    && let Some(iface) = interfaces.get_by_ifindex(*ifindex)
                    && iface.is_unnumbered()
                {
                    nl_nexthop = nl_nexthop.onlink();
                }

                nl_nexthops.push(nl_nexthop.build());
            }
            Nexthop::Interface { ifindex } => {
                let nl_nexthop =
                    RouteNextHopBuilder::new(af).interface(*ifindex);
                nl_nexthops.push(nl_nexthop.build());
            }
            Nexthop::Recursive { resolved, .. } => nl_nexthops
                .extend(netlink_nexthops(af, resolved.iter(), interfaces)),
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
