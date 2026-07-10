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
    MplsLabel, RouteAttribute, RouteMessage, RouteNextHop, RouteProtocol,
    RouteType,
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
    let mut nexthops = netlink_nexthops(
        AddressFamily::Mpls,
        route.nexthops.iter(),
        interfaces,
    );
    let msg = match nexthops.len() {
        // Use top-level nexthop attributes for the single-nexthop case:
        // the kernel does not accept the RTA_MULTIPATH encoding produced
        // for AF_MPLS routes (they get installed with no nexthops and are
        // flagged dead/linkdown). See examples/mpls_repro.rs.
        1 => {
            let nexthop = nexthops.remove(0);
            let mut msg = RouteMessageBuilder::<MplsLabel>::new()
                .label(label)
                .protocol(protocol)
                .build();
            msg.attributes
                .push(RouteAttribute::Oif(nexthop.interface_index));
            msg.attributes.extend(nexthop.attributes);
            msg
        }
        _ => RouteMessageBuilder::<MplsLabel>::new()
            .label(label)
            .protocol(protocol)
            .multipath(nexthops)
            .build(),
    };

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;
    use holo_utils::ibus::IbusClientId;
    use holo_utils::southbound::{RouteKind, RouteOpaqueAttrs};
    use netlink_packet_route::route::RouteVia;
    use tokio::sync::mpsc;

    use super::*;
    use crate::rib::RouteFlags;

    fn route(nexthops: BTreeSet<Nexthop>) -> Route {
        Route::new(
            Protocol::BGP,
            IbusClientId::default(),
            RouteKind::Unicast,
            20,
            0,
            None,
            RouteOpaqueAttrs::None,
            nexthops,
            Utc::now(),
            RouteFlags::ACTIVE,
        )
    }

    fn address_nexthop(ifindex: u32, addr: Ipv4Addr, label: u32) -> Nexthop {
        Nexthop::Address {
            ifindex,
            addr: IpAddr::V4(addr),
            labels: vec![Label::new(label)],
        }
    }

    fn install_mpls_route(route: &Route) -> RouteMessage {
        let (tx, mut rx) = mpsc::unbounded_channel();
        mpls_route_install(&tx, Label::new(100), route, &Interfaces::default());
        match rx.try_recv().unwrap() {
            NetlinkRequest::RouteAdd(msg) => msg,
            NetlinkRequest::RouteDel(_) => panic!("unexpected route delete"),
        }
    }

    #[test]
    fn mpls_single_nexthop_uses_top_level_attrs() {
        let route = route(BTreeSet::from([address_nexthop(
            10,
            Ipv4Addr::new(192, 0, 2, 1),
            200,
        )]));

        let msg = install_mpls_route(&route);

        assert!(
            msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Oif(10)))
        );
        assert!(msg.attributes.iter().any(|attr| matches!(
            attr,
            RouteAttribute::Via(RouteVia::Inet(addr))
                if *addr == Ipv4Addr::new(192, 0, 2, 1)
        )));
        assert!(msg.attributes.iter().any(|attr| matches!(
            attr,
            RouteAttribute::NewDestination(labels)
                if labels.iter().map(|label| label.label).collect::<Vec<_>>() == vec![200]
        )));
        assert!(
            !msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::MultiPath(_)))
        );
    }

    #[test]
    fn mpls_multipath_keeps_labels_per_nexthop() {
        let route = route(BTreeSet::from([
            address_nexthop(10, Ipv4Addr::new(192, 0, 2, 1), 200),
            address_nexthop(20, Ipv4Addr::new(192, 0, 2, 2), 300),
        ]));

        let msg = install_mpls_route(&route);
        let multipath = msg
            .attributes
            .iter()
            .find_map(|attr| {
                if let RouteAttribute::MultiPath(nexthops) = attr {
                    Some(nexthops)
                } else {
                    None
                }
            })
            .unwrap();

        assert_eq!(multipath.len(), 2);
        assert_eq!(multipath[0].interface_index, 10);
        assert_eq!(multipath[1].interface_index, 20);
        for (nexthop, addr, label) in [
            (&multipath[0], Ipv4Addr::new(192, 0, 2, 1), 200),
            (&multipath[1], Ipv4Addr::new(192, 0, 2, 2), 300),
        ] {
            assert!(nexthop.attributes.iter().any(|attr| matches!(
                attr,
                RouteAttribute::Via(RouteVia::Inet(nh_addr)) if *nh_addr == addr
            )));
            assert!(nexthop.attributes.iter().any(|attr| matches!(
                attr,
                RouteAttribute::NewDestination(labels)
                    if labels.iter().map(|label| label.label).collect::<Vec<_>>() == vec![label]
            )));
        }
    }
}
