//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Ingestion of routes from non-default Linux kernel routing tables.
//
// Routes are imported read-only: they are tracked in custom RIBs and may
// be leaked into default RIBs for protocol redistribution, but they are
// never written back to any kernel table.

use std::collections::BTreeMap;
use std::net::IpAddr;

use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{Nexthop, RouteKind, RouteOpaqueAttrs};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc::UnboundedSender;

use crate::rib::Route;

// Routing table IDs that must never be imported: RT_TABLE_UNSPEC,
// RT_TABLE_DEFAULT, RT_TABLE_MAIN and RT_TABLE_LOCAL. Routes Holo
// itself installs land in RT_TABLE_MAIN, so importing it would create
// Netlink echo loops; RT_TABLE_DEFAULT (253) is an alias for the main
// table and is rejected for the same reason.
pub const TABLE_UNSPEC: u32 = 0;
pub const TABLE_DEFAULT: u32 = 253;
pub const TABLE_MAIN: u32 = 254;
pub const TABLE_LOCAL: u32 = 255;

// Table ID the kernel uses in the message header when the real table ID
// is carried in the RTA_TABLE attribute (table IDs above 255).
const TABLE_COMPAT: u8 = 252;

// Returns whether the given kernel table ID may be imported.
pub fn table_id_allowed(table: u32) -> bool {
    !matches!(
        table,
        TABLE_UNSPEC | TABLE_DEFAULT | TABLE_MAIN | TABLE_LOCAL
    )
}

// Command sent to the kernel table monitor task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelCmd {
    // Start watching a kernel table: initial dump, then live updates.
    Watch { af: AddressFamily, table: u32 },
    // Stop watching a kernel table.
    Unwatch { af: AddressFamily, table: u32 },
}

// Route addition imported from a kernel table.
#[derive(Clone, Debug)]
pub struct KernelRouteAdd {
    pub table: u32,
    pub prefix: IpNetwork,
    pub kind: RouteKind,
    pub nexthops: Vec<Nexthop>,
}

// Route deletion imported from a kernel table.
#[derive(Clone, Debug)]
pub struct KernelRouteDel {
    pub table: u32,
    pub prefix: IpNetwork,
}

// Event sent by the kernel table monitor task to the routing master.
#[derive(Clone, Debug)]
pub enum KernelEvent {
    Add(KernelRouteAdd),
    Del(KernelRouteDel),
    // Start of a full table dump. Routes present in the RIB when the
    // dump ends missing from it are stale and get withdrawn. Emitted on
    // initial watch and on Netlink buffer overrun (ENOBUFS) resync.
    DumpStart {
        af: AddressFamily,
        table: u32,
    },
    // End of a full table dump started by DumpStart. `ok` is false when
    // the dump failed partway (Netlink error): a partial dump must
    // never sweep routes the failed dump never had the chance to
    // confirm.
    DumpEnd {
        af: AddressFamily,
        table: u32,
        ok: bool,
    },
}

// Contents of a custom RIB bound to a kernel routing table.
#[derive(Debug)]
pub struct KernelRib {
    pub address_family: AddressFamily,
    pub table_id: u32,
    pub routes: BTreeMap<IpNetwork, Route>,
    // Prefixes present when a dump started, awaiting re-confirmation by
    // the dump's route additions. See KernelEvent::DumpStart.
    pub dump_pending: Option<std::collections::BTreeSet<IpNetwork>>,
}

impl KernelRib {
    // Completes a table dump: returns the prefixes that were present
    // when the dump started but were not re-confirmed by an addition
    // during it, i.e. routes the kernel no longer has in the table.
    pub fn complete_dump(&mut self) -> Vec<IpNetwork> {
        self.dump_pending
            .take()
            .map(|pending| pending.into_iter().collect())
            .unwrap_or_default()
    }

    // Aborts a failed dump: forgets the sweep set and keeps the prior
    // RIB contents until a later dump succeeds.
    pub fn abort_dump(&mut self) {
        self.dump_pending = None;
    }
}

// Builds the route stored in a kernel RIB for an imported route.
pub(crate) fn kernel_route(add: &KernelRouteAdd) -> Route {
    let mut route = Route::new(
        Protocol::KERNEL,
        None,
        add.kind,
        0,
        0,
        None,
        RouteOpaqueAttrs::None,
        add.nexthops.clone().into(),
    );
    // Imported routes are never installed back into the kernel.
    route.flags.insert(crate::rib::RouteFlags::NO_FIB);
    route
}

// Returns the effective kernel table ID of a route message: the RTA_TABLE
// attribute takes precedence over the table ID in the message header, as
// the header can only carry IDs up to 255.
pub fn effective_table_id(header_table: u8, rta_table: Option<u32>) -> u32 {
    match rta_table {
        Some(table) => table,
        None => header_table as u32,
    }
}

// Parsed representation of the fields of a route message this feature
// cares about, decoupled from the Netlink types for testability.
#[derive(Clone, Debug)]
pub struct RouteMsgFields {
    pub address_family: AddressFamily,
    pub header_table: u8,
    pub rta_table: Option<u32>,
    pub destination: Option<IpAddr>,
    pub destination_prefix_length: u8,
    pub kind: RouteType,
    pub gateway: Option<IpAddr>,
    pub output_ifindex: Option<u32>,
}

// Route types this feature imports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteType {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
}

impl RouteType {
    pub fn route_kind(self) -> RouteKind {
        match self {
            RouteType::Unicast => RouteKind::Unicast,
            RouteType::Blackhole => RouteKind::Blackhole,
            RouteType::Unreachable => RouteKind::Unreachable,
            RouteType::Prohibit => RouteKind::Prohibit,
        }
    }
}

// Converts parsed route message fields into an imported route addition,
// if the message describes a route worth importing.
pub fn parse_route_fields(fields: &RouteMsgFields) -> Option<KernelRouteAdd> {
    let table = effective_table_id(fields.header_table, fields.rta_table);
    if !table_id_allowed(table) {
        return None;
    }

    let kind = fields.kind;

    // Build the prefix: IPv4 routes to the default prefix carry no
    // destination attribute.
    let prefix = match (fields.address_family, fields.destination) {
        (AddressFamily::Ipv4, None) => IpNetwork::V4(
            ipnetwork::Ipv4Network::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                fields.destination_prefix_length,
            )
            .ok()?,
        ),
        (AddressFamily::Ipv4, Some(IpAddr::V4(addr))) => {
            ipnetwork::Ipv4Network::new(addr, fields.destination_prefix_length)
                .ok()?
                .into()
        }
        (AddressFamily::Ipv6, None) => IpNetwork::V6(
            ipnetwork::Ipv6Network::new(
                std::net::Ipv6Addr::UNSPECIFIED,
                fields.destination_prefix_length,
            )
            .ok()?,
        ),
        (AddressFamily::Ipv6, Some(IpAddr::V6(addr))) => {
            ipnetwork::Ipv6Network::new(addr, fields.destination_prefix_length)
                .ok()?
                .into()
        }
        _ => return None,
    };
    if !prefix.is_routable() && kind == RouteType::Unicast {
        return None;
    }

    // Build the next hop.
    let nexthops = match (fields.gateway, fields.output_ifindex) {
        (Some(addr), Some(ifindex)) => {
            vec![Nexthop::Address {
                ifindex,
                addr,
                labels: Box::new([]),
            }]
        }
        (Some(addr), None) => {
            // Gateway without an outgoing interface: resolve it through
            // the main RIB.
            vec![Nexthop::Recursive {
                addr,
                labels: Box::new([]),
                resolved: Box::new([]),
            }]
        }
        (None, Some(ifindex)) => vec![Nexthop::Interface { ifindex }],
        (None, None) => {
            if kind == RouteType::Unicast {
                return None;
            }
            Vec::new()
        }
    };

    Some(KernelRouteAdd {
        table,
        prefix,
        kind: kind.route_kind(),
        nexthops,
    })
}

// ===== monitor task =====

// Spawns the kernel table monitor task, returning the command channel.
// The task watches the kernel tables requested through the command
// channel, forwarding imported route events to the routing master.
#[cfg(target_os = "linux")]
pub fn spawn_monitor_task(
    event_tx: UnboundedSender<KernelEvent>,
) -> UnboundedSender<KernelCmd> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        monitor_task(event_tx, cmd_rx).await;
    });
    cmd_tx
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_monitor_task(
    _event_tx: UnboundedSender<KernelEvent>,
) -> UnboundedSender<KernelCmd> {
    let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    cmd_tx
}

#[cfg(target_os = "linux")]
async fn monitor_task(
    event_tx: UnboundedSender<KernelEvent>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<KernelCmd>,
) {
    use futures::stream::StreamExt;
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_route::RouteNetlinkMessage;
    use rtnetlink::new_connection;

    // Dedicated connection for the route multicast groups.
    let (mut conn, handle, monitor) = match new_connection() {
        Ok(conn) => conn,
        Err(error) => {
            tracing::error!(%error, "failed to create kernel table monitor socket");
            return;
        }
    };
    let mut monitor = {
        use netlink_sys::{AsyncSocket, SocketAddr};
        let groups = (1 << (libc::RTNLGRP_IPV4_ROUTE - 1))
            | (1 << (libc::RTNLGRP_IPV6_ROUTE - 1));
        let addr = SocketAddr::new(0, groups);
        if let Err(error) = conn.socket_mut().socket_mut().bind(&addr) {
            tracing::error!(%error, "failed to bind kernel table monitor socket");
            return;
        }
        monitor
    };
    // Enlarge the Netlink receive buffer to make event loss less likely
    // under route churn (the kernel default is far too small).
    {
        use netlink_sys::AsyncSocket;
        if let Err(error) = conn
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(4 * 1024 * 1024)
        {
            tracing::warn!(%error, "kernel monitor: failed to set receive buffer size");
        }
    }
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Watched kernel tables.
    let mut watched: std::collections::BTreeSet<(AddressFamily, u32)> =
        Default::default();

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => match cmd {
                KernelCmd::Watch { af, table } => {
                    tracing::debug!(%af, table, "kernel monitor: watch");
                    if watched.insert((af, table)) {
                        dump_table(&handle, &event_tx, af, table).await;
                    }
                }
                KernelCmd::Unwatch { af, table } => {
                    watched.remove(&(af, table));
                }
            },
            Some((msg, _)) = monitor.next() => {
                // Netlink buffer overrun: some events were lost. Re-dump
                // every watched table so the RIBs are reconciled; routes
                // the kernel no longer has are withdrawn at dump end.
                if let NetlinkPayload::Error(error) = &msg.payload
                    && error.code.map(i32::from) == Some(-libc::ENOBUFS)
                {
                    tracing::warn!(
                        "kernel monitor: buffer overrun, resyncing watched tables"
                    );
                    for (af, table) in watched.clone() {
                        dump_table(&handle, &event_tx, af, table).await;
                    }
                    continue;
                }
                let payload = match msg.payload {
                    NetlinkPayload::InnerMessage(msg) => msg,
                    _ => continue,
                };
                let event = match payload {
                    RouteNetlinkMessage::NewRoute(route_msg) => {
                        parse_route_message(&route_msg).map(KernelEvent::Add)
                    }
                    RouteNetlinkMessage::DelRoute(route_msg) => {
                        let table = effective_table_id(
                            route_msg.header.table,
                            route_msg.attributes.iter().find_map(|attr| {
                                if let netlink_packet_route::route::RouteAttribute::Table(t) = attr {
                                    Some(*t)
                                } else {
                                    None
                                }
                            }),
                        );
                        route_prefix(&route_msg).map(|prefix| {
                            KernelEvent::Del(KernelRouteDel { table, prefix })
                        })
                    }
                    _ => None,
                };
                if let Some(event) = event {
                    let af = event_prefix_af(&event);
                    let table = event_table(&event);
                    if watched.contains(&(af, table)) {
                        let _ = event_tx.send(event);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn event_table(event: &KernelEvent) -> u32 {
    match event {
        KernelEvent::Add(add) => add.table,
        KernelEvent::Del(del) => del.table,
        KernelEvent::DumpStart { table, .. }
        | KernelEvent::DumpEnd { table, .. } => *table,
    }
}

#[cfg(target_os = "linux")]
fn event_prefix_af(event: &KernelEvent) -> AddressFamily {
    match event {
        KernelEvent::Add(add) => add.prefix.address_family(),
        KernelEvent::Del(del) => del.prefix.address_family(),
        KernelEvent::DumpStart { af, .. } | KernelEvent::DumpEnd { af, .. } => {
            *af
        }
    }
}

// Dumps the existing routes of a kernel table, forwarding them as events.
#[cfg(target_os = "linux")]
async fn dump_table(
    handle: &rtnetlink::Handle,
    event_tx: &UnboundedSender<KernelEvent>,
    af: AddressFamily,
    table: u32,
) {
    use futures::stream::StreamExt;
    use netlink_packet_route::route::RouteAttribute;
    use rtnetlink::RouteMessageBuilder;

    // The builder sets the dump (match and root) flags.
    let mut msg = match af {
        AddressFamily::Ipv4 => {
            RouteMessageBuilder::<std::net::Ipv4Addr>::new().build()
        }
        AddressFamily::Ipv6 => {
            RouteMessageBuilder::<std::net::Ipv6Addr>::new().build()
        }
    };
    if table <= u8::MAX as u32 {
        msg.header.table = table as u8;
    } else {
        msg.header.table = TABLE_COMPAT;
        msg.attributes.push(RouteAttribute::Table(table));
    }

    let mut stream = handle.route().get(msg).execute();
    let _ = event_tx.send(KernelEvent::DumpStart { af, table });
    let mut ok = true;
    while let Some(result) = stream.next().await {
        match result {
            Ok(route_msg) => {
                if let Some(add) = parse_route_message(&route_msg)
                    && add.table == table
                {
                    let _ = event_tx.send(KernelEvent::Add(add));
                }
            }
            Err(err) => {
                ok = false;
                tracing::warn!(
                    %err,
                    table,
                    %af,
                    "kernel table dump error; stale sweep skipped"
                );
            }
        }
    }
    let _ = event_tx.send(KernelEvent::DumpEnd { af, table, ok });
}

// Parses a Netlink route message into an imported route addition.
#[cfg(target_os = "linux")]
fn parse_route_message(
    route_msg: &netlink_packet_route::route::RouteMessage,
) -> Option<KernelRouteAdd> {
    use netlink_packet_route::route::{
        RouteAttribute, RouteType as NlRouteType, RouteVia,
    };

    let kind = match route_msg.header.kind {
        NlRouteType::Unicast => RouteType::Unicast,
        NlRouteType::BlackHole => RouteType::Blackhole,
        NlRouteType::Unreachable => RouteType::Unreachable,
        NlRouteType::Prohibit => RouteType::Prohibit,
        _ => return None,
    };
    let mut fields = RouteMsgFields {
        address_family: match route_msg.header.address_family {
            netlink_packet_route::AddressFamily::Inet => AddressFamily::Ipv4,
            netlink_packet_route::AddressFamily::Inet6 => AddressFamily::Ipv6,
            _ => return None,
        },
        header_table: route_msg.header.table,
        rta_table: None,
        destination: None,
        destination_prefix_length: route_msg.header.destination_prefix_length,
        kind,
        gateway: None,
        output_ifindex: None,
    };
    let mut multipath = false;
    for attr in &route_msg.attributes {
        match attr {
            RouteAttribute::MultiPath(_) => multipath = true,
            RouteAttribute::Table(table) => fields.rta_table = Some(*table),
            RouteAttribute::Destination(addr) => {
                fields.destination = Some(route_address_to_ip(addr)?)
            }
            RouteAttribute::Gateway(addr) => {
                fields.gateway = Some(route_address_to_ip(addr)?)
            }
            RouteAttribute::Via(via) => {
                fields.gateway = Some(match via {
                    RouteVia::Inet(addr) => (*addr).into(),
                    RouteVia::Inet6(addr) => (*addr).into(),
                    _ => return None,
                })
            }
            RouteAttribute::Oif(ifindex) => {
                fields.output_ifindex = Some(*ifindex)
            }
            _ => (),
        }
    }
    if multipath {
        // ECMP import is unsupported: this parser models a single
        // gateway/OIF, so importing a multipath route would present an
        // incomplete view of the kernel's forwarding state. Reject the
        // whole route rather than one of its paths.
        tracing::warn!(
            table = effective_table_id(
                route_msg.header.table,
                fields.rta_table
            ),
            destination = ?fields.destination,
            prefix_len = fields.destination_prefix_length,
            "rejecting kernel route with RTA_MULTIPATH (ECMP import unsupported)"
        );
        return None;
    }
    parse_route_fields(&fields)
}

#[cfg(target_os = "linux")]
fn route_address_to_ip(
    addr: &netlink_packet_route::route::RouteAddress,
) -> Option<IpAddr> {
    use netlink_packet_route::route::RouteAddress;
    match addr {
        RouteAddress::Inet(addr) => Some((*addr).into()),
        RouteAddress::Inet6(addr) => Some((*addr).into()),
        _ => None,
    }
}

// Extracts the prefix of a route message, for deletions.
#[cfg(target_os = "linux")]
fn route_prefix(
    route_msg: &netlink_packet_route::route::RouteMessage,
) -> Option<IpNetwork> {
    let mut destination = None;
    for attr in &route_msg.attributes {
        if let netlink_packet_route::route::RouteAttribute::Destination(addr) =
            attr
        {
            destination = Some(route_address_to_ip(addr)?);
        }
    }
    let len = route_msg.header.destination_prefix_length;
    match (route_msg.header.address_family, destination) {
        (netlink_packet_route::AddressFamily::Inet, None) => Some(
            ipnetwork::Ipv4Network::new(std::net::Ipv4Addr::UNSPECIFIED, len)
                .ok()?
                .into(),
        ),
        (netlink_packet_route::AddressFamily::Inet, Some(IpAddr::V4(addr))) => {
            Some(ipnetwork::Ipv4Network::new(addr, len).ok()?.into())
        }
        (netlink_packet_route::AddressFamily::Inet6, None) => Some(
            ipnetwork::Ipv6Network::new(std::net::Ipv6Addr::UNSPECIFIED, len)
                .ok()?
                .into(),
        ),
        (
            netlink_packet_route::AddressFamily::Inet6,
            Some(IpAddr::V6(addr)),
        ) => Some(ipnetwork::Ipv6Network::new(addr, len).ok()?.into()),
        _ => None,
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;

    fn fields_v4(table: u8, rta_table: Option<u32>) -> RouteMsgFields {
        RouteMsgFields {
            address_family: AddressFamily::Ipv4,
            header_table: table,
            rta_table,
            destination: Some("100.64.0.42".parse().unwrap()),
            destination_prefix_length: 32,
            kind: RouteType::Unicast,
            gateway: None,
            output_ifindex: Some(10),
        }
    }

    #[test]
    fn default_routes_parse_without_destination_attr() {
        // Linux omits RTA_DST for default routes: both 0.0.0.0/0 and
        // ::/0 arrive with destination == None.
        let fields = RouteMsgFields {
            address_family: AddressFamily::Ipv6,
            header_table: 52,
            rta_table: None,
            destination: None,
            destination_prefix_length: 0,
            kind: RouteType::Unicast,
            gateway: Some("fe80::1".parse().unwrap()),
            output_ifindex: Some(10),
        };
        let add = parse_route_fields(&fields).expect("::/0 parses");
        assert_eq!(add.prefix.to_string(), "::/0");
        let fields = RouteMsgFields {
            address_family: AddressFamily::Ipv4,
            gateway: None,
            ..fields
        };
        let add = parse_route_fields(&fields).expect("0.0.0.0/0 parses");
        assert_eq!(add.prefix.to_string(), "0.0.0.0/0");
        // route_prefix() over raw netlink messages without RTA_DST.
        for (family, expect) in [
            (netlink_packet_route::AddressFamily::Inet6, "::/0"),
            (netlink_packet_route::AddressFamily::Inet, "0.0.0.0/0"),
        ] {
            let mut msg = netlink_packet_route::route::RouteMessage::default();
            msg.header.address_family = family;
            msg.header.destination_prefix_length = 0;
            assert_eq!(
                route_prefix(&msg),
                Some(expect.parse::<IpNetwork>().unwrap()),
                "default route {expect}"
            );
        }
    }

    #[test]
    fn table_id_rejects_unspec_main_and_local() {
        assert!(!table_id_allowed(TABLE_UNSPEC));
        assert!(!table_id_allowed(TABLE_DEFAULT));
        assert!(!table_id_allowed(TABLE_MAIN));
        assert!(!table_id_allowed(TABLE_LOCAL));
        assert!(table_id_allowed(52));
        assert!(table_id_allowed(1000));
    }

    #[test]
    fn effective_table_prefers_rta_table() {
        // Table IDs up to 255 ride in the header.
        assert_eq!(effective_table_id(52, None), 52);
        // Larger IDs ride in RTA_TABLE, with RT_TABLE_COMPAT in the header.
        assert_eq!(effective_table_id(TABLE_COMPAT, Some(1000)), 1000);
    }

    #[test]
    fn parses_u8_and_u32_table_ids() {
        let add = parse_route_fields(&fields_v4(52, None)).unwrap();
        assert_eq!(add.table, 52);
        assert_eq!(add.prefix.to_string(), "100.64.0.42/32");

        let add =
            parse_route_fields(&fields_v4(TABLE_COMPAT, Some(1000))).unwrap();
        assert_eq!(add.table, 1000);
    }

    #[test]
    fn rejects_main_and_local_tables() {
        assert!(
            parse_route_fields(&fields_v4(TABLE_MAIN as u8, None)).is_none()
        );
        assert!(
            parse_route_fields(&fields_v4(TABLE_LOCAL as u8, None)).is_none()
        );
    }

    #[test]
    fn parses_nexthop_variants() {
        // Gateway with outgoing interface.
        let mut fields = fields_v4(52, None);
        fields.gateway = Some("100.64.0.1".parse().unwrap());
        let add = parse_route_fields(&fields).unwrap();
        assert_eq!(
            add.nexthops,
            vec![Nexthop::Address {
                ifindex: 10,
                addr: "100.64.0.1".parse().unwrap(),
                labels: Box::new([]),
            }]
        );

        // Interface only.
        let mut fields = fields_v4(52, None);
        fields.gateway = None;
        let add = parse_route_fields(&fields).unwrap();
        assert_eq!(add.nexthops, vec![Nexthop::Interface { ifindex: 10 }]);

        // Gateway without interface: recursive.
        let mut fields = fields_v4(52, None);
        fields.gateway = Some("100.64.0.1".parse().unwrap());
        fields.output_ifindex = None;
        let add = parse_route_fields(&fields).unwrap();
        assert!(matches!(
            add.nexthops[0],
            Nexthop::Recursive {
                addr: IpAddr::V4(_),
                ..
            }
        ));
    }

    #[test]
    fn blackhole_routes_have_no_nexthops() {
        let mut fields = fields_v4(52, None);
        fields.kind = RouteType::Blackhole;
        fields.gateway = None;
        fields.output_ifindex = None;
        let add = parse_route_fields(&fields).unwrap();
        assert_eq!(add.kind, RouteKind::Blackhole);
        assert!(add.nexthops.is_empty());
    }

    #[test]
    fn dump_sweep_withdraws_unconfirmed_routes() {
        let gone: IpNetwork = "100.64.0.42/32".parse().unwrap();
        let kept: IpNetwork = "100.64.0.43/32".parse().unwrap();
        let mut rib = KernelRib {
            address_family: AddressFamily::Ipv4,
            table_id: 52,
            routes: Default::default(),
            dump_pending: None,
        };
        for prefix in [gone, kept] {
            let add = KernelRouteAdd {
                table: 52,
                prefix,
                kind: RouteKind::Unicast,
                nexthops: vec![],
            };
            rib.routes.insert(prefix, kernel_route(&add));
        }
        // A dump starts: every current route awaits re-confirmation.
        rib.dump_pending = Some(rib.routes.keys().copied().collect());
        // The dump re-confirms only `kept`.
        rib.dump_pending.as_mut().unwrap().remove(&kept);
        assert_eq!(rib.complete_dump(), vec![gone]);
        // Without an ongoing dump, completion is a no-op.
        assert!(rib.complete_dump().is_empty());
    }

    #[test]
    fn failed_dump_keeps_prior_routes() {
        let kept: IpNetwork = "100.64.0.43/32".parse().unwrap();
        let mut rib = KernelRib {
            address_family: AddressFamily::Ipv4,
            table_id: 52,
            routes: Default::default(),
            dump_pending: None,
        };
        let add = KernelRouteAdd {
            table: 52,
            prefix: kept,
            kind: RouteKind::Unicast,
            nexthops: vec![],
        };
        rib.routes.insert(kept, kernel_route(&add));
        // A dump starts and then fails without confirming anything: the
        // abort must sweep nothing and keep the prior RIB contents.
        rib.dump_pending = Some(rib.routes.keys().copied().collect());
        rib.abort_dump();
        assert!(rib.dump_pending.is_none());
        assert!(rib.routes.contains_key(&kept));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn multipath_routes_are_rejected() {
        use netlink_packet_route::route::{
            RouteAddress, RouteAttribute, RouteMessage, RouteType,
        };
        let mut msg = RouteMessage::default();
        msg.header.kind = RouteType::Unicast;
        msg.header.address_family = netlink_packet_route::AddressFamily::Inet;
        msg.header.table = 52;
        msg.header.destination_prefix_length = 24;
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(
                "10.0.0.0".parse().unwrap(),
            )));
        // RouteNextHop is non-exhaustive; an empty path list is enough
        // to carry the RTA_MULTIPATH attribute itself.
        msg.attributes.push(RouteAttribute::MultiPath(vec![]));
        assert!(parse_route_message(&msg).is_none());
        // The same route without RTA_MULTIPATH still parses.
        msg.attributes
            .retain(|attr| !matches!(attr, RouteAttribute::MultiPath(_)));
        msg.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                "10.0.0.1".parse().unwrap(),
            )));
        assert!(parse_route_message(&msg).is_some());
    }
}
