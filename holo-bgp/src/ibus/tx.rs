//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::IpAddr;

use holo_utils::ibus::IbusChannelsTx;
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    LabelInstallMsg, LabelUninstallMsg, Nexthop, RouteKeyMsg, RouteKind,
    RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::rib::LocalRoute;

// ===== global functions =====

pub(crate) fn router_id_sub(ibus_tx: &IbusChannelsTx) {
    ibus_tx.router_id_sub();
}

pub(crate) fn route_install(
    ibus_tx: &IbusChannelsTx,
    prefix: impl Into<IpNetwork>,
    route: &LocalRoute,
    distance: u8,
) {
    // Fill-in nexthops.
    let nexthops = route
        .nexthops
        .iter()
        .flat_map(|nexthops| nexthops.iter())
        .map(|nexthop| Nexthop::Recursive {
            addr: *nexthop,
            labels: route
                .nexthop_label
                .map(|label| vec![label])
                .unwrap_or_default(),
            resolved: Default::default(),
        })
        .collect::<BTreeSet<_>>();

    // Install route.
    let msg = RouteMsg {
        protocol: Protocol::BGP,
        kind: RouteKind::Unicast,
        prefix: prefix.into(),
        distance: distance.into(),
        metric: route.attrs.base.value.med.unwrap_or(0),
        tag: None,
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops: nexthops.clone(),
    };
    ibus_tx.route_ip_add(msg);
}

pub(crate) fn route_uninstall(
    ibus_tx: &IbusChannelsTx,
    prefix: impl Into<IpNetwork>,
) {
    // Uninstall route.
    let msg = RouteKeyMsg {
        protocol: Protocol::BGP,
        prefix: prefix.into(),
    };
    ibus_tx.route_ip_del(msg);
}

pub(crate) fn label_install(
    ibus_tx: &IbusChannelsTx,
    prefix: IpNetwork,
    route: &LocalRoute,
    old_route: Option<&LocalRoute>,
) {
    let Some(label) = route.label else {
        return;
    };
    if label.is_reserved() {
        return;
    }

    if let Some(old_route) = old_route
        && old_route.label == route.label
        && old_route.nexthops == route.nexthops
        && old_route.nexthop_label == route.nexthop_label
    {
        return;
    }

    let nexthops =
        route_mpls_nexthops(route.nexthops.as_ref(), route.nexthop_label);
    let msg = LabelInstallMsg {
        protocol: Protocol::BGP,
        label,
        nexthops,
        route: Some((Protocol::BGP, prefix)),
        replace: true,
    };
    ibus_tx.route_mpls_add(msg);
}

pub(crate) fn label_uninstall(
    ibus_tx: &IbusChannelsTx,
    prefix: IpNetwork,
    route: &LocalRoute,
) {
    let Some(label) = route.label else {
        return;
    };
    if label.is_reserved() {
        return;
    }

    let msg = LabelUninstallMsg {
        protocol: Protocol::BGP,
        label,
        nexthops: Default::default(),
        route: Some((Protocol::BGP, prefix)),
    };
    ibus_tx.route_mpls_del(msg);
}

pub(crate) fn nexthop_track(ibus_tx: &IbusChannelsTx, addr: IpAddr) {
    ibus_tx.nexthop_track(addr);
}

pub(crate) fn nexthop_untrack(ibus_tx: &IbusChannelsTx, addr: IpAddr) {
    ibus_tx.nexthop_untrack(addr);
}

fn route_mpls_nexthops(
    nexthops: Option<&BTreeSet<IpAddr>>,
    label: Option<Label>,
) -> BTreeSet<Nexthop> {
    nexthops
        .into_iter()
        .flat_map(|nexthops| nexthops.iter())
        .map(|nexthop| Nexthop::Recursive {
            addr: *nexthop,
            labels: label.map(|label| vec![label]).unwrap_or_default(),
            resolved: Default::default(),
        })
        .collect()
}
