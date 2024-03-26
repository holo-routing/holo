//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use holo_utils::bgp::RouteType;
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{RouteKeyMsg, RouteMsg};

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::instance::{Instance, InstanceUpView};
use crate::packet::attribute::Attrs;
use crate::rib::{Route, RouteOrigin};

// ===== global functions =====

pub(crate) async fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;
    instance.update().await;
}

pub(crate) fn process_nht_update(
    instance: &mut Instance,
    addr: IpAddr,
    metric: Option<u32>,
) {
    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    Debug::NhtUpdate(addr, metric).log();

    process_nht_update_af::<Ipv4Unicast>(&mut instance, addr, metric);
    process_nht_update_af::<Ipv6Unicast>(&mut instance, addr, metric);
}

pub(crate) fn process_route_add(instance: &mut Instance, msg: RouteMsg) {
    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    process_route_add_af::<Ipv4Unicast>(&mut instance, &msg);
    process_route_add_af::<Ipv6Unicast>(&mut instance, &msg);
}

pub(crate) fn process_route_del(instance: &mut Instance, msg: RouteKeyMsg) {
    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    process_route_del_af::<Ipv4Unicast>(&mut instance, &msg);
    process_route_del_af::<Ipv6Unicast>(&mut instance, &msg);
}

// ===== helper functions =====

fn process_nht_update_af<A>(
    instance: &mut InstanceUpView<'_>,
    addr: IpAddr,
    metric: Option<u32>,
) where
    A: AddressFamily,
{
    let table = A::table(&mut instance.state.rib.tables);
    if let Some(nht) = table.nht.get_mut(&addr) {
        nht.metric = metric;
        table.queued_prefixes.extend(nht.prefixes.keys());
        instance.state.schedule_decision_process(instance.tx);
    }
}

fn process_route_add_af<A>(instance: &mut InstanceUpView<'_>, msg: &RouteMsg)
where
    A: AddressFamily,
{
    // Check if the prefix is compatible with this address family.
    let Some(prefix) = A::IpNetwork::get(msg.prefix) else {
        return;
    };

    // Get prefix RIB entry.
    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let dest = table.prefixes.entry(prefix).or_default();

    // Get redistribution configuration for the address family and route
    // protocol.
    let Some(_redistribute_cfg) = instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .and_then(|afi_safi| afi_safi.redistribution.get(&msg.protocol))
    else {
        dest.redistribute = None;
        return;
    };

    // TODO: Apply redistribute routing policy, if any.
    let attrs = Attrs::default();

    // Update redistributed route in the RIB.
    let route_attrs = rib.attr_sets.get_route_attr_sets(&attrs);
    let origin = RouteOrigin::Protocol(msg.protocol);
    let route = Route::new(origin, route_attrs.clone(), RouteType::Internal);
    dest.redistribute = Some(Box::new(route));

    // Enqueue prefix and schedule the BGP Decision Process.
    table.queued_prefixes.insert(prefix);
    instance.state.schedule_decision_process(instance.tx);
}

fn process_route_del_af<A>(instance: &mut InstanceUpView<'_>, msg: &RouteKeyMsg)
where
    A: AddressFamily,
{
    // Check if the prefix is compatible with this address family.
    let Some(prefix) = A::IpNetwork::get(msg.prefix) else {
        return;
    };

    // Check if redistribution is enabled for this address family and route
    // protocol.
    if instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .and_then(|afi_safi| afi_safi.redistribution.get(&msg.protocol))
        .is_none()
    {
        return;
    }

    // Get prefix RIB entry.
    let rib = &mut instance.state.rib;
    let table = A::table(&mut rib.tables);
    let dest = table.prefixes.entry(prefix).or_default();

    // Remove redistributed route.
    dest.redistribute = None;

    // Enqueue prefix and schedule the BGP Decision Process.
    table.queued_prefixes.insert(prefix);
    instance.state.schedule_decision_process(instance.tx);
}
