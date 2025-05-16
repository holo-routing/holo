//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::btree_map;

use holo_utils::ip::SocketAddrKind;

use crate::debug::Debug;
use crate::error::Error;
use crate::instance::InstanceUpView;
use crate::interface::{Interface, Interfaces};
use crate::network::SendDestination;
use crate::output::{self, ResponseType};
use crate::packet::{Command, PduVersion, RteRouteVersion, RteVersion};
use crate::route::{Metric, Route, RouteFlags, RouteType};
use crate::version::Version;
use crate::{neighbor, southbound};

// ===== UDP packet receipt =====

pub(crate) fn process_pdu<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
    src: V::SocketAddr,
    pdu: Result<V::Pdu, V::PduDecodeError>,
) where
    V: Version,
{
    // Lookup interface.
    let Some(iface) = V::get_iface_by_source(interfaces, src) else {
        return;
    };

    // Ignore PDUs received on inactive interfaces.
    if !iface.state.active {
        return;
    }

    // Log received PDU.
    if instance.config.trace_opts.packets_rx {
        Debug::<V>::PduRx(iface, src.ip(), &pdu).log();
    }

    // Update or create new neighbor.
    let nbr = neighbor::update(
        &mut instance.state.neighbors,
        *src.ip(),
        instance.config.invalid_interval,
        &instance.tx.protocol_input.nbr_timeout,
    );

    match pdu {
        Ok(mut pdu) => {
            if let Some(auth_seqno) = pdu.auth_seqno() {
                // Perform sequence number validation to protect against replay
                // attacks when authentication is enabled.
                if auth_seqno < nbr.auth_seqno {
                    // Log the error first.
                    Error::<V>::UdpPduAuthInvalidSeqno(src, auth_seqno).log();

                    // Update neighbor statistics.
                    nbr.bad_packets_rcvd += 1;

                    // Update interface statistics.
                    iface.state.statistics.bad_packets_rcvd += 1;
                    iface.state.statistics.update_discontinuity_time();

                    // Discard the packet.
                    return;
                }

                // Update neighbor's last received sequence number.
                nbr.auth_seqno = auth_seqno;
            }

            // Update statistics.
            instance.state.statistics.update(pdu.command(), false);
            for rte_error in pdu.rte_errors() {
                // Log the error first.
                Error::<V>::UdpPduDecodeError(rte_error).log();

                // Update neighbor statistics.
                nbr.bad_routes_rcvd += 1;

                // Update interface statistics.
                iface.state.statistics.bad_routes_rcvd += 1;
                iface.state.statistics.update_discontinuity_time();
            }

            match pdu.command() {
                Command::Request => {
                    process_pdu_request(instance, iface, src, pdu);
                }
                Command::Response => {
                    process_pdu_response(instance, iface, src, pdu);
                }
            }
        }
        Err(error) => {
            // Log the error first.
            Error::<V>::UdpPduDecodeError(error).log();

            // Update neighbor statistics.
            nbr.bad_packets_rcvd += 1;

            // Update interface statistics.
            iface.state.statistics.bad_packets_rcvd += 1;
            iface.state.statistics.update_discontinuity_time();
        }
    }
}

fn process_pdu_request<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &mut Interface<V>,
    src: V::SocketAddr,
    mut pdu: V::Pdu,
) where
    V: Version,
{
    // Ignore requests received on passive interfaces.
    if iface.is_passive() {
        return;
    }

    // If there are no entries, no response is given.
    if pdu.rtes().is_empty() {
        return;
    }

    // The response should be sent to the requester's address and port.
    let dst = SendDestination::Unicast(src);

    // Check if it's a request to send the entire routing table.
    if pdu.is_dump_request() {
        output::send_response(instance, iface, dst, ResponseType::Normal);
    } else {
        // Examine the list of RTEs in the Request one by one. For each entry,
        // look up the destination in the router's routing database and, if
        // there is a route, put that route's metric in the metric field of the
        // RTE. If there is no explicit route to the specified destination, put
        // infinity in the metric field. Once all the entries have been filled
        // in, change the command from Request to Response and send the datagram
        // back to the requester.
        for rte in pdu.rtes_mut() {
            if let Some(rte) = rte.as_route_mut() {
                let metric = if let Some(route) =
                    instance.state.routes.get(rte.prefix())
                {
                    // Do not perform split-horizon.
                    route.metric
                } else {
                    Metric::from(Metric::INFINITE)
                };
                rte.set_metric(metric);
            }
        }
        pdu.set_command(Command::Response);
        output::send_pdu(instance, iface, dst, pdu);
    }
}

// A Response can be received for one of several different reasons:
//
// - response to a specific query
// - regular update (unsolicited response)
// - triggered update caused by a route change
//
// Processing is the same no matter why the Response was generated.
fn process_pdu_response<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &mut Interface<V>,
    src: V::SocketAddr,
    pdu: V::Pdu,
) where
    V: Version,
{
    let invalid_interval = iface.config.invalid_interval;
    let flush_interval = iface.config.flush_interval;
    let distance = instance.config.distance;

    // The Response must be ignored if it is not from the RIP port.
    if src.port() != V::UDP_PORT {
        return;
    }

    // Iterate over all RTEs.
    let mut ripng_nexthop = None;
    for rte in pdu.rtes() {
        let source = Some(*src.ip());

        // Process RIPng nexthop RTE.
        if let Some(rte_nexthop) = rte.as_nexthop() {
            // The advertised nexthop applies to all following route RTEs until
            // the end of the message or until another next hop RTE is
            // encountered.
            ripng_nexthop = rte_nexthop;
            continue;
        }

        // Proceed to process normal route RTEs.
        let rte = match rte.as_route() {
            Some(rte) => rte,
            None => continue,
        };

        // Update the metric by adding the cost of the network on which the
        // message arrived.
        let mut metric = rte.metric();
        metric.add(iface.config.cost);

        // Use nexthop from the nexthop field (RIPv2) or nexthop RTE (RIPng) if
        // it's present. Otherwise, use the source of the RIP advertisement.
        let mut nexthop = *src.ip();
        // RIPv2 nexthop handling.
        let ripv2_nexthop = rte.nexthop();
        if let Some(rte_nexthop) = ripv2_nexthop
            && iface.system.contains_addr(rte_nexthop)
        {
            nexthop = *rte_nexthop;
        }
        // RIPng nexthop handling.
        if let Some(rte_nexthop) = ripng_nexthop {
            nexthop = *rte_nexthop;
        }
        let nexthop = Some(nexthop);

        // Check if the route already exists in the routing table.
        match instance.state.routes.entry(*rte.prefix()) {
            btree_map::Entry::Occupied(mut o) => {
                let route = o.get_mut();

                // Update route in the following cases:
                // * New metric is lower
                // * Same neighbor, but different metric, nexthop or tag
                if metric.get() < route.metric.get()
                    || (source == route.source
                        && (metric != route.metric
                            || nexthop != route.nexthop
                            || rte.tag() != route.tag))
                {
                    if instance.config.trace_opts.route {
                        Debug::<V>::RouteUpdate(
                            &route.prefix,
                            &source,
                            &metric,
                        )
                        .log();
                    }

                    let old_metric = route.metric;

                    // Update route.
                    route.ifindex = iface.system.ifindex.unwrap();
                    route.source = source;
                    route.nexthop = nexthop;
                    route.metric = metric;
                    route.rcvd_metric = Some(rte.metric());
                    route.tag = rte.tag();
                    route.flags.insert(RouteFlags::CHANGED);

                    // Signal the output process to trigger an update.
                    instance.tx.protocol_input.trigger_update();

                    if !metric.is_infinite() {
                        // Install route.
                        southbound::tx::route_install(
                            &instance.tx.ibus,
                            route,
                            distance,
                        );
                    } else if !old_metric.is_infinite() {
                        // Uninstall route.
                        southbound::tx::route_uninstall(
                            &instance.tx.ibus,
                            route,
                        );

                        route.garbage_collection_start(
                            flush_interval,
                            &instance.tx.protocol_input.route_gc_timeout,
                        );
                    }
                }

                // Reinitialize the route timeout.
                if source == route.source && !metric.is_infinite() {
                    route.timeout_reset(
                        invalid_interval,
                        &instance.tx.protocol_input.route_timeout,
                    );
                    route.garbage_collection_stop();
                }
            }
            btree_map::Entry::Vacant(v) => {
                if metric.is_infinite() {
                    continue;
                }

                // Create new route.
                let mut route = Route::new(
                    *rte.prefix(),
                    iface.system.ifindex.unwrap(),
                    source,
                    metric,
                    rte.tag(),
                    RouteType::Rip,
                    &instance.config.trace_opts,
                );
                route.nexthop = nexthop;
                route.rcvd_metric = Some(rte.metric());

                // Set route timeout.
                route.timeout_reset(
                    invalid_interval,
                    &instance.tx.protocol_input.route_timeout,
                );

                // Signal the output process to trigger an update.
                instance.tx.protocol_input.trigger_update();

                // Install route.
                southbound::tx::route_install(
                    &instance.tx.ibus,
                    &route,
                    distance,
                );

                // Add route.
                v.insert(route);
            }
        }
    }
}

// ===== instance initial update =====

pub(crate) fn process_initial_update<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
) where
    V: Version,
{
    if instance.config.trace_opts.events {
        Debug::<V>::InitialUpdate.log();
    }
    instance.state.initial_update_task = None;
    output::send_response_all(instance, interfaces, ResponseType::Normal);
}

// ===== instance update interval =====

pub(crate) fn process_update_interval<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
) where
    V: Version,
{
    if instance.config.trace_opts.events {
        Debug::<V>::UpdateInterval.log();
    }
    output::send_response_all(instance, interfaces, ResponseType::Normal);
}

// ===== instance triggered update =====

pub(crate) fn process_triggered_update<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
) where
    V: Version,
{
    // Don't generate triggered updates before the initial update is sent.
    if instance.state.initial_update_task.is_some() {
        return;
    }

    // Wait until the triggered update timeout expires.
    if instance.state.triggered_upd_timeout_task.is_some() {
        instance.state.pending_trigger_upd = true;
        return;
    }

    output::triggered_update(instance, interfaces);
}

// ===== instance triggered update timeout =====

pub(crate) fn process_triggered_update_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
) where
    V: Version,
{
    if instance.state.pending_trigger_upd {
        output::triggered_update(instance, interfaces);
    }

    output::cancel_triggered_update(instance);
}

// ===== neighbor timeout =====

pub(crate) fn process_nbr_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    addr: V::IpAddr,
) where
    V: Version,
{
    if instance.config.trace_opts.events {
        Debug::<V>::NbrTimeout(&addr).log();
    }
    instance.state.neighbors.remove(&addr);
}

// ===== route timeout =====

pub(crate) fn process_route_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Interfaces<V>,
    prefix: V::IpNetwork,
) where
    V: Version,
{
    let route = match instance.state.routes.get_mut(&prefix) {
        Some(route) => route,
        None => return,
    };

    if let Some((_, iface)) = interfaces.get_by_ifindex(route.ifindex) {
        if instance.config.trace_opts.route {
            Debug::<V>::RouteTimeout(&prefix).log();
        }

        route.invalidate(
            iface.config.flush_interval,
            instance.tx,
            &instance.config.trace_opts,
        );
    }
}

// ===== route garbage-collection timeout =====

pub(crate) fn process_route_gc_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    prefix: V::IpNetwork,
) where
    V: Version,
{
    let route = match instance.state.routes.get_mut(&prefix) {
        Some(route) => route,
        None => return,
    };
    if route.garbage_collect_task.is_none() {
        return;
    }

    if instance.config.trace_opts.route {
        Debug::<V>::RouteGcTimeout(&prefix).log();
    }
    instance.state.routes.remove(&prefix);
}
