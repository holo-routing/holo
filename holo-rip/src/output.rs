//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::time::Duration;

use itertools::Itertools;
use rand::Rng;

use crate::debug::Debug;
use crate::instance::{InstanceState, InstanceUp};
use crate::interface::{Interface, InterfaceUp, SplitHorizon};
use crate::network::SendDestination;
use crate::packet::{Command, PduVersion, RteVersion};
use crate::route::{RouteFlags, RouteType};
use crate::tasks;
use crate::tasks::messages::output::UdpTxPduMsg;
use crate::version::Version;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseType {
    Normal,
    Triggered,
}

// ===== global functions =====

pub(crate) fn send_pdu<V>(
    instance_state: &mut InstanceState<V>,
    iface: &mut InterfaceUp<V>,
    dst: SendDestination<V::IpAddr, V::SocketAddr>,
    pdu: V::Pdu,
) where
    V: Version,
{
    Debug::<V>::PduTx(iface, &pdu).log();

    // Update instance statistics.
    instance_state.statistics.update(pdu.command(), true);

    // Update interface statistics.
    if pdu.command() == Command::Response {
        iface.state.statistics.updates_sent += 1;
        iface.state.statistics.update_discontinuity_time();
    }

    // Send packet.
    let _ = instance_state.udp_tx_pdup.send(UdpTxPduMsg { dst, pdu });
}

pub(crate) fn send_request<V>(
    instance_state: &mut InstanceState<V>,
    iface: &mut InterfaceUp<V>,
    dst: SendDestination<V::IpAddr, V::SocketAddr>,
) where
    V: Version,
{
    // Do not send RIP packets on passive interfaces.
    if iface.is_passive() {
        return;
    }

    // Send request to send the entire routing table.
    let pdu = V::Pdu::new_dump_request();
    send_pdu(instance_state, iface, dst, pdu);
}

pub(crate) fn send_response<V>(
    instance_state: &mut InstanceState<V>,
    iface: &mut InterfaceUp<V>,
    dst: SendDestination<V::IpAddr, V::SocketAddr>,
    response_type: ResponseType,
) where
    V: Version,
{
    // Do not send RIP packets on passive interfaces.
    if iface.is_passive() {
        return;
    }

    // Build Response PDU.
    let mut rtes = vec![];
    for route in instance_state.routes.values() {
        let mut metric = route.metric;

        // Skip unchanged routes for triggered updates.
        if response_type == ResponseType::Triggered
            && !route.flags.contains(RouteFlags::CHANGED)
        {
            continue;
        }

        // Split-horizon processing.
        if route.route_type == RouteType::Rip {
            let suppress = route.ifindex == iface.core.system.ifindex.unwrap();

            match iface.core.config.split_horizon {
                SplitHorizon::Disabled => (),
                SplitHorizon::Simple => {
                    if suppress {
                        continue;
                    }
                }
                SplitHorizon::PoisonReverse => {
                    if suppress {
                        metric.set_infinite()
                    }
                }
            }
        }

        // Append RTE.
        let rte = <V::Pdu as PduVersion<_, _, _>>::Rte::new_route(
            route.prefix,
            None,
            metric,
            route.tag,
        );
        rtes.push(rte);
    }

    // Nothing to send.
    if rtes.is_empty() {
        return;
    }

    // Send as many PDUs as necessary.
    for rtes in rtes
        .into_iter()
        .chunks(V::Pdu::max_entries(iface.core.system.mtu.unwrap()))
        .into_iter()
        .map(|c| c.collect())
    {
        let pdu = V::Pdu::new(Command::Response, rtes);
        send_pdu(instance_state, iface, dst, pdu);
    }
}

pub(crate) fn send_response_all<V>(
    instance: &mut InstanceUp<V>,
    response_type: ResponseType,
) where
    V: Version,
{
    for iface in instance.core.interfaces.iter_mut() {
        if let Interface::Up(iface) = iface {
            iface.with_destinations(|iface, dst| {
                send_response(&mut instance.state, iface, dst, response_type);
            })
        }
    }

    // A triggered update should be suppressed if a regular update is due by the
    // time the triggered update would be sent.
    cancel_triggered_update(instance);

    // Clear the route change flags.
    for route in instance.state.routes.values_mut() {
        route.flags.remove(RouteFlags::CHANGED);
    }
}

pub(crate) fn triggered_update<V>(instance: &mut InstanceUp<V>)
where
    V: Version,
{
    Debug::<V>::TriggeredUpdate.log();

    // Send routes.
    send_response_all(instance, ResponseType::Triggered);

    // Start triggered update timeout.
    let timeout = rand::thread_rng()
        .gen_range(1..instance.core.config.triggered_update_threshold);
    let triggered_upd_timeout_task = tasks::triggered_upd_timeout(
        Duration::from_secs(timeout.into()),
        &instance.tx.protocol_input.triggered_upd_timeout,
    );
    instance.state.triggered_upd_timeout_task =
        Some(triggered_upd_timeout_task);
}

pub(crate) fn cancel_triggered_update<V>(instance: &mut InstanceUp<V>)
where
    V: Version,
{
    instance.state.triggered_upd_timeout_task = None;
    instance.state.pending_trigger_upd = false;
}
