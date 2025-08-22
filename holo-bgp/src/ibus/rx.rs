//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

use holo_utils::bgp::RouteType;
use holo_utils::ip::IpNetworkExt;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{RouteKeyMsg, RouteMsg};
use ipnetwork::IpNetwork;

use crate::af::{AddressFamily, Ipv4Unicast, Ipv6Unicast};
use crate::debug::Debug;
use crate::instance::{Instance, InstanceUpView};
use crate::policy::RoutePolicyInfo;
use crate::rib::RouteOrigin;
use crate::tasks::messages::output::PolicyApplyMsg;

// ===== global functions =====

pub(crate) fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;
    instance.update();
}

pub(crate) fn process_nht_update(
    instance: &mut Instance,
    addr: IpAddr,
    metric: Option<u32>,
) {
    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    if instance.config.trace_opts.nht {
        Debug::NhtUpdate(addr, metric).log();
    }

    process_nht_update_af::<Ipv4Unicast>(&mut instance, addr, metric);
    process_nht_update_af::<Ipv6Unicast>(&mut instance, addr, metric);
}

pub(crate) fn process_route_add(instance: &mut Instance, msg: RouteMsg) {
    if !msg.prefix.is_routable() {
        return;
    }

    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    match msg.prefix {
        IpNetwork::V4(..) => {
            process_route_add_af::<Ipv4Unicast>(&mut instance, msg);
        }
        IpNetwork::V6(..) => {
            process_route_add_af::<Ipv6Unicast>(&mut instance, msg);
        }
    }
}

pub(crate) fn process_route_del(instance: &mut Instance, msg: RouteKeyMsg) {
    if !msg.prefix.is_routable() {
        return;
    }

    let Some((mut instance, _)) = instance.as_up() else {
        return;
    };

    let proto = msg.protocol;
    match msg.prefix {
        IpNetwork::V4(prefix) => {
            process_route_del_af::<Ipv4Unicast>(&mut instance, prefix, proto);
        }
        IpNetwork::V6(prefix) => {
            process_route_del_af::<Ipv6Unicast>(&mut instance, prefix, proto);
        }
    }
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

fn process_route_add_af<A>(instance: &mut InstanceUpView<'_>, msg: RouteMsg)
where
    A: AddressFamily,
{
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

    // Get policy configuration for the address family.
    let apply_policy_cfg = &instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .map(|afi_safi| &afi_safi.apply_policy)
        .unwrap_or(&instance.config.apply_policy);

    // Enqueue import policy application.
    let msg = PolicyApplyMsg::Redistribute {
        afi_safi: A::AFI_SAFI,
        prefix: msg.prefix,
        route: RoutePolicyInfo::new(
            RouteOrigin::Protocol(msg.protocol),
            RouteType::Internal,
            msg.tag,
            Some(msg.opaque_attrs),
            Default::default(),
        ),
        policies: apply_policy_cfg
            .import_policy
            .iter()
            .map(|policy| instance.shared.policies.get(policy).unwrap().clone())
            .collect(),
        match_sets: instance.shared.policy_match_sets.clone(),
        default_policy: apply_policy_cfg.default_import_policy,
    };
    instance.state.policy_apply_tasks.enqueue(msg);
}

fn process_route_del_af<A>(
    instance: &mut InstanceUpView<'_>,
    prefix: A::IpNetwork,
    protocol: Protocol,
) where
    A: AddressFamily,
{
    // Check if redistribution is enabled for this address family and route
    // protocol.
    if instance
        .config
        .afi_safi
        .get(&A::AFI_SAFI)
        .and_then(|afi_safi| afi_safi.redistribution.get(&protocol))
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
