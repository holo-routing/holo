//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;

use holo_northbound::{notification, paths};
use holo_yang::ToYang;

use crate::error::InterfaceCfgError;
use crate::gr::GrExitReason;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::neighbor::Neighbor;
use crate::packet::error::LsaValidationError;
use crate::packet::PacketType;
use crate::version::Version;

// ===== global functions =====

pub(crate) fn if_state_change<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
) where
    V: Version,
{
    use paths::if_state_change as base;

    let af = instance.state.af.to_yang();
    let state = iface.state.ism_state.to_yang();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(&iface.name)),
        (base::state::PATH, Some(&state)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn if_config_error<V>(
    instance: &InstanceUpView<'_, V>,
    ifname: &str,
    src: &V::NetIpAddr,
    pkt_type: &PacketType,
    error: &InterfaceCfgError,
) where
    V: Version,
{
    use paths::if_config_error as base;

    let af = instance.state.af.to_yang();
    let src = src.to_string();
    let pkt_type = pkt_type.to_yang();
    let error = error.to_yang();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(ifname)),
        (base::packet_source::PATH, Some(&src)),
        (base::packet_type::PATH, Some(&pkt_type)),
        (base::error::PATH, Some(&error)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn nbr_state_change<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
) where
    V: Version,
{
    use paths::nbr_state_change as base;

    let af = instance.state.af.to_yang();
    let nbr_router_id = nbr.router_id.to_string();
    let nbr_addr = nbr.src.to_string();
    let state = nbr.state.to_yang();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(&iface.name)),
        (base::neighbor_router_id::PATH, Some(&nbr_router_id)),
        (base::neighbor_ip_addr::PATH, Some(&nbr_addr)),
        (base::state::PATH, Some(&state)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn nbr_restart_helper_enter<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
    age: u32,
) where
    V: Version,
{
    use paths::nbr_restart_helper_status_change as base;

    let af = instance.state.af.to_yang();
    let nbr_router_id = nbr.router_id.to_string();
    let nbr_addr = nbr.src.to_string();
    let age = age.to_string();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(&iface.name)),
        (base::neighbor_router_id::PATH, Some(&nbr_router_id)),
        (base::neighbor_ip_addr::PATH, Some(&nbr_addr)),
        (base::status::PATH, Some("helping")),
        (base::age::PATH, Some(&age)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn nbr_restart_helper_exit<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    nbr: &Neighbor<V>,
    reason: GrExitReason,
) where
    V: Version,
{
    use paths::nbr_restart_helper_status_change as base;

    let af = instance.state.af.to_yang();
    let nbr_router_id = nbr.router_id.to_string();
    let nbr_addr = nbr.src.to_string();
    let reason = reason.to_yang();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(&iface.name)),
        (base::neighbor_router_id::PATH, Some(&nbr_router_id)),
        (base::neighbor_ip_addr::PATH, Some(&nbr_addr)),
        (base::status::PATH, Some("not-helping")),
        (base::exit_reason::PATH, Some(&reason)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn if_rx_bad_packet<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    src: V::NetIpAddr,
) where
    V: Version,
{
    use paths::if_rx_bad_packet as base;

    let af = instance.state.af.to_yang();
    let src = src.to_string();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::address_family::PATH, Some(&af)),
        (base::interface::interface::PATH, Some(&iface.name)),
        (base::packet_source::PATH, Some(&src)),
        // TODO: set the packet-type whenever possible.
        //(base::packet_type::PATH, None),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn if_rx_bad_lsa<V>(
    instance: &InstanceUpView<'_, V>,
    src: V::NetIpAddr,
    error: LsaValidationError,
) where
    V: Version,
{
    use paths::if_rx_bad_lsa as base;

    let src = src.to_string();
    let error = error.to_yang();

    let args = [
        (base::routing_protocol_name::PATH, Some(instance.name)),
        (base::packet_source::PATH, Some(&src)),
        (base::error::PATH, Some(&error)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}

pub(crate) fn sr_index_out_of_range<V>(
    instance: &InstanceUpView<'_, V>,
    nbr_router_id: Ipv4Addr,
    index: u32,
) where
    V: Version,
{
    use paths::segment_routing_index_out_of_range as base;

    let nbr_router_id = nbr_router_id.to_string();
    let index = index.to_string();

    let args = [
        (base::routing_protocol::PATH, Some(instance.name)),
        (base::received_target::PATH, Some(&nbr_router_id)),
        (base::received_index::PATH, Some(&index)),
    ];
    notification::send(&instance.tx.nb, base::PATH, &args);
}
