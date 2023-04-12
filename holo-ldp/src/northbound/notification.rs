//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::IpAddr;

use holo_northbound::{notification, paths, NbProviderSender};

use crate::fec::Fec;
use crate::neighbor::Neighbor;

pub(crate) fn mpls_ldp_peer_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    nbr: &Neighbor,
) {
    use paths::mpls_ldp_peer_event as base;

    let event_type = if nbr.is_operational() { "up" } else { "down" };
    let lsr_id = nbr.lsr_id.to_string();

    let args = [
        (base::event_type::PATH, Some(event_type)),
        (base::peer::protocol_name::PATH, Some(instance_name)),
        (base::peer::lsr_id::PATH, Some(&lsr_id)),
    ];
    notification::send(nb_tx, base::PATH, &args);
}

pub(crate) fn mpls_ldp_hello_adjacency_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    ifname: Option<&str>,
    addr: &IpAddr,
    created: bool,
) {
    use paths::mpls_ldp_hello_adjacency_event as base;

    let event_type = if created { "up" } else { "down" };
    let addr_str = addr.to_string();

    let mut args = vec![];
    args.push((base::event_type::PATH, Some(event_type)));
    args.push((base::protocol_name::PATH, Some(instance_name)));
    if let Some(ifname) = ifname {
        args.push((base::link::next_hop_interface::PATH, Some(ifname)));
        args.push((base::link::next_hop_address::PATH, Some(&addr_str)));
    } else {
        args.push((base::targeted::target_address::PATH, Some(&addr_str)));
    }
    notification::send(nb_tx, base::PATH, &args);
}

pub(crate) fn mpls_ldp_fec_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    fec: &Fec,
) {
    use paths::mpls_ldp_fec_event as base;

    let event_type = if fec.is_operational() { "up" } else { "down" };
    let fec_str = fec.inner.prefix.to_string();

    let args = [
        (base::event_type::PATH, Some(event_type)),
        (base::protocol_name::PATH, Some(instance_name)),
        (base::fec::PATH, Some(&fec_str)),
    ];
    notification::send(nb_tx, base::PATH, &args);
}
