//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use holo_northbound::{notification, paths, NbProviderSender};

use crate::fec::Fec;
use crate::neighbor::Neighbor;

// ===== global functions =====

pub(crate) fn mpls_ldp_peer_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    nbr: &Neighbor,
) {
    use paths::mpls_ldp_peer_event::peer::Peer;
    use paths::mpls_ldp_peer_event::{self, MplsLdpPeerEvent};

    let event_type = event_type(nbr.is_operational());
    let data = MplsLdpPeerEvent {
        event_type: Some(event_type.into()),
        peer: Some(Peer {
            protocol_name: Some(instance_name.into()),
            lsr_id: Some(nbr.lsr_id.to_string().into()),
            label_space_id: None,
        }),
    };
    notification::send(nb_tx, mpls_ldp_peer_event::PATH, data);
}

pub(crate) fn mpls_ldp_hello_adjacency_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    ifname: Option<&str>,
    addr: &IpAddr,
    created: bool,
) {
    use paths::mpls_ldp_hello_adjacency_event::link::Link;
    use paths::mpls_ldp_hello_adjacency_event::targeted::Targeted;
    use paths::mpls_ldp_hello_adjacency_event::{
        self, MplsLdpHelloAdjacencyEvent,
    };

    let event_type = event_type(created);
    let data = MplsLdpHelloAdjacencyEvent {
        protocol_name: Some(instance_name.into()),
        event_type: Some(event_type.into()),
        targeted: ifname.is_none().then_some(Targeted {
            target_address: Some(addr.to_string().into()),
        }),
        link: ifname.map(|ifname| Link {
            next_hop_interface: Some(ifname.into()),
            next_hop_address: Some(addr.to_string().into()),
        }),
    };
    notification::send(nb_tx, mpls_ldp_hello_adjacency_event::PATH, data);
}

pub(crate) fn mpls_ldp_fec_event(
    nb_tx: &NbProviderSender,
    instance_name: &str,
    fec: &Fec,
) {
    use paths::mpls_ldp_fec_event::{self, MplsLdpFecEvent};

    let event_type = event_type(fec.is_operational());
    let data = MplsLdpFecEvent {
        event_type: Some(event_type.into()),
        protocol_name: Some(instance_name.into()),
        fec: Some(fec.inner.prefix.to_string().into()),
    };
    notification::send(nb_tx, mpls_ldp_fec_event::PATH, data);
}

// ===== helper functions =====

fn event_type(up: bool) -> &'static str {
    if up {
        "up"
    } else {
        "down"
    }
}
