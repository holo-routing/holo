//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::{LazyLock as Lazy, atomic};

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, Provider,
};
use holo_northbound::yang::control_plane_protocol::mpls_ldp;
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use holo_utils::mpls::Label;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_yang::ToYang;
use ipnetwork::Ipv4Network;

use crate::discovery::Adjacency;
use crate::fec::Fec;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::neighbor::{LabelAdvMode, LabelDistMode, Neighbor, NeighborFlags};

pub static CALLBACKS: Lazy<Callbacks<Instance>> = Lazy::new(load_callbacks);

#[derive(Debug, Default, EnumAsInner)]
pub enum ListEntry<'a> {
    #[default]
    None,
    AddrBinding(AddrBinding),
    LabelBinding(LabelBinding),
    Fec(&'a Fec),
    Interface(&'a Interface),
    InterfaceAdj(&'a Adjacency),
    TargetedNbrAdj(&'a Adjacency),
    Neighbor(&'a Neighbor),
    NeighborAdj(&'a Adjacency),
}

#[derive(Debug, new)]
pub struct AddrBinding {
    addr: Ipv4Addr,
    adv_type: AdvertisementType,
    lsr_id: Option<Ipv4Addr>,
}

#[derive(Debug, new)]
pub struct LabelBinding {
    lsr_id: Ipv4Addr,
    adv_type: AdvertisementType,
    label: Label,
    used_in_fwd: bool,
}

#[derive(Debug)]
pub enum AdvertisementType {
    Advertised,
    Received,
}

// ===== callbacks =====

fn load_callbacks() -> Callbacks<Instance> {
    CallbacksBuilder::<Instance>::default()
        .path(mpls_ldp::global::address_families::ipv4::PATH)
        .get_object(|_instance, _args| {
            use mpls_ldp::global::address_families::ipv4::Ipv4;
            Box::new(Ipv4 {
                label_distribution_control_mode: Some(LabelDistMode::Independent.to_yang()),
            })
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };

            // Skip if there's no neighbor in the operational state.
            if !instance_state.neighbors.iter().any(|nbr| nbr.is_operational()) {
                return None;
            }

            // Advertised addresses.
            let advertised = instance.system.ipv4_addr_list.iter().map(|addr| {
                let binding = AddrBinding::new(addr.ip(), AdvertisementType::Advertised, None);
                ListEntry::AddrBinding(binding)
            });

            // Received addresses.
            let received = instance_state.neighbors.iter().flat_map(|nbr| {
                nbr.addr_list.iter().filter_map(move |addr| {
                    Ipv4Addr::get(*addr).map(|addr| {
                        let binding = AddrBinding::new(addr, AdvertisementType::Received, Some(nbr.lsr_id));
                        ListEntry::AddrBinding(binding)
                    })
                })
            });

            // Chain advertised and received addresses.
            Some(Box::new(advertised.chain(received)))
        })
        .get_object(|_instance, args| {
            use mpls_ldp::global::address_families::ipv4::bindings::address::Address;
            let binding = args.list_entry.as_addr_binding().unwrap();
            Box::new(Address {
                address: Cow::Owned(binding.addr),
                advertisement_type: Some(binding.adv_type.to_yang()),
            })
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::peer::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::global::address_families::ipv4::bindings::address::peer::Peer;
            let binding = args.list_entry.as_addr_binding().unwrap();
            Box::new(Peer {
                lsr_id: binding.lsr_id.map(Cow::Owned),
                label_space_id: binding.lsr_id.map(|_lsr_id| 0),
            })
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.fecs.values().filter(|fec| fec.inner.prefix.is_ipv4()).filter(|fec| !fec.inner.upstream.is_empty() || !fec.inner.downstream.is_empty()).map(ListEntry::Fec);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use mpls_ldp::global::address_families::ipv4::bindings::fec_label::FecLabel;
            let fec = args.list_entry.as_fec().unwrap();
            Box::new(FecLabel {
                fec: Cow::Owned(Ipv4Network::get(*fec.inner.prefix).unwrap()),
            })
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::PATH)
        .get_iterate(|instance, args| {
            let fec = args.parent_list_entry.as_fec().unwrap();

            // Advertised label mappings.
            let advertised = fec.inner.upstream.iter().map(|(lsr_id, mapping)| {
                let binding = LabelBinding::new(*lsr_id, AdvertisementType::Advertised, mapping.label, true);
                ListEntry::LabelBinding(binding)
            });

            // Received label mappings.
            let received = fec.inner.downstream.iter().filter_map(|(lsr_id, mapping)| {
                instance.state.as_ref().unwrap().neighbors.get_by_lsr_id(lsr_id).map(|(_, nbr)| {
                    let binding = LabelBinding::new(*lsr_id, AdvertisementType::Received, mapping.label, fec.is_nbr_nexthop(nbr));
                    ListEntry::LabelBinding(binding)
                })
            });

            // Chain advertised and received label mappings.
            Some(Box::new(advertised.chain(received)))
        })
        .get_object(|_instance, args| {
            use mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::Peer;
            let binding = args.list_entry.as_label_binding().unwrap();
            Box::new(Peer {
                lsr_id: Cow::Owned(binding.lsr_id),
                label_space_id: 0,
                advertisement_type: binding.adv_type.to_yang(),
                label: Some(binding.label.to_yang()),
                used_in_forwarding: Some(binding.used_in_fwd),
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            if !instance.is_active() {
                return None;
            }
            let iter = instance.interfaces.iter().filter(|iface| iface.is_active()).map(ListEntry::Interface);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::interfaces::interface::Interface;
            let iface = args.list_entry.as_interface().unwrap();
            Box::new(Interface {
                name: iface.name.as_str().into(),
                next_hello: iface.next_hello().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, args| {
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_iface(&iface.name).into_iter().flatten().map(ListEntry::InterfaceAdj);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency;
            let adj = args.list_entry.as_interface_adj().unwrap();
            let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
            Box::new(HelloAdjacency {
                adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
                next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime;
            let adj = args.list_entry.as_interface_adj().unwrap();
            Box::new(HelloHoldtime {
                adjacent: Some(adj.holdtime_adjacent),
                negotiated: Some(adj.holdtime_negotiated),
                remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics;
            let adj = args.list_entry.as_interface_adj().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)).ignore_in_testing(),
                hello_received: Some(adj.hello_rcvd).ignore_in_testing(),
                hello_dropped: Some(adj.hello_dropped).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer;
            let adj = args.list_entry.as_interface_adj().unwrap();
            Box::new(Peer {
                lsr_id: Some(Cow::Owned(adj.lsr_id)),
                label_space_id: Some(0),
            })
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.ipv4.adjacencies.iter().filter(|adj| adj.source.ifname.is_none()).map(ListEntry::TargetedNbrAdj);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency;
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
            Box::new(HelloAdjacency {
                local_address: Cow::Owned(Ipv4Addr::get(adj.local_addr).unwrap()),
                adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
                next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime;
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Box::new(HelloHoldtime {
                adjacent: Some(adj.holdtime_adjacent),
                negotiated: Some(adj.holdtime_negotiated),
                remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics;
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)).ignore_in_testing(),
                hello_received: Some(adj.hello_rcvd).ignore_in_testing(),
                hello_dropped: Some(adj.hello_dropped).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer;
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Box::new(Peer {
                lsr_id: Some(Cow::Owned(adj.lsr_id)),
                label_space_id: Some(0),
            })
        })
        .path(mpls_ldp::peers::peer::PATH)
        .get_iterate(|instance, _args| {
            let Some(instance_state) = &instance.state else { return None };
            let iter = instance_state.neighbors.iter().map(ListEntry::Neighbor);
            Some(Box::new(iter))
        })
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::Peer;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(Peer {
                lsr_id: Cow::Owned(nbr.lsr_id),
                label_space_id: 0,
                next_keep_alive: nbr.next_kalive().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
                session_state: Some(nbr.state.to_yang()),
                up_time: nbr.uptime.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, args| {
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_lsr_id(&nbr.lsr_id).into_iter().flatten().map(ListEntry::NeighborAdj);
            Some(Box::new(iter))
        })
        .get_object(|instance, args| {
            use mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency;
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
            Box::new(HelloAdjacency {
                local_address: Cow::Owned(Ipv4Addr::get(adj.local_addr).unwrap()),
                adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
                next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime;
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Box::new(HelloHoldtime {
                adjacent: Some(adj.holdtime_adjacent),
                negotiated: Some(adj.holdtime_negotiated),
                remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics;
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Box::new(Statistics {
                discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)).ignore_in_testing(),
                hello_received: Some(adj.hello_rcvd).ignore_in_testing(),
                hello_dropped: Some(adj.hello_dropped).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::label_advertisement_mode::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::label_advertisement_mode::LabelAdvertisementMode;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(LabelAdvertisementMode {
                local: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited.to_yang()),
                peer: nbr.rcvd_label_adv_mode.as_ref().map(|mode| mode.to_yang()),
                negotiated: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited.to_yang()),
            })
        })
        .path(mpls_ldp::peers::peer::received_peer_state::capability::end_of_lib::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::received_peer_state::capability::end_of_lib::EndOfLib;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(EndOfLib {
                enabled: Some(nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF)),
            })
        })
        .path(mpls_ldp::peers::peer::received_peer_state::capability::typed_wildcard_fec::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::received_peer_state::capability::typed_wildcard_fec::TypedWildcardFec;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(TypedWildcardFec {
                enabled: Some(nbr.flags.contains(NeighborFlags::CAP_TYPED_WCARD)),
            })
        })
        .path(mpls_ldp::peers::peer::session_holdtime::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::session_holdtime::SessionHoldtime;
            let nbr = args.list_entry.as_neighbor().unwrap();
            Box::new(SessionHoldtime {
                peer: nbr.kalive_holdtime_rcvd,
                negotiated: nbr.kalive_holdtime_negotiated,
                remaining: nbr.kalive_timeout_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::tcp_connection::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::tcp_connection::TcpConnection;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let mut local_address = None;
            let mut local_port = None;
            let mut remote_address = None;
            let mut remote_port = None;
            if let Some(conn_info) = &nbr.conn_info {
                local_address = Some(Cow::Borrowed(&conn_info.local_addr));
                local_port = Some(conn_info.local_port);
                remote_address = Some(Cow::Borrowed(&conn_info.remote_addr));
                remote_port = Some(conn_info.remote_port);
            }
            Box::new(TcpConnection {
                local_address,
                local_port: local_port.ignore_in_testing(),
                remote_address,
                remote_port: remote_port.ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::statistics::PATH)
        .get_object(|instance, args| {
            use mpls_ldp::peers::peer::statistics::Statistics;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total_addresses = nbr.addr_list.len();
            let total_labels = nbr.rcvd_mappings.len();
            let total_fec_label_bindings = nbr.rcvd_mappings.keys().map(|prefix| instance.state.as_ref().unwrap().fecs.get(prefix).unwrap()).filter(|fec| fec.is_nbr_nexthop(nbr)).count();
            Box::new(Statistics {
                discontinuity_time: nbr.statistics.discontinuity_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
                total_addresses: Some(total_addresses.saturating_into()),
                total_labels: Some(total_labels.saturating_into()),
                total_fec_label_bindings: Some(total_fec_label_bindings.saturating_into()),
            })
        })
        .path(mpls_ldp::peers::peer::statistics::received::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::statistics::received::Received;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let msgs = &nbr.statistics.msgs_rcvd;
            Box::new(Received {
                total_octets: Some(msgs.total_bytes).ignore_in_testing(),
                total_messages: Some(msgs.total).ignore_in_testing(),
                address: Some(msgs.address).ignore_in_testing(),
                address_withdraw: Some(msgs.address_withdraw).ignore_in_testing(),
                initialization: Some(msgs.initialization).ignore_in_testing(),
                keepalive: Some(msgs.keepalive.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                label_abort_request: Some(msgs.label_abort_request).ignore_in_testing(),
                label_mapping: Some(msgs.label_mapping).ignore_in_testing(),
                label_release: Some(msgs.label_release).ignore_in_testing(),
                label_request: Some(msgs.label_request).ignore_in_testing(),
                label_withdraw: Some(msgs.label_withdraw).ignore_in_testing(),
                notification: Some(msgs.notification).ignore_in_testing(),
            })
        })
        .path(mpls_ldp::peers::peer::statistics::sent::PATH)
        .get_object(|_instance, args| {
            use mpls_ldp::peers::peer::statistics::sent::Sent;
            let nbr = args.list_entry.as_neighbor().unwrap();
            let msgs = &nbr.statistics.msgs_sent;
            Box::new(Sent {
                total_octets: Some(msgs.total_bytes).ignore_in_testing(),
                total_messages: Some(msgs.total).ignore_in_testing(),
                address: Some(msgs.address).ignore_in_testing(),
                address_withdraw: Some(msgs.address_withdraw).ignore_in_testing(),
                initialization: Some(msgs.initialization).ignore_in_testing(),
                keepalive: Some(msgs.keepalive.load(atomic::Ordering::Relaxed)).ignore_in_testing(),
                label_abort_request: Some(msgs.label_abort_request).ignore_in_testing(),
                label_mapping: Some(msgs.label_mapping).ignore_in_testing(),
                label_release: Some(msgs.label_release).ignore_in_testing(),
                label_request: Some(msgs.label_request).ignore_in_testing(),
                label_withdraw: Some(msgs.label_withdraw).ignore_in_testing(),
                notification: Some(msgs.notification).ignore_in_testing(),
            })
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> &'static Callbacks<Instance> {
        &CALLBACKS
    }
}

// ===== impl ListEntry =====

impl ListEntryKind for ListEntry<'_> {}
