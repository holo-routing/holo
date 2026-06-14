//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::atomic;

use derive_new::new;
use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use holo_utils::mpls::Label;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;
use holo_yang::types::Timeticks64;
use ipnetwork::Ipv4Network;

use crate::discovery::Adjacency;
use crate::fec::Fec;
use crate::instance::Instance;
use crate::interface::Interface;
use crate::neighbor::{LabelAdvMode, LabelDistMode, Neighbor, NeighborFlags};
use crate::northbound::yang_gen::{self, mpls_ldp};

impl Provider for Instance {
    type ListEntry<'a> = yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-mpls-ldp:mpls-ldp",
            Protocol::LDP.to_yang(),
            self.name
        )
    }
}

#[derive(Debug)]
#[derive(new)]
pub struct AddrBinding {
    addr: Ipv4Addr,
    adv_type: AdvertisementType,
    lsr_id: Option<Ipv4Addr>,
}

#[derive(Debug)]
#[derive(new)]
pub struct LabelBinding {
    lsr_id: Ipv4Addr,
    adv_type: AdvertisementType,
    label: Label,
    used_in_fwd: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum AdvertisementType {
    Advertised,
    Received,
}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for mpls_ldp::global::address_families::ipv4::Ipv4<'a> {
    type ParentListEntry = ();

    fn new(_instance: &'a Instance, _: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            label_distribution_control_mode: Some(LabelDistMode::Independent.to_yang()),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::address::Address {
    type ParentListEntry = ();
    type ListEntry = AddrBinding;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let neighbors = &instance.state.as_ref()?.neighbors;

        // Skip if there's no neighbor in the operational state.
        if !neighbors.iter().any(|nbr| nbr.is_operational()) {
            return None;
        }

        // Advertised addresses.
        let advertised = instance.system.ipv4_addr_list.iter().map(|addr| AddrBinding::new(addr.ip(), AdvertisementType::Advertised, None));

        // Received addresses.
        let received = neighbors.iter().flat_map(|nbr| {
            nbr.addr_list
                .iter()
                .filter_map(move |addr| Ipv4Addr::get(*addr).map(|addr| AddrBinding::new(addr, AdvertisementType::Received, Some(nbr.lsr_id))))
        });

        // Chain advertised and received addresses.
        let iter = advertised.chain(received);
        Some(iter)
    }

    fn new(_instance: &'a Instance, binding: &Self::ListEntry) -> Self {
        Self {
            address: binding.addr,
            advertisement_type: Some(binding.adv_type),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::address::peer::Peer {
    type ParentListEntry = AddrBinding;

    fn new(_instance: &'a Instance, binding: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            lsr_id: binding.lsr_id,
            label_space_id: binding.lsr_id.map(|_lsr_id| 0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::fec_label::FecLabel {
    type ParentListEntry = ();
    type ListEntry = &'a Fec;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let fecs = &instance.state.as_ref()?.fecs;
        let iter = fecs.values().filter(|fec| fec.inner.prefix.is_ipv4()).filter(|fec| !fec.inner.upstream.is_empty() || !fec.inner.downstream.is_empty());
        Some(iter)
    }

    fn new(_instance: &'a Instance, fec: &Self::ListEntry) -> Self {
        Self {
            fec: Ipv4Network::get(*fec.inner.prefix).unwrap(),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::Peer<'a> {
    type ParentListEntry = &'a Fec;
    type ListEntry = LabelBinding;

    fn iter(instance: &'a Instance, &fec: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        // Advertised label mappings.
        let advertised = fec.inner.upstream.iter().map(|(lsr_id, mapping)| LabelBinding::new(*lsr_id, AdvertisementType::Advertised, mapping.label, true));

        // Received label mappings.
        let received = fec.inner.downstream.iter().filter_map(move |(lsr_id, mapping)| {
            instance
                .state
                .as_ref()
                .unwrap()
                .neighbors
                .get_by_lsr_id(lsr_id)
                .map(|(_, nbr)| LabelBinding::new(*lsr_id, AdvertisementType::Received, mapping.label, fec.is_nbr_nexthop(nbr)))
        });

        // Chain advertised and received label mappings.
        let iter = advertised.chain(received);
        Some(iter)
    }

    fn new(_instance: &'a Instance, binding: &Self::ListEntry) -> Self {
        Self {
            lsr_id: binding.lsr_id,
            label_space_id: 0,
            advertisement_type: binding.adv_type,
            label: Some(binding.label.to_yang()),
            used_in_forwarding: Some(binding.used_in_fwd),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::interfaces::interface::Interface<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Interface;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        if !instance.is_active() {
            return None;
        }
        let iter = instance.interfaces.iter().filter(|iface| iface.is_active());
        Some(iter)
    }

    fn new(_instance: &'a Instance, iface: &Self::ListEntry) -> Self {
        Self {
            name: Cow::Borrowed(&iface.name),
            next_hello: iface.next_hello().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency {
    type ParentListEntry = &'a Interface;
    type ListEntry = &'a Adjacency;

    fn iter(instance: &'a Instance, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_iface(&iface.name).into_iter().flatten();
        Some(iter)
    }

    fn new(instance: &'a Instance, adj: &Self::ListEntry) -> Self {
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            adjacent_address: Ipv4Addr::get(adj.source.addr).unwrap(),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(adj.discontinuity_time),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            lsr_id: Some(adj.lsr_id),
            label_space_id: Some(0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency {
    type ParentListEntry = ();
    type ListEntry = &'a Adjacency;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let adjacencies = &instance.state.as_ref()?.ipv4.adjacencies;
        let iter = adjacencies.iter().filter(|adj| adj.source.ifname.is_none());
        Some(iter)
    }

    fn new(instance: &'a Instance, adj: &Self::ListEntry) -> Self {
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            local_address: Ipv4Addr::get(adj.local_addr).unwrap(),
            adjacent_address: Ipv4Addr::get(adj.source.addr).unwrap(),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(adj.discontinuity_time),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            lsr_id: Some(adj.lsr_id),
            label_space_id: Some(0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::peers::peer::Peer<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a Neighbor;

    fn iter(instance: &'a Instance, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance, nbr: &Self::ListEntry) -> Self {
        Self {
            lsr_id: nbr.lsr_id,
            label_space_id: 0,
            next_keep_alive: nbr.next_kalive().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            session_state: Some(nbr.state.to_yang()),
            up_time: nbr.uptime.map(Timeticks64).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency {
    type ParentListEntry = &'a Neighbor;
    type ListEntry = &'a Adjacency;

    fn iter(instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_lsr_id(&nbr.lsr_id).into_iter().flatten();
        Some(iter)
    }

    fn new(instance: &'a Instance, adj: &Self::ListEntry) -> Self {
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            local_address: Ipv4Addr::get(adj.local_addr).unwrap(),
            adjacent_address: Ipv4Addr::get(adj.source.addr).unwrap(),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics {
    type ParentListEntry = &'a Adjacency;

    fn new(_instance: &'a Instance, adj: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(adj.discontinuity_time),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::label_advertisement_mode::LabelAdvertisementMode {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            local: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited),
            peer: nbr.rcvd_label_adv_mode,
            negotiated: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::received_peer_state::capability::end_of_lib::EndOfLib {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            enabled: Some(nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::received_peer_state::capability::typed_wildcard_fec::TypedWildcardFec {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            enabled: Some(nbr.flags.contains(NeighborFlags::CAP_TYPED_WCARD)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::session_holdtime::SessionHoldtime {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            peer: nbr.kalive_holdtime_rcvd,
            negotiated: nbr.kalive_holdtime_negotiated,
            remaining: nbr.kalive_timeout_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::tcp_connection::TcpConnection {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let conn_info = nbr.conn_info.as_ref()?;
        Some(Self {
            local_address: Some(conn_info.local_addr),
            local_port: Some(conn_info.local_port).ignore_in_testing(),
            remote_address: Some(conn_info.remote_addr),
            remote_port: Some(conn_info.remote_port).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::statistics::Statistics {
    type ParentListEntry = &'a Neighbor;

    fn new(instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let total_addresses = nbr.addr_list.len();
        let total_labels = nbr.rcvd_mappings.len();
        let total_fec_label_bindings = nbr.rcvd_mappings.keys().map(|prefix| instance.state.as_ref().unwrap().fecs.get(prefix).unwrap()).filter(|fec| fec.is_nbr_nexthop(nbr)).count();
        Some(Self {
            discontinuity_time: nbr.statistics.discontinuity_time.ignore_in_testing(),
            total_addresses: Some(total_addresses.saturating_into()),
            total_labels: Some(total_labels.saturating_into()),
            total_fec_label_bindings: Some(total_fec_label_bindings.saturating_into()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::statistics::received::Received {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let msgs = &nbr.statistics.msgs_rcvd;
        Some(Self {
            total_octets: Some(msgs.total_bytes),
            total_messages: Some(msgs.total),
            address: Some(msgs.address),
            address_withdraw: Some(msgs.address_withdraw),
            initialization: Some(msgs.initialization),
            keepalive: Some(msgs.keepalive.load(atomic::Ordering::Relaxed)),
            label_abort_request: Some(msgs.label_abort_request),
            label_mapping: Some(msgs.label_mapping),
            label_release: Some(msgs.label_release),
            label_request: Some(msgs.label_request),
            label_withdraw: Some(msgs.label_withdraw),
            notification: Some(msgs.notification),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::statistics::sent::Sent {
    type ParentListEntry = &'a Neighbor;

    fn new(_instance: &'a Instance, nbr: &Self::ParentListEntry) -> Option<Self> {
        let msgs = &nbr.statistics.msgs_sent;
        Some(Self {
            total_octets: Some(msgs.total_bytes),
            total_messages: Some(msgs.total),
            address: Some(msgs.address),
            address_withdraw: Some(msgs.address_withdraw),
            initialization: Some(msgs.initialization),
            keepalive: Some(msgs.keepalive.load(atomic::Ordering::Relaxed)),
            label_abort_request: Some(msgs.label_abort_request),
            label_mapping: Some(msgs.label_mapping),
            label_release: Some(msgs.label_release),
            label_request: Some(msgs.label_request),
            label_withdraw: Some(msgs.label_withdraw),
            notification: Some(msgs.notification),
        })
        .ignore_in_testing()
    }
}
