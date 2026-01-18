//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::atomic;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::state::{ListEntryKind, Provider, YangContainer, YangList, YangOps};
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
use crate::northbound::yang_gen::{self, mpls_ldp};

impl Provider for Instance {
    type ListEntry<'a> = ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = yang_gen::ops::YANG_OPS_STATE;
}

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

#[derive(Debug)]
pub enum AdvertisementType {
    Advertised,
    Received,
}

pub type ListIterator<'a> = Box<dyn Iterator<Item = ListEntry<'a>> + 'a>;

impl ListEntryKind for ListEntry<'_> {}

// ===== YANG impls =====

impl<'a> YangContainer<'a, Instance> for mpls_ldp::global::address_families::ipv4::Ipv4<'a> {
    fn new(_instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<Self> {
        Some(Self {
            label_distribution_control_mode: Some(LabelDistMode::Independent.to_yang()),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::address::Address<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let neighbors = &instance.state.as_ref()?.neighbors;

        // Skip if there's no neighbor in the operational state.
        if !neighbors.iter().any(|nbr| nbr.is_operational()) {
            return None;
        }

        // Advertised addresses.
        let advertised = instance.system.ipv4_addr_list.iter().map(|addr| {
            let binding = AddrBinding::new(addr.ip(), AdvertisementType::Advertised, None);
            ListEntry::AddrBinding(binding)
        });

        // Received addresses.
        let received = neighbors.iter().flat_map(|nbr| {
            nbr.addr_list.iter().filter_map(move |addr| {
                Ipv4Addr::get(*addr).map(|addr| {
                    let binding = AddrBinding::new(addr, AdvertisementType::Received, Some(nbr.lsr_id));
                    ListEntry::AddrBinding(binding)
                })
            })
        });

        // Chain advertised and received addresses.
        Some(Box::new(advertised.chain(received)))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let binding = list_entry.as_addr_binding().unwrap();
        Self {
            address: Cow::Owned(binding.addr),
            advertisement_type: Some(binding.adv_type.to_yang()),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::address::peer::Peer<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let binding = list_entry.as_addr_binding().unwrap();
        Some(Self {
            lsr_id: binding.lsr_id.map(Cow::Owned),
            label_space_id: binding.lsr_id.map(|_lsr_id| 0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::fec_label::FecLabel<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let fecs = &instance.state.as_ref()?.fecs;
        let iter = fecs
            .values()
            .filter(|fec| fec.inner.prefix.is_ipv4())
            .filter(|fec| !fec.inner.upstream.is_empty() || !fec.inner.downstream.is_empty())
            .map(ListEntry::Fec);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let fec = list_entry.as_fec().unwrap();
        Self {
            fec: Cow::Owned(Ipv4Network::get(*fec.inner.prefix).unwrap()),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::Peer<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let fec = list_entry.as_fec().unwrap();

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
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let binding = list_entry.as_label_binding().unwrap();
        Self {
            lsr_id: Cow::Owned(binding.lsr_id),
            label_space_id: 0,
            advertisement_type: binding.adv_type.to_yang(),
            label: Some(binding.label.to_yang()),
            used_in_forwarding: Some(binding.used_in_fwd),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::interfaces::interface::Interface<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        if !instance.is_active() {
            return None;
        }
        let iter = instance.interfaces.iter().filter(|iface| iface.is_active()).map(ListEntry::Interface);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let iface = list_entry.as_interface().unwrap();
        Self {
            name: Cow::Borrowed(&iface.name),
            next_hello: iface.next_hello().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let iface = list_entry.as_interface().unwrap();
        let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_iface(&iface.name).into_iter().flatten().map(ListEntry::InterfaceAdj);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let adj = list_entry.as_interface_adj().unwrap();
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_interface_adj().unwrap();
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_interface_adj().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_interface_adj().unwrap();
        Some(Self {
            lsr_id: Some(Cow::Owned(adj.lsr_id)),
            label_space_id: Some(0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let adjacencies = &instance.state.as_ref()?.ipv4.adjacencies;
        let iter = adjacencies.iter().filter(|adj| adj.source.ifname.is_none()).map(ListEntry::TargetedNbrAdj);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let adj = list_entry.as_targeted_nbr_adj().unwrap();
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            local_address: Cow::Owned(Ipv4Addr::get(adj.local_addr).unwrap()),
            adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_targeted_nbr_adj().unwrap();
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_targeted_nbr_adj().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::Peer<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_targeted_nbr_adj().unwrap();
        Some(Self {
            lsr_id: Some(Cow::Owned(adj.lsr_id)),
            label_space_id: Some(0),
        })
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::peers::peer::Peer<'a> {
    fn iter(instance: &'a Instance, _list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let neighbors = &instance.state.as_ref()?.neighbors;
        let iter = neighbors.iter().map(ListEntry::Neighbor);
        Some(Box::new(iter))
    }

    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let nbr = list_entry.as_neighbor().unwrap();
        Self {
            lsr_id: Cow::Owned(nbr.lsr_id),
            label_space_id: 0,
            next_keep_alive: nbr.next_kalive().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
            session_state: Some(nbr.state.to_yang()),
            up_time: nbr.uptime.as_ref().map(Cow::Borrowed).ignore_in_testing(),
        }
    }
}

impl<'a> YangList<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::HelloAdjacency<'a> {
    fn iter(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<ListIterator<'a>> {
        let nbr = list_entry.as_neighbor().unwrap();
        let iter = instance.state.as_ref().unwrap().ipv4.adjacencies.iter_by_lsr_id(&nbr.lsr_id).into_iter().flatten().map(ListEntry::NeighborAdj);
        Some(Box::new(iter))
    }

    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Self {
        let adj = list_entry.as_neighbor_adj().unwrap();
        let next_hello = adj.next_hello(&instance.interfaces, &instance.tneighbors);
        Self {
            local_address: Cow::Owned(Ipv4Addr::get(adj.local_addr).unwrap()),
            adjacent_address: Cow::Owned(Ipv4Addr::get(adj.source.addr).unwrap()),
            next_hello: Some(next_hello.as_secs().saturating_into()).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::HelloHoldtime {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_neighbor_adj().unwrap();
        Some(Self {
            adjacent: Some(adj.holdtime_adjacent),
            negotiated: Some(adj.holdtime_negotiated),
            remaining: adj.holdtime_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::Statistics<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let adj = list_entry.as_neighbor_adj().unwrap();
        Some(Self {
            discontinuity_time: Some(Cow::Borrowed(&adj.discontinuity_time)),
            hello_received: Some(adj.hello_rcvd),
            hello_dropped: Some(adj.hello_dropped),
        })
        .ignore_in_testing()
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::label_advertisement_mode::LabelAdvertisementMode<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            local: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited.to_yang()),
            peer: nbr.rcvd_label_adv_mode.as_ref().map(|mode| mode.to_yang()),
            negotiated: nbr.is_operational().then_some(LabelAdvMode::DownstreamUnsolicited.to_yang()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::received_peer_state::capability::end_of_lib::EndOfLib {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            enabled: Some(nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::received_peer_state::capability::typed_wildcard_fec::TypedWildcardFec {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            enabled: Some(nbr.flags.contains(NeighborFlags::CAP_TYPED_WCARD)),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::session_holdtime::SessionHoldtime {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        Some(Self {
            peer: nbr.kalive_holdtime_rcvd,
            negotiated: nbr.kalive_holdtime_negotiated,
            remaining: nbr.kalive_timeout_remaining().map(|d| d.as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::tcp_connection::TcpConnection<'a> {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        let conn_info = nbr.conn_info.as_ref()?;
        Some(Self {
            local_address: Some(Cow::Borrowed(&conn_info.local_addr)),
            local_port: Some(conn_info.local_port).ignore_in_testing(),
            remote_address: Some(Cow::Borrowed(&conn_info.remote_addr)),
            remote_port: Some(conn_info.remote_port).ignore_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::statistics::Statistics<'a> {
    fn new(instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
        let total_addresses = nbr.addr_list.len();
        let total_labels = nbr.rcvd_mappings.len();
        let total_fec_label_bindings = nbr.rcvd_mappings.keys().map(|prefix| instance.state.as_ref().unwrap().fecs.get(prefix).unwrap()).filter(|fec| fec.is_nbr_nexthop(nbr)).count();
        Some(Self {
            discontinuity_time: nbr.statistics.discontinuity_time.as_ref().map(Cow::Borrowed).ignore_in_testing(),
            total_addresses: Some(total_addresses.saturating_into()),
            total_labels: Some(total_labels.saturating_into()),
            total_fec_label_bindings: Some(total_fec_label_bindings.saturating_into()),
        })
    }
}

impl<'a> YangContainer<'a, Instance> for mpls_ldp::peers::peer::statistics::received::Received {
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
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
    fn new(_instance: &'a Instance, list_entry: &ListEntry<'a>) -> Option<Self> {
        let nbr = list_entry.as_neighbor().unwrap();
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
