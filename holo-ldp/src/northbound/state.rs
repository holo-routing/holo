//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{atomic, LazyLock as Lazy};

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_northbound::paths::control_plane_protocol::mpls_ldp;
use holo_northbound::state::{
    Callbacks, CallbacksBuilder, ListEntryKind, NodeAttributes, Provider,
};
use holo_utils::mpls::Label;
use holo_yang::ToYang;

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
    CallbacksBuilder::default()
        .path(mpls_ldp::global::address_families::ipv4::label_distribution_control_mode::PATH)
        .get_element_string(|_instance, _args| {
            let mode = LabelDistMode::Independent.to_yang().into();
            Some(mode)
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                // Skip if there's no neighbor in the operational state.
                if !instance
                    .state
                    .neighbors
                    .iter()
                    .any(|nbr| nbr.is_operational())
                {
                    return None;
                }

                // Advertised addresses.
                let advertised =
                    instance.core.system.ipv4_addr_list.iter().map(
                        |addr| {
                            let binding = AddrBinding::new(
                                addr.ip(),
                                AdvertisementType::Advertised,
                                None,
                            );
                            ListEntry::AddrBinding(binding)
                        },
                    );

                // Received addresses.
                let received = instance
                    .state
                    .neighbors
                    .iter()
                    .flat_map(|nbr| {
                        nbr.addr_list.iter().filter_map(move |addr| {
                            if let IpAddr::V4(addr) = addr {
                                Some((nbr, addr))
                            } else {
                                None
                            }
                        })
                    })
                    .map(|(nbr, addr)| {
                        let binding = AddrBinding::new(
                            *addr,
                            AdvertisementType::Received,
                            Some(nbr.lsr_id),
                        );
                        ListEntry::AddrBinding(binding)
                    });

                // Chain advertised and received addresses.
                Some(Box::new(advertised.chain(received)))
            } else {
                None
            }
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::advertisement_type::PATH)
        .get_element_string(|_instance, args| {
            let binding = args.list_entry.as_addr_binding().unwrap();
            Some(binding.adv_type.to_yang().into())
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::peer::lsr_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let binding = args.list_entry.as_addr_binding().unwrap();
            binding.lsr_id
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::address::peer::label_space_id::PATH)
        .get_element_u16(|_instance, args| {
            let binding = args.list_entry.as_addr_binding().unwrap();
            binding.lsr_id.map(|_lsr_id| 0)
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .state
                    .fecs
                    .values()
                    .filter(|fec| fec.inner.prefix.is_ipv4())
                    .filter(|fec| {
                        !fec.inner.upstream.is_empty()
                            || !fec.inner.downstream.is_empty()
                    })
                    .map(ListEntry::Fec);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::PATH)
        .get_iterate(|instance, args| {
            let instance = instance.as_up().unwrap();
            let fec = args.parent_list_entry.as_fec().unwrap();

            // Advertised label mappings.
            let advertised =
                fec.inner.upstream.iter().map(|(lsr_id, mapping)| {
                    let binding = LabelBinding::new(
                        *lsr_id,
                        AdvertisementType::Advertised,
                        mapping.label,
                        true,
                    );
                    ListEntry::LabelBinding(binding)
                });

            // Received label mappings.
            let received = fec.inner.downstream.iter().filter_map(|(lsr_id, mapping)| {
                instance
                    .state
                    .neighbors
                    .get_by_lsr_id(lsr_id)
                    .map(|(_, nbr)| {
                        let binding = LabelBinding::new(
                            *lsr_id,
                            AdvertisementType::Received,
                            mapping.label,
                            fec.is_nbr_nexthop(nbr),
                        );
                        ListEntry::LabelBinding(binding)
                    })
            });

            // Chain advertised and received label mappings.
            Some(Box::new(advertised.chain(received)))
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::label::PATH)
        .get_element_string(|_instance, args| {
            let binding = args.list_entry.as_label_binding().unwrap();
            Some(binding.label.to_yang().into())
        })
        .path(mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::used_in_forwarding::PATH)
        .get_element_bool(|_instance, args| {
            let binding = args.list_entry.as_label_binding().unwrap();
            Some(binding.used_in_fwd)
        })
        .path(mpls_ldp::discovery::interfaces::interface::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .core
                    .interfaces
                    .iter()
                    .filter(|iface| iface.is_active())
                    .map(ListEntry::Interface);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(mpls_ldp::discovery::interfaces::interface::next_hello::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let iface = args.list_entry.as_interface().unwrap();
            iface.next_hello().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, args| {
            let instance = instance.as_up().unwrap();
            let iface = args.parent_list_entry.as_interface().unwrap();
            let iter = instance
                .state
                .ipv4
                .adjacencies
                .iter_by_iface(&iface.id)
                .into_iter()
                .flatten()
                .map(ListEntry::InterfaceAdj);
            Some(Box::new(iter))
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::adjacent::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.holdtime_adjacent)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::negotiated::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.holdtime_negotiated)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::remaining::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            adj.holdtime_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::next_hello::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|instance, args| {
            let instance = instance.as_up().unwrap();
            let adj = args.list_entry.as_interface_adj().unwrap();
            let remaining = adj.next_hello(instance);
            Some(u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX))
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.discontinuity_time)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.hello_rcvd)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_dropped::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.hello_dropped)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::lsr_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let adj = args.list_entry.as_interface_adj().unwrap();
            Some(adj.lsr_id)
        })
        .path(mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::label_space_id::PATH)
        .get_element_u16(|_instance, _args| {
            Some(0)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .state
                    .ipv4
                    .adjacencies
                    .iter()
                    .filter(|adj| adj.source.iface_id.is_none())
                    .map(ListEntry::TargetedNbrAdj);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::adjacent::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.holdtime_adjacent)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::negotiated::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.holdtime_negotiated)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::remaining::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            adj.holdtime_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::next_hello::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|instance, args| {
            let instance = instance.as_up().unwrap();
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            let remaining = adj.next_hello(instance);
            Some(u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX))
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.discontinuity_time)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.hello_rcvd)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_dropped::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.hello_dropped)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::lsr_id::PATH)
        .get_element_ipv4(|_instance, args| {
            let adj = args.list_entry.as_targeted_nbr_adj().unwrap();
            Some(adj.lsr_id)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::peer::label_space_id::PATH)
        .get_element_u16(|_instance, _args| {
            Some(0)
        })
        .path(mpls_ldp::discovery::targeted::address_families::ipv4::target::PATH)
        .get_iterate(|_instance, _args| {
            // No operational data under this list.
            None
        })
        .path(mpls_ldp::peers::peer::PATH)
        .get_iterate(|instance, _args| {
            if let Instance::Up(instance) = instance {
                let iter = instance
                    .state
                    .neighbors
                    .iter()
                    .map(ListEntry::Neighbor);
                Some(Box::new(iter))
            } else {
                None
            }
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::PATH)
        .get_iterate(|instance, args| {
            let instance = instance.as_up().unwrap();
            let nbr = args.parent_list_entry.as_neighbor().unwrap();
            let iter = instance
                .state
                .ipv4
                .adjacencies
                .iter_by_lsr_id(&nbr.lsr_id)
                .into_iter()
                .flatten()
                .map(ListEntry::NeighborAdj);
            Some(Box::new(iter))
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::adjacent::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Some(adj.holdtime_adjacent)
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::negotiated::PATH)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Some(adj.holdtime_negotiated)
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::hello_holdtime::remaining::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            adj.holdtime_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::next_hello::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|instance, args| {
            let instance = instance.as_up().unwrap();
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            let remaining = adj.next_hello(instance);
            Some(u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX))
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Some(adj.discontinuity_time)
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_received::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Some(adj.hello_rcvd)
        })
        .path(mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::statistics::hello_dropped::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let adj = args.list_entry.as_neighbor_adj().unwrap();
            Some(adj.hello_dropped)
        })
        .path(mpls_ldp::peers::peer::label_advertisement_mode::local::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            if nbr.is_operational() {
                Some(LabelAdvMode::DownstreamUnsolicited.to_yang().into())
            } else {
                None
            }
        })
        .path(mpls_ldp::peers::peer::label_advertisement_mode::peer::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.rcvd_label_adv_mode.as_ref().map(|mode| mode.to_yang().into())
        })
        .path(mpls_ldp::peers::peer::label_advertisement_mode::negotiated::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            if nbr.is_operational() {
                Some(LabelAdvMode::DownstreamUnsolicited.to_yang().into())
            } else {
                None
            }
        })
        .path(mpls_ldp::peers::peer::next_keep_alive::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.next_kalive().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::peers::peer::received_peer_state::capability::end_of_lib::enabled::PATH)
        .get_element_bool(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.flags.contains(NeighborFlags::CAP_UNREC_NOTIF))
        })
        .path(mpls_ldp::peers::peer::received_peer_state::capability::typed_wildcard_fec::enabled::PATH)
        .get_element_bool(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.flags.contains(NeighborFlags::CAP_TYPED_WCARD))
        })
        .path(mpls_ldp::peers::peer::session_holdtime::peer::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.kalive_holdtime_rcvd
        })
        .path(mpls_ldp::peers::peer::session_holdtime::negotiated::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.kalive_holdtime_negotiated
        })
        .path(mpls_ldp::peers::peer::session_holdtime::remaining::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.kalive_timeout_remaining().map(|remaining| {
                u16::try_from(remaining.as_secs()).unwrap_or(u16::MAX)
            })
        })
        .path(mpls_ldp::peers::peer::session_state::PATH)
        .get_element_string(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.state.to_yang().into())
        })
        .path(mpls_ldp::peers::peer::tcp_connection::local_address::PATH)
        .get_element_ip(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.local_addr)
        })
        .path(mpls_ldp::peers::peer::tcp_connection::local_port::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.local_port)
        })
        .path(mpls_ldp::peers::peer::tcp_connection::remote_address::PATH)
        .get_element_ip(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.remote_addr)
        })
        .path(mpls_ldp::peers::peer::tcp_connection::remote_port::PATH)
        .get_element_u16(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.conn_info.as_ref().map(|conn_info| conn_info.remote_port)
        })
        .path(mpls_ldp::peers::peer::up_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_timeticks64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.uptime
        })
        .path(mpls_ldp::peers::peer::statistics::discontinuity_time::PATH)
        .attributes(NodeAttributes::TIME)
        .get_element_date_and_time(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            nbr.statistics.discontinuity_time
        })
        .path(mpls_ldp::peers::peer::statistics::received::total_octets::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.total_bytes)
        })
        .path(mpls_ldp::peers::peer::statistics::received::total_messages::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.total)
        })
        .path(mpls_ldp::peers::peer::statistics::received::address::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.address)
        })
        .path(mpls_ldp::peers::peer::statistics::received::address_withdraw::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.address_withdraw)
        })
        .path(mpls_ldp::peers::peer::statistics::received::initialization::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.initialization)
        })
        .path(mpls_ldp::peers::peer::statistics::received::keepalive::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total = nbr
                .statistics
                .msgs_rcvd
                .keepalive
                .load(atomic::Ordering::Relaxed);
            Some(total)
        })
        .path(mpls_ldp::peers::peer::statistics::received::label_abort_request::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.label_abort_request)
        })
        .path(mpls_ldp::peers::peer::statistics::received::label_mapping::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.label_mapping)
        })
        .path(mpls_ldp::peers::peer::statistics::received::label_release::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.label_release)
        })
        .path(mpls_ldp::peers::peer::statistics::received::label_request::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.label_request)
        })
        .path(mpls_ldp::peers::peer::statistics::received::label_withdraw::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.label_withdraw)
        })
        .path(mpls_ldp::peers::peer::statistics::received::notification::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_rcvd.notification)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::total_octets::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.total_bytes)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::total_messages::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.total)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::address::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.address)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::address_withdraw::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.address_withdraw)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::initialization::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.initialization)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::keepalive::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total = nbr
                .statistics
                .msgs_sent
                .keepalive
                .load(atomic::Ordering::Relaxed);
            Some(total)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::label_abort_request::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.label_abort_request)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::label_mapping::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.label_mapping)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::label_release::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.label_release)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::label_request::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.label_request)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::label_withdraw::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.label_withdraw)
        })
        .path(mpls_ldp::peers::peer::statistics::sent::notification::PATH)
        .attributes(NodeAttributes::COUNTER)
        .get_element_u64(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            Some(nbr.statistics.msgs_sent.notification)
        })
        .path(mpls_ldp::peers::peer::statistics::total_addresses::PATH)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total = u32::try_from(nbr.addr_list.len()).unwrap_or(u32::MAX);
            Some(total)
        })
        .path(mpls_ldp::peers::peer::statistics::total_labels::PATH)
        .get_element_u32(|_instance, args| {
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total = u32::try_from(nbr.rcvd_mappings.len()).unwrap_or(u32::MAX);
            Some(total)
        })
        .path(mpls_ldp::peers::peer::statistics::total_fec_label_bindings::PATH)
        .get_element_u32(|instance, args| {
            let instance = instance.as_up().unwrap();
            let nbr = args.list_entry.as_neighbor().unwrap();
            let total = nbr
                .rcvd_mappings
                .keys()
                .map(|prefix| instance.state.fecs.get(prefix).unwrap())
                .filter(|fec| fec.is_nbr_nexthop(nbr))
                .count();
            Some(u32::try_from(total).unwrap_or(u32::MAX))
        })
        .build()
}

// ===== impl Instance =====

impl Provider for Instance {
    const STATE_PATH: &'static str = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-mpls-ldp:mpls-ldp'][name='test']/ietf-mpls-ldp:mpls-ldp";

    type ListEntry<'a> = ListEntry<'a>;

    fn callbacks() -> Option<&'static Callbacks<Instance>> {
        Some(&CALLBACKS)
    }
}

// ===== impl ListEntry =====

impl<'a> ListEntryKind for ListEntry<'a> {
    fn get_keys(&self) -> Option<String> {
        match self {
            ListEntry::None => None,
            ListEntry::AddrBinding(binding) => {
                use mpls_ldp::global::address_families::ipv4::bindings::address::list_keys;
                let keys = list_keys(binding.addr);
                Some(keys)
            }
            ListEntry::LabelBinding(binding) => {
                use mpls_ldp::global::address_families::ipv4::bindings::fec_label::peer::list_keys;
                let keys =
                    list_keys(binding.lsr_id, 0, binding.adv_type.to_yang());
                Some(keys)
            }
            ListEntry::Fec(fec) => {
                use mpls_ldp::global::address_families::ipv4::bindings::fec_label::list_keys;
                let keys = list_keys(&fec.inner.prefix);
                Some(keys)
            }
            ListEntry::Interface(iface) => {
                use mpls_ldp::discovery::interfaces::interface::list_keys;
                let keys = list_keys(&iface.name);
                Some(keys)
            }
            ListEntry::InterfaceAdj(adj) => {
                use mpls_ldp::discovery::interfaces::interface::address_families::ipv4::hello_adjacencies::hello_adjacency::list_keys;
                let keys = list_keys(adj.source.addr);
                Some(keys)
            }
            ListEntry::TargetedNbrAdj(adj) => {
                use mpls_ldp::discovery::targeted::address_families::ipv4::hello_adjacencies::hello_adjacency::list_keys;
                let keys = list_keys(adj.local_addr, adj.source.addr);
                Some(keys)
            }
            ListEntry::Neighbor(nbr) => {
                use mpls_ldp::peers::peer::list_keys;
                let keys = list_keys(nbr.lsr_id, 0);
                Some(keys)
            }
            ListEntry::NeighborAdj(adj) => {
                use mpls_ldp::peers::peer::address_families::ipv4::hello_adjacencies::hello_adjacency::list_keys;
                let keys = list_keys(adj.local_addr, adj.source.addr);
                Some(keys)
            }
        }
    }
}
