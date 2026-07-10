//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_utils::bgp::AfiSafi;
use holo_utils::ip::{IpAddrKind, IpNetworkKind, Ipv4AddrExt, Ipv6AddrExt};
use holo_utils::mpls::Label;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;

use crate::neighbor::{
    Neighbor, NeighborUpdateQueue, NeighborUpdateQueues, PeerType,
};
use crate::packet::attribute::{self, ATTR_MIN_LEN_EXT, BaseAttrs};
use crate::packet::iana::{Afi, Safi};
use crate::packet::message::{
    LabeledIpv4Nlri, LabeledIpv6Nlri, Message, MpReachNlri, MpUnreachNlri,
    ReachNlri, UnreachNlri, UpdateMsg,
};
use crate::rib::{RoutingTable, RoutingTables};

// BGP address-family specific code.
pub trait AddressFamily: Sized {
    // Address Family Identifier.
    const AFI: Afi;
    // Subsequent Address Family Identifier.
    const SAFI: Safi;
    // Combined AFI and SAFI.
    const AFI_SAFI: AfiSafi;

    // The type of IP address used by this address family.
    type IpAddr: IpAddrKind;
    // The type of IP network used by this address family.
    type IpNetwork: IpNetworkKind<Self::IpAddr> + prefix_trie::Prefix;
    // The NLRI key used by the BGP RIB for this address family.
    type Prefix: Copy + Ord;

    // Get the routing table for this address family from the provided
    // `RoutingTables`.
    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self>;

    // Get the update queue for this address family from the provided
    // `NeighborUpdateQueues`.
    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self>;

    // Extract the next hop IP address from the received BGP attributes.
    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr;

    // Modify the next hop(s) for transmission.
    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs);

    // Convert between generic IP prefixes used by policy/RIB APIs and the
    // per-address-family NLRI key.
    fn prefix_from_ip_network(prefix: IpNetwork) -> Option<Self::Prefix>;

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork;

    // Build BGP UPDATE messages based on the provided update queue.
    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message>;
}

#[derive(Debug)]
pub struct Ipv4Unicast;

#[derive(Debug)]
pub struct Ipv6Unicast;

#[derive(Debug)]
pub struct Ipv4LabeledUnicast;

#[derive(Debug)]
pub struct Ipv6LabeledUnicast;

// ===== impl Ipv4Unicast =====

impl AddressFamily for Ipv4Unicast {
    const AFI: Afi = Afi::Ipv4;
    const SAFI: Safi = Safi::Unicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv4Unicast;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;
    type Prefix = Ipv4Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv4_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv4_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        attrs.nexthop.unwrap()
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        // Get source address of the BGP session.
        let session_src = match nbr.conn_info.as_ref().unwrap().local_addr {
            IpAddr::V4(addr) => {
                // BGP over IPv4.
                addr
            }
            IpAddr::V6(_addr) => {
                // BGP over IPv6.
                //
                // TODO: use IPv4 address of the corresponding system interface.
                Ipv4Addr::UNSPECIFIED
            }
        };

        // Handle locally originated routes.
        if local {
            attrs.nexthop = Some(session_src.into());
            return;
        }

        match nbr.peer_type {
            PeerType::Internal => {
                // Next hop isn't modified.
            }
            PeerType::External => {
                if !nbr.shared_subnet {
                    // Update next hop using the source address of the eBGP
                    // session.
                    attrs.nexthop = Some(session_src.into());
                } else {
                    // Next hop isn't modified (eBGP next hop optimization).
                }
            }
        }
    }

    fn prefix_from_ip_network(prefix: IpNetwork) -> Option<Self::Prefix> {
        Ipv4Network::get(prefix)
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        // Reachable prefixes.
        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv4Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - attribute::nexthop::length())
                / (1 + Ipv4Addr::LENGTH as u16);

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let reach = ReachNlri {
                            prefixes: chunk.map(|(prefix, _)| prefix).collect(),
                            nexthop,
                        };
                        Message::Update(UpdateMsg {
                            reach: Some(reach),
                            unreach: None,
                            mp_reach: None,
                            mp_unreach: None,
                            attrs: Some(attrs.clone()),
                        })
                    },
                ),
            );
        }

        // Unreachable prefixes.
        if !unreach.is_empty() {
            let max = (Message::MAX_LEN - UpdateMsg::MIN_LEN)
                / (1 + Ipv4Addr::LENGTH as u16);

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let unreach = UnreachNlri {
                            prefixes: chunk.collect(),
                        };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: Some(unreach),
                            mp_reach: None,
                            mp_unreach: None,
                            attrs: None,
                        })
                    },
                ),
            );
        }

        msgs
    }
}

// ===== impl Ipv6Unicast =====

impl AddressFamily for Ipv6Unicast {
    const AFI: Afi = Afi::Ipv6;
    const SAFI: Safi = Safi::Unicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv6Unicast;

    type IpAddr = Ipv6Addr;
    type IpNetwork = Ipv6Network;
    type Prefix = Ipv6Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv6_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv6_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        attrs
            .ll_nexthop
            .map(IpAddr::from)
            .unwrap_or(attrs.nexthop.unwrap())
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        // Get source address of the BGP session.
        let session_src = match nbr.conn_info.as_ref().unwrap().local_addr {
            IpAddr::V4(addr) => {
                // BGP over IPv4 (IPv4-mapped IPv6 address).
                addr.to_ipv6_mapped()
            }
            IpAddr::V6(addr) => {
                // BGP over IPv6.
                addr
            }
        };

        // Handle locally originated routes.
        if local {
            attrs.nexthop = Some(session_src.into());
            if nbr.shared_subnet {
                // TODO: update link-local next hop.
            }
            return;
        }

        match nbr.peer_type {
            PeerType::Internal => {
                // Global next hop isn't modified.

                // TODO: update link-local next hop.
            }
            PeerType::External => {
                if !nbr.shared_subnet {
                    // Update global next hop using the source address of the
                    // eBGP session.
                    attrs.nexthop = Some(session_src.into());

                    // Unset link-local next hop.
                    attrs.ll_nexthop = None;
                } else {
                    // Global next hop isn't modified (eBGP next hop
                    // optimization).

                    // TODO: update link-local next hop.
                }
            }
        }
    }

    fn prefix_from_ip_network(prefix: IpNetwork) -> Option<Self::Prefix> {
        Ipv6Network::get(prefix)
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        // Reachable prefixes.
        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv6Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let ll_nexthop = attrs.base.ll_nexthop;
            let nexthop_len = if ll_nexthop.is_some() { 32 } else { 16 };
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - ATTR_MIN_LEN_EXT
                - MpReachNlri::MIN_LEN
                - nexthop_len)
                / (1 + Ipv6Addr::LENGTH as u16);

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let mp_reach = MpReachNlri::Ipv6Unicast {
                            prefixes: chunk.map(|(prefix, _)| prefix).collect(),
                            nexthop,
                            ll_nexthop,
                        };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: Some(mp_reach),
                            mp_unreach: None,
                            attrs: Some(attrs.clone()),
                        })
                    },
                ),
            );
        }

        // Unreachable prefixes.
        if !unreach.is_empty() {
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - ATTR_MIN_LEN_EXT
                - MpUnreachNlri::MIN_LEN)
                / (1 + Ipv6Addr::LENGTH as u16);

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let mp_unreach = MpUnreachNlri::Ipv6Unicast {
                            prefixes: chunk.collect(),
                        };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: None,
                            mp_unreach: Some(mp_unreach),
                            attrs: None,
                        })
                    },
                ),
            );
        }

        msgs
    }
}

// ===== impl Ipv4LabeledUnicast =====

impl AddressFamily for Ipv4LabeledUnicast {
    const AFI: Afi = Afi::Ipv4;
    const SAFI: Safi = Safi::LabeledUnicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv4LabeledUnicast;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;
    type Prefix = Ipv4Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv4_labeled_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv4_labeled_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        Ipv4Unicast::nexthop_rx_extract(attrs)
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        Ipv4Unicast::nexthop_tx_change(nbr, local, attrs)
    }

    fn prefix_from_ip_network(prefix: IpNetwork) -> Option<Self::Prefix> {
        Ipv4Network::get(prefix)
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv4Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - ATTR_MIN_LEN_EXT
                - MpReachNlri::MIN_LEN)
                / 5;

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|(prefix, label)| LabeledIpv4Nlri {
                                label: label.unwrap_or_else(|| {
                                    Label::explicit_null(
                                        holo_utils::ip::AddressFamily::Ipv4,
                                    )
                                }),
                                prefix,
                            })
                            .collect();
                        let mp_reach = MpReachNlri::Ipv4LabeledUnicast {
                            prefixes,
                            nexthop,
                        };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: Some(mp_reach),
                            mp_unreach: None,
                            attrs: Some(attrs.clone()),
                        })
                    },
                ),
            );
        }

        if !unreach.is_empty() {
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - ATTR_MIN_LEN_EXT
                - MpUnreachNlri::MIN_LEN)
                / 5;

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledIpv4Nlri {
                                label: Label::explicit_null(
                                    holo_utils::ip::AddressFamily::Ipv4,
                                ),
                                prefix,
                            })
                            .collect();
                        let mp_unreach =
                            MpUnreachNlri::Ipv4LabeledUnicast { prefixes };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: None,
                            mp_unreach: Some(mp_unreach),
                            attrs: None,
                        })
                    },
                ),
            );
        }

        msgs
    }
}

// ===== impl Ipv6LabeledUnicast =====

impl AddressFamily for Ipv6LabeledUnicast {
    const AFI: Afi = Afi::Ipv6;
    const SAFI: Safi = Safi::LabeledUnicast;
    const AFI_SAFI: AfiSafi = AfiSafi::Ipv6LabeledUnicast;

    type IpAddr = Ipv6Addr;
    type IpNetwork = Ipv6Network;
    type Prefix = Ipv6Network;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.ipv6_labeled_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.ipv6_labeled_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        Ipv6Unicast::nexthop_rx_extract(attrs)
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        Ipv6Unicast::nexthop_tx_change(nbr, local, attrs)
    }

    fn prefix_from_ip_network(prefix: IpNetwork) -> Option<Self::Prefix> {
        Ipv6Network::get(prefix)
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);

        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv6Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let ll_nexthop = attrs.base.ll_nexthop;
            let nexthop_len = if ll_nexthop.is_some() { 32 } else { 16 };
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - ATTR_MIN_LEN_EXT
                - MpReachNlri::MIN_LEN
                - nexthop_len)
                / 17;

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|(prefix, label)| LabeledIpv6Nlri {
                                label: label.unwrap_or_else(|| {
                                    Label::explicit_null(
                                        holo_utils::ip::AddressFamily::Ipv6,
                                    )
                                }),
                                prefix,
                            })
                            .collect();
                        let mp_reach = MpReachNlri::Ipv6LabeledUnicast {
                            prefixes,
                            nexthop,
                            ll_nexthop,
                        };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: Some(mp_reach),
                            mp_unreach: None,
                            attrs: Some(attrs.clone()),
                        })
                    },
                ),
            );
        }

        if !unreach.is_empty() {
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - ATTR_MIN_LEN_EXT
                - MpUnreachNlri::MIN_LEN)
                / 17;

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledIpv6Nlri {
                                label: Label::explicit_null(
                                    holo_utils::ip::AddressFamily::Ipv6,
                                ),
                                prefix,
                            })
                            .collect();
                        let mp_unreach =
                            MpUnreachNlri::Ipv6LabeledUnicast { prefixes };
                        Message::Update(UpdateMsg {
                            reach: None,
                            unreach: None,
                            mp_reach: None,
                            mp_unreach: Some(mp_unreach),
                            attrs: None,
                        })
                    },
                ),
            );
        }

        msgs
    }
}
