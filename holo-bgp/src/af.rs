//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_protocol::InstanceShared;
use holo_utils::bgp::{AfiSafi, RouteDistinguisher, RouteTarget};
use holo_utils::ibus::IbusChannelsTx;
use holo_utils::ip::{IpAddrKind, IpNetworkKind, Ipv4AddrExt, Ipv6AddrExt};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;

use crate::ibus;
use crate::neighbor::{
    Neighbor, NeighborUpdateQueue, NeighborUpdateQueues, PeerType,
};
use crate::packet::attribute::{self, ATTR_MIN_LEN_EXT, BaseAttrs};
use crate::packet::iana::{Afi, Safi};
use crate::packet::message::{
    LabeledVpnIpv4Nlri, LabeledVpnIpv6Nlri, Message, MpReachNlri,
    MpUnreachNlri, ReachNlri, UnreachNlri, UpdateMsg,
};
use crate::rib::{LocalRoute, RoutingTable, RoutingTables};

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

    // Whether selected Loc-RIB routes should be installed in the global RIB.
    const INSTALL_LOC_RIB: bool = true;

    // Whether selected Loc-RIB routes should be advertised to neighbors by
    // the generic policy path.
    const DISSEMINATE: bool = true;
    const POLICY_DISSEMINATE: bool = true;

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

    fn vpn_import_install(
        _prefix: Self::Prefix,
        _route: &LocalRoute,
        _shared: &InstanceShared,
        _ibus_tx: &IbusChannelsTx,
        _distance: u8,
    ) {
    }

    fn vpn_import_uninstall(
        _prefix: Self::Prefix,
        _route: &LocalRoute,
        _shared: &InstanceShared,
        _ibus_tx: &IbusChannelsTx,
    ) {
    }
}

#[derive(Debug)]
pub struct Ipv4Unicast;

#[derive(Debug)]
pub struct Ipv6Unicast;

#[derive(Debug)]
pub struct Vpnv4Unicast;

#[derive(Debug)]
pub struct Vpnv6Unicast;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vpnv4Prefix {
    pub rd: RouteDistinguisher,
    pub prefix: Ipv4Network,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vpnv6Prefix {
    pub rd: RouteDistinguisher,
    pub prefix: Ipv6Network,
}

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
                            prefixes: chunk.collect(),
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
                            prefixes: chunk.collect(),
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

// ===== impl Vpnv4Unicast =====

impl AddressFamily for Vpnv4Unicast {
    const AFI: Afi = Afi::Ipv4;
    const SAFI: Safi = Safi::LabeledVpn;
    const AFI_SAFI: AfiSafi = AfiSafi::L3vpnIpv4Unicast;
    const INSTALL_LOC_RIB: bool = false;
    const POLICY_DISSEMINATE: bool = false;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;
    type Prefix = Vpnv4Prefix;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.vpnv4_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.vpnv4_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        attrs.nexthop.unwrap()
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        Ipv4Unicast::nexthop_tx_change(nbr, local, attrs);
    }

    fn prefix_from_ip_network(_prefix: IpNetwork) -> Option<Self::Prefix> {
        None
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);
        let labels = std::mem::take(&mut queue.labels);

        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv4Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - ATTR_MIN_LEN_EXT
                - MpReachNlri::MIN_LEN)
                / (1 + 3 + 8 + Ipv4Addr::LENGTH as u16);

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledVpnIpv4Nlri {
                                label: labels
                                    .get(&prefix)
                                    .map(|label| label.get())
                                    .unwrap_or(0),
                                rd: prefix.rd,
                                prefix: prefix.prefix,
                            })
                            .collect();
                        let mp_reach =
                            MpReachNlri::L3vpnIpv4Unicast { prefixes, nexthop };
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
                / (1 + 3 + 8 + Ipv4Addr::LENGTH as u16);

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledVpnIpv4Nlri {
                                label: labels
                                    .get(&prefix)
                                    .map(|label| label.get())
                                    .unwrap_or(0),
                                rd: prefix.rd,
                                prefix: prefix.prefix,
                            })
                            .collect();
                        let mp_unreach =
                            MpUnreachNlri::L3vpnIpv4Unicast { prefixes };
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

    fn vpn_import_install(
        prefix: Self::Prefix,
        route: &LocalRoute,
        shared: &InstanceShared,
        ibus_tx: &IbusChannelsTx,
        distance: u8,
    ) {
        vpn_import_install(
            prefix.prefix.into(),
            route,
            shared,
            ibus_tx,
            distance,
        );
    }

    fn vpn_import_uninstall(
        prefix: Self::Prefix,
        route: &LocalRoute,
        shared: &InstanceShared,
        ibus_tx: &IbusChannelsTx,
    ) {
        vpn_import_uninstall(prefix.prefix.into(), route, shared, ibus_tx);
    }
}

// ===== impl Vpnv6Unicast =====

impl AddressFamily for Vpnv6Unicast {
    const AFI: Afi = Afi::Ipv6;
    const SAFI: Safi = Safi::LabeledVpn;
    const AFI_SAFI: AfiSafi = AfiSafi::L3vpnIpv6Unicast;
    const INSTALL_LOC_RIB: bool = false;
    const POLICY_DISSEMINATE: bool = false;

    type IpAddr = Ipv6Addr;
    type IpNetwork = Ipv6Network;
    type Prefix = Vpnv6Prefix;

    fn table(tables: &mut RoutingTables) -> &mut RoutingTable<Self> {
        &mut tables.vpnv6_unicast
    }

    fn update_queue(
        queues: &mut NeighborUpdateQueues,
    ) -> &mut NeighborUpdateQueue<Self> {
        &mut queues.vpnv6_unicast
    }

    fn nexthop_rx_extract(attrs: &BaseAttrs) -> IpAddr {
        Ipv6Unicast::nexthop_rx_extract(attrs)
    }

    fn nexthop_tx_change(nbr: &Neighbor, local: bool, attrs: &mut BaseAttrs) {
        Ipv6Unicast::nexthop_tx_change(nbr, local, attrs);
    }

    fn prefix_from_ip_network(_prefix: IpNetwork) -> Option<Self::Prefix> {
        None
    }

    fn prefix_to_ip_network(prefix: Self::Prefix) -> IpNetwork {
        prefix.prefix.into()
    }

    fn build_updates(queue: &mut NeighborUpdateQueue<Self>) -> Vec<Message> {
        let mut msgs = vec![];
        let reach = std::mem::take(&mut queue.reach);
        let unreach = std::mem::take(&mut queue.unreach);
        let labels = std::mem::take(&mut queue.labels);

        for (attrs, prefixes) in reach.into_iter() {
            let nexthop = Ipv6Addr::get(attrs.base.nexthop.unwrap()).unwrap();
            let max = (Message::MAX_LEN
                - UpdateMsg::MIN_LEN
                - attrs.length()
                - ATTR_MIN_LEN_EXT
                - MpReachNlri::MIN_LEN)
                / (1 + 3 + 8 + Ipv6Addr::LENGTH as u16);

            msgs.extend(
                prefixes.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledVpnIpv6Nlri {
                                label: labels
                                    .get(&prefix)
                                    .map(|label| label.get())
                                    .unwrap_or(0),
                                rd: prefix.rd,
                                prefix: prefix.prefix,
                            })
                            .collect();
                        let mp_reach =
                            MpReachNlri::L3vpnIpv6Unicast { prefixes, nexthop };
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
                / (1 + 3 + 8 + Ipv6Addr::LENGTH as u16);

            msgs.extend(
                unreach.into_iter().chunks(max as usize).into_iter().map(
                    |chunk| {
                        let prefixes = chunk
                            .map(|prefix| LabeledVpnIpv6Nlri {
                                label: labels
                                    .get(&prefix)
                                    .map(|label| label.get())
                                    .unwrap_or(0),
                                rd: prefix.rd,
                                prefix: prefix.prefix,
                            })
                            .collect();
                        let mp_unreach =
                            MpUnreachNlri::L3vpnIpv6Unicast { prefixes };
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

    fn vpn_import_install(
        prefix: Self::Prefix,
        route: &LocalRoute,
        shared: &InstanceShared,
        ibus_tx: &IbusChannelsTx,
        distance: u8,
    ) {
        vpn_import_install(
            prefix.prefix.into(),
            route,
            shared,
            ibus_tx,
            distance,
        );
    }

    fn vpn_import_uninstall(
        prefix: Self::Prefix,
        route: &LocalRoute,
        shared: &InstanceShared,
        ibus_tx: &IbusChannelsTx,
    ) {
        vpn_import_uninstall(prefix.prefix.into(), route, shared, ibus_tx);
    }
}

fn vpn_import_install(
    prefix: IpNetwork,
    route: &LocalRoute,
    shared: &InstanceShared,
    ibus_tx: &IbusChannelsTx,
    distance: u8,
) {
    for table_id in vpn_import_table_ids(route, shared) {
        ibus::tx::route_install(
            ibus_tx,
            Some(table_id),
            prefix,
            route,
            distance,
        );
    }
}

fn vpn_import_uninstall(
    prefix: IpNetwork,
    route: &LocalRoute,
    shared: &InstanceShared,
    ibus_tx: &IbusChannelsTx,
) {
    for table_id in vpn_import_table_ids(route, shared) {
        ibus::tx::route_uninstall(ibus_tx, Some(table_id), prefix);
    }
}

fn vpn_import_table_ids(
    route: &LocalRoute,
    shared: &InstanceShared,
) -> Vec<u32> {
    let Some(route_rts) = route_import_rts(route) else {
        return vec![];
    };
    let imports = shared.vpn_imports.lock().unwrap();
    imports
        .values()
        .filter(|import| !import.import_rts.is_disjoint(&route_rts))
        .filter_map(|import| import.table_id)
        .collect()
}

fn route_import_rts(route: &LocalRoute) -> Option<BTreeSet<RouteTarget>> {
    let ext_comm = route.attrs.ext_comm.as_ref()?;
    let rts = ext_comm
        .value
        .0
        .iter()
        .filter_map(RouteTarget::from_ext_comm)
        .collect::<BTreeSet<_>>();
    (!rts.is_empty()).then_some(rts)
}
