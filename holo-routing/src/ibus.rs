//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::IpAddr;

use holo_utils::ibus::{
    IbusMsg, IbusSender, InterfaceAddressMsg, InterfaceMsg, KeychainMsg,
    NexthopMsg, PolicyMsg, RouteBierMsg, RouteIpMsg, RouteMplsMsg,
    RouteRedistributeMsg,
};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{RouteKeyMsg, RouteMsg};
use ipnetwork::IpNetwork;

use crate::rib::Route;
use crate::{Interface, Master};

// ===== global functions =====

pub(crate) fn process_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        IbusMsg::Interface(iface_msg) => match iface_msg {
            // Interface update notification.
            InterfaceMsg::Update(msg) => {
                master.interfaces.insert(
                    msg.ifname.clone(),
                    Interface::new(msg.ifname, msg.ifindex, msg.flags),
                );
            }

            // Interface delete notification.
            InterfaceMsg::Delete(ifname) => {
                master.interfaces.remove(&ifname);
            }
            _ => {}
        },

        // Interface Address
        IbusMsg::InterfaceAddress(iface_addr_msg) => match iface_addr_msg {
            // Interface address addition notification.
            InterfaceAddressMsg::Add(msg) => {
                // Add connected route to the RIB.
                master.rib.connected_route_add(msg, &master.interfaces);
            }

            // Interface address delete notification.
            InterfaceAddressMsg::Delete(msg) => {
                // Remove connected route from the RIB.
                master.rib.connected_route_del(msg);
            }
        },

        // Keychain
        IbusMsg::Keychain(keychain_msg) => match keychain_msg {
            KeychainMsg::Update(keychain) => {
                // Update the local copy of the keychain.
                master
                    .shared
                    .keychains
                    .insert(keychain.name.clone(), keychain.clone());
            }
            KeychainMsg::Delete(keychain_name) => {
                // Remove the local copy of the keychain.
                master.shared.keychains.remove(&keychain_name);
            }
        },

        // Nexthop
        IbusMsg::Nexthop(nexthop_msg) => match nexthop_msg {
            // Nexthop tracking registration.
            NexthopMsg::Track(addr) => {
                master.rib.nht_add(addr, &master.ibus_tx);
            }

            // Nexthop tracking unregistration.
            NexthopMsg::Untrack(addr) => {
                master.rib.nht_del(addr);
            }

            _ => {}
        },

        // ==== POLICY ====
        IbusMsg::Policy(policy_msg) => {
            match policy_msg {
                PolicyMsg::MatchSetsUpdate(match_sets) => {
                    // Update the local copy of the policy match sets.
                    master.shared.policy_match_sets = match_sets;
                }
                PolicyMsg::Update(policy) => {
                    // Update the local copy of the policy definition.
                    master
                        .shared
                        .policies
                        .insert(policy.name.clone(), policy.clone());
                }
                PolicyMsg::Delete(policy_name) => {
                    // Remove the local copy of the policy definition.
                    master.shared.policies.remove(&policy_name);
                }
            }
        }

        // ==== ROUTE IP ====
        IbusMsg::RouteIp(route_ip_msg) => {
            match route_ip_msg {
                RouteIpMsg::Add(msg) => {
                    // Add route to the RIB.
                    master.rib.ip_route_add(msg);
                }
                RouteIpMsg::Delete(msg) => {
                    // Remove route from the RIB.
                    master.rib.ip_route_del(msg);
                }
            }
        }

        // ==== ROUTE MPLS ====
        IbusMsg::RouteMpls(route_mpls_msg) => {
            match route_mpls_msg {
                RouteMplsMsg::Add(msg) => {
                    // Add MPLS route to the LIB.
                    master.rib.mpls_route_add(msg);
                }
                RouteMplsMsg::Delete(msg) => {
                    // Remove MPLS route from the LIB.
                    master.rib.mpls_route_del(msg);
                }
            }
        }

        // ==== ROUTE REDISTRIBUTE ====
        IbusMsg::RouteRedistribute(RouteRedistributeMsg::Dump {
            protocol,
            af,
        }) => {
            // Redistribute all requested routes.
            master
                .rib
                .redistribute_request(protocol, af, &master.ibus_tx);
        }

        // ==== ROUTE BIER ====
        IbusMsg::RouteBier(route_bier_msg) => match route_bier_msg {
            RouteBierMsg::Add(msg) => {
                master.birt.bier_nbr_add(msg);
            }
            RouteBierMsg::Delete(msg) => {
                master.birt.bier_nbr_del(msg);
            }
        },

        // ===== BIER PURGE ====
        IbusMsg::BierPurge => {
            master.birt.entries.clear();
        }
        // Ignore other events.
        _ => {}
    }
}

// Requests information about all interfaces addresses.
pub(crate) fn request_addresses(ibus_tx: &IbusSender) {
    send(ibus_tx, InterfaceMsg::Dump.into());
}

// Sends route redistribute update notification.
pub(crate) fn notify_redistribute_add(
    ibus_tx: &IbusSender,
    prefix: IpNetwork,
    route: &Route,
) {
    let msg = RouteRedistributeMsg::Add(RouteMsg {
        protocol: route.protocol,
        prefix,
        distance: route.distance,
        metric: route.metric,
        tag: route.tag,
        opaque_attrs: route.opaque_attrs.clone(),
        nexthops: route.nexthops.clone(),
    });
    send(ibus_tx, msg.into());
}

// Sends route redistribute delete notification.
pub(crate) fn notify_redistribute_del(
    ibus_tx: &IbusSender,
    prefix: IpNetwork,
    protocol: Protocol,
) {
    let msg = RouteKeyMsg { protocol, prefix };
    let msg = RouteRedistributeMsg::Delete(msg);
    send(ibus_tx, msg.into());
}

// Sends route redistribute delete notification.
pub(crate) fn notify_nht_update(
    ibus_tx: &IbusSender,
    addr: IpAddr,
    metric: Option<u32>,
) {
    let msg = NexthopMsg::Update { addr, metric };
    send(ibus_tx, msg.into());
}

// ===== helper functions =====

fn send(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
