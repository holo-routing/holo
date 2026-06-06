//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, hash_map};
use std::net::IpAddr;

use holo_utils::ibus::{
    IbusChannelsTx, IbusClient, IbusClientId, IbusMsg, IbusSender,
};
use holo_utils::ip::{AddressFamily, IpNetworkKind, JointPrefixMapExt};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    AddressFlags, Nexthop, RouteKeyMsg, RouteKind, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;

use crate::rib::{NhtEntry, RedistributeSub, Route, RouteFlags};
use crate::{InstanceId, Master};

// ===== global functions =====

pub(crate) fn process_msg(
    master: &mut Master,
    client: IbusClient,
    msg: IbusMsg,
) {
    // Relay broadcast messages to protocol instances.
    match &msg {
        IbusMsg::KeychainUpd(..)
        | IbusMsg::KeychainDel(..)
        | IbusMsg::PolicyMatchSetsUpd(..)
        | IbusMsg::PolicyUpd(..)
        | IbusMsg::PolicyDel(..) => {
            // Relay to all instances.
            for instance in master.instances.values() {
                send(&instance.ibus_tx, msg.clone());
            }
        }
        _ => {}
    }

    match msg {
        // BFD peer (un)registration. Relayed to the BFD instance, with the
        // client's identity injected from the connection it arrived on.
        IbusMsg::BfdSessionReg {
            sess_key,
            client_id,
            client_config,
            ..
        } => {
            if let Some(instance) = master
                .instances
                .get(&InstanceId::new(Protocol::BFD, "main".to_owned()))
            {
                send(
                    &instance.ibus_tx,
                    IbusMsg::BfdSessionReg {
                        client: Some(client),
                        sess_key,
                        client_id,
                        client_config,
                    },
                );
            }
        }
        IbusMsg::BfdSessionUnreg { sess_key, .. } => {
            if let Some(instance) = master
                .instances
                .get(&InstanceId::new(Protocol::BFD, "main".to_owned()))
            {
                send(
                    &instance.ibus_tx,
                    IbusMsg::BfdSessionUnreg {
                        client: Some(client),
                        sess_key,
                    },
                );
            }
        }
        IbusMsg::KeychainUpd(keychain) => {
            // Update the local copy of the keychain.
            master
                .shared
                .keychains
                .insert(keychain.name.clone(), keychain.clone());
        }
        IbusMsg::KeychainDel(keychain_name) => {
            // Remove the local copy of the keychain.
            master.shared.keychains.remove(&keychain_name);
        }
        // Nexthop tracking registration.
        IbusMsg::NexthopTrack { addr } => {
            master.rib.nht_add(client, addr);
        }
        // Nexthop tracking unregistration.
        IbusMsg::NexthopUntrack { addr } => {
            master.rib.nht_del(client.id, addr);
        }
        IbusMsg::PolicyMatchSetsUpd(match_sets) => {
            // Update the local copy of the policy match sets.
            master.shared.policy_match_sets = match_sets;
        }
        IbusMsg::PolicyUpd(policy) => {
            // Update the local copy of the policy definition.
            master
                .shared
                .policies
                .insert(policy.name.clone(), policy.clone());
        }
        IbusMsg::PolicyDel(policy_name) => {
            // Remove the local copy of the policy definition.
            master.shared.policies.remove(&policy_name);
        }
        IbusMsg::RouteIpAdd(msg) => {
            // Add route to the RIB.
            master.rib.ip_route_add(msg, client.id);
        }
        IbusMsg::RouteIpDel(msg) => {
            // Remove route from the RIB.
            master.rib.ip_route_del(msg);
        }
        IbusMsg::RouteMplsAdd(msg) => {
            // Add MPLS route to the LIB.
            master.rib.mpls_route_add(msg, client.id);
        }
        IbusMsg::RouteMplsDel(msg) => {
            // Remove MPLS route from the LIB.
            master.rib.mpls_route_del(msg);
        }
        IbusMsg::RouteBierAdd(msg) => {
            master.birt.bier_nbr_add(msg);
        }
        IbusMsg::RouteBierDel(msg) => {
            master.birt.bier_nbr_del(msg);
        }
        IbusMsg::BierPurge => {
            master.birt.entries.clear();
        }
        IbusMsg::RouteRedistributeSub { protocol, af } => {
            let sub = master.rib.subscriptions.entry(client.id).or_insert(
                RedistributeSub {
                    protocols: Default::default(),
                    tx: client.tx,
                },
            );
            if matches!(af, None | Some(AddressFamily::Ipv4)) {
                sub.protocols.insert((AddressFamily::Ipv4, protocol));
            }
            if matches!(af, None | Some(AddressFamily::Ipv6)) {
                sub.protocols.insert((AddressFamily::Ipv6, protocol));
            }

            // Redistribute active routes of the requested protocol type.
            let redistribute_prefix =
                |prefix, routes: &BTreeMap<u32, Route>| {
                    if let Some(best_route) = routes
                        .values()
                        .find(|route| route.protocol == protocol)
                        .filter(|route| {
                            route.flags.contains(RouteFlags::ACTIVE)
                                && !route.flags.contains(RouteFlags::REMOVED)
                        })
                    {
                        notify_redistribute_add(sub, prefix, best_route);
                    }
                };
            if af.is_none() || af == Some(AddressFamily::Ipv4) {
                for (prefix, routes) in master.rib.ip.ipv4().iter() {
                    redistribute_prefix(prefix.into(), routes);
                }
            }
            if af.is_none() || af == Some(AddressFamily::Ipv6) {
                for (prefix, routes) in master.rib.ip.ipv6().iter() {
                    redistribute_prefix(prefix.into(), routes);
                }
            }
        }
        IbusMsg::RouteRedistributeUnsub { protocol, af } => {
            if let hash_map::Entry::Occupied(mut o) =
                master.rib.subscriptions.entry(client.id)
            {
                let sub = o.get_mut();
                if matches!(af, None | Some(AddressFamily::Ipv4)) {
                    sub.protocols.remove(&(AddressFamily::Ipv4, protocol));
                }
                if matches!(af, None | Some(AddressFamily::Ipv6)) {
                    sub.protocols.remove(&(AddressFamily::Ipv6, protocol));
                }
                if sub.protocols.is_empty() {
                    o.remove();
                }
            }
        }
        // Ignore other events.
        _ => {}
    }
}

pub(crate) fn process_notification_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            master.interfaces.update(msg.ifname, msg.ifindex, msg.flags);
        }
        // Interface delete notification.
        IbusMsg::InterfaceDel(ifname) => {
            master.interfaces.remove(&ifname);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            let Some(iface) = master.interfaces.get_mut_by_name(&msg.ifname)
            else {
                return;
            };

            // Add address to interface.
            iface.addresses.insert(msg.addr, msg.flags);
            let ifindex = iface.ifindex;

            // Add connected route to the RIB.
            if !msg.flags.contains(AddressFlags::UNNUMBERED) {
                master.ibus_tx.route_ip_add(RouteMsg {
                    protocol: Protocol::DIRECT,
                    kind: RouteKind::Unicast,
                    prefix: msg.addr.apply_mask(),
                    distance: 0,
                    metric: 0,
                    tag: None,
                    opaque_attrs: RouteOpaqueAttrs::None,
                    nexthops: [Nexthop::Interface { ifindex }].into(),
                });
            }
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            let Some(iface) = master.interfaces.get_mut_by_name(&msg.ifname)
            else {
                return;
            };

            // Remove address from interface.
            iface.addresses.remove(&msg.addr);

            // Remove connected route from the RIB.
            if !msg.flags.contains(AddressFlags::UNNUMBERED) {
                master.ibus_tx.route_ip_del(RouteKeyMsg {
                    protocol: Protocol::DIRECT,
                    prefix: msg.addr.apply_mask(),
                });
            }
        }
        // Ignore other events.
        _ => {}
    }
}

// Cleans up all state associated with a disconnected client.
pub(crate) fn disconnect(master: &mut Master, id: IbusClientId) {
    master.rib.subscriptions.remove(&id);
    for nhte in master.rib.nht.values_mut() {
        nhte.subscriptions.remove(&id);
    }
    master.rib.route_remove_all_by_owner(id);
}

// Requests information about all interfaces addresses.
pub(crate) fn request_addresses(ibus_tx: &IbusChannelsTx) {
    ibus_tx.interface_sub(None, None);
}

// Sends route redistribute update notification.
pub(crate) fn notify_redistribute_add(
    sub: &RedistributeSub,
    prefix: IpNetwork,
    route: &Route,
) {
    if !sub
        .protocols
        .contains(&(prefix.address_family(), route.protocol))
    {
        return;
    }

    let msg = RouteMsg {
        protocol: route.protocol,
        kind: route.kind,
        prefix,
        distance: route.distance,
        metric: route.metric,
        tag: route.tag,
        opaque_attrs: route.opaque_attrs,
        nexthops: route.nexthops.clone(),
    };
    let msg = IbusMsg::RouteRedistributeAdd(msg);
    send(&sub.tx, msg.clone());
}

// Sends route redistribute delete notification.
pub(crate) fn notify_redistribute_del(
    sub: &RedistributeSub,
    prefix: IpNetwork,
    protocol: Protocol,
) {
    if !sub.protocols.contains(&(prefix.address_family(), protocol)) {
        return;
    }

    let msg = RouteKeyMsg { protocol, prefix };
    let msg = IbusMsg::RouteRedistributeDel(msg);
    send(&sub.tx, msg.clone());
}

// Sends route redistribute delete notification.
pub(crate) fn notify_nht_update(addr: IpAddr, nhte: &NhtEntry) {
    let msg = IbusMsg::NexthopUpd {
        addr,
        metric: nhte.metric,
    };
    for ibus_tx in nhte.subscriptions.values() {
        send(ibus_tx, msg.clone());
    }
}

// ===== helper functions =====

fn send(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
