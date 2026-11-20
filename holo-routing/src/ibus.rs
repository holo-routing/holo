//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::hash_map;
use std::net::IpAddr;

use holo_utils::ibus::{
    IbusChannelsTx, IbusClient, IbusClientId, IbusMsg, IbusSender,
};
use holo_utils::ip::{AddressFamily, IpNetworkKind, JointPrefixMapExt};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    AddressFlags, InterfaceFlags, Nexthop, RouteKeyMsg, RouteKind, RouteMsg,
    RouteOpaqueAttrs,
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
            let redistribute_prefix = |prefix, routes: &Vec<Route>| {
                if let Some(best_route) = routes
                    .iter()
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
            let iface_idx = master.interfaces.update(msg.ifname, msg.ifindex);
            let iface = &mut master.interfaces[iface_idx];
            let old_flags = std::mem::replace(&mut iface.flags, msg.flags);

            // Add or remove the connected routes of the interface when it
            // goes up or down, as only operative interfaces have them.
            let was_operative = old_flags.contains(InterfaceFlags::OPERATIVE);
            let operative = msg.flags.contains(InterfaceFlags::OPERATIVE);
            if was_operative != operative {
                let iface = &master.interfaces[iface_idx];
                let ifindex = iface.ifindex;
                for (addr, flags) in &iface.addresses {
                    if flags.contains(AddressFlags::UNNUMBERED) {
                        continue;
                    }

                    let prefix = addr.apply_mask();
                    if operative {
                        connected_route_add(&master.ibus_tx, prefix, ifindex);
                    } else {
                        connected_route_del(&master.ibus_tx, prefix);
                    }
                }
            }
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

            // Add connected route to the RIB, if the interface is operative.
            if iface.flags.contains(InterfaceFlags::OPERATIVE)
                && !msg.flags.contains(AddressFlags::UNNUMBERED)
            {
                let prefix = msg.addr.apply_mask();
                connected_route_add(&master.ibus_tx, prefix, iface.ifindex);
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
                connected_route_del(&master.ibus_tx, msg.addr.apply_mask());
            }
        }
        // Ignore other events.
        _ => {}
    }
}

// Cleans up all state associated with a disconnected client.
pub(crate) fn disconnect(master: &mut Master, id: IbusClientId) {
    master.rib.subscriptions.remove(&id);
    master.rib.nht.retain(|_, nhte| {
        nhte.subscriptions.remove(&id);
        !nhte.subscriptions.is_empty()
    });
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
    if !prefix.is_routable()
        || !sub
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
        nexthops: route.nexthops.to_vec(),
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
    if !prefix.is_routable()
        || !sub.protocols.contains(&(prefix.address_family(), protocol))
    {
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
        metric: nhte.resolution.as_ref().map(|resolution| resolution.metric),
    };
    for ibus_tx in nhte.subscriptions.values() {
        send(ibus_tx, msg.clone());
    }
}

// ===== helper functions =====

// Adds the connected route of the given prefix through the given interface.
fn connected_route_add(
    ibus_tx: &IbusChannelsTx,
    prefix: IpNetwork,
    ifindex: u32,
) {
    ibus_tx.route_ip_add(RouteMsg {
        protocol: Protocol::DIRECT,
        kind: RouteKind::Unicast,
        prefix,
        distance: 0,
        metric: 0,
        tag: None,
        opaque_attrs: RouteOpaqueAttrs::None,
        nexthops: [Nexthop::Interface { ifindex }].into(),
    });
}

// Removes the connected route of the given prefix.
fn connected_route_del(ibus_tx: &IbusChannelsTx, prefix: IpNetwork) {
    ibus_tx.route_ip_del(RouteKeyMsg {
        protocol: Protocol::DIRECT,
        prefix,
    });
}

fn send(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
