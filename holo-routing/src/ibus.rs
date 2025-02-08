//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::IpAddr;

use holo_utils::ibus::{IbusChannelsTx, IbusMsg, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{RouteKeyMsg, RouteMsg};
use ipnetwork::IpNetwork;

use crate::rib::Route;
use crate::{InstanceHandle, InstanceId, Interface, Master};

// ===== global functions =====

pub(crate) fn process_msg(master: &mut Master, msg: IbusMsg) {
    // Relay message to protocol instances.
    match &msg {
        IbusMsg::BfdSessionReg { .. } | IbusMsg::BfdSessionUnreg { .. } => {
            // Relay to the BFD instance.
            if let Some(instance) = master
                .instances
                .get(&InstanceId::new(Protocol::BFD, "main".to_owned()))
            {
                send(&instance.ibus_tx, msg.clone());
            }
        }
        IbusMsg::BfdStateUpd { .. }
        | IbusMsg::HostnameUpdate(..)
        | IbusMsg::KeychainUpd(..)
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
        // Interface update notification.
        IbusMsg::InterfaceUpd(msg) => {
            master.interfaces.insert(
                msg.ifname.clone(),
                Interface::new(msg.ifname, msg.ifindex, msg.flags),
            );
        }
        // Interface delete notification.
        IbusMsg::InterfaceDel(ifname) => {
            master.interfaces.remove(&ifname);
        }
        // Interface address addition notification.
        IbusMsg::InterfaceAddressAdd(msg) => {
            // Add connected route to the RIB.
            master.rib.connected_route_add(msg, &master.interfaces);
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            // Remove connected route from the RIB.
            master.rib.connected_route_del(msg);
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
        IbusMsg::NexthopTrack(addr) => {
            // Nexthop tracking registration.
            master.rib.nht_add(addr, &master.instances);
        }
        IbusMsg::NexthopUntrack(addr) => {
            // Nexthop tracking unregistration.
            master.rib.nht_del(addr);
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
            master.rib.ip_route_add(msg);
        }
        IbusMsg::RouteIpDel(msg) => {
            // Remove route from the RIB.
            master.rib.ip_route_del(msg);
        }
        IbusMsg::RouteMplsAdd(msg) => {
            // Add MPLS route to the LIB.
            master.rib.mpls_route_add(msg);
        }
        IbusMsg::RouteMplsDel(msg) => {
            // Remove MPLS route from the LIB.
            master.rib.mpls_route_del(msg);
        }
        IbusMsg::RouteRedistributeDump { protocol, af } => {
            // Redistribute all requested routes.
            master
                .rib
                .redistribute_request(protocol, af, &master.instances);
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
        // Ignore other events.
        _ => {}
    }
}

// Requests information about all interfaces addresses.
pub(crate) fn request_addresses(ibus_tx: &IbusChannelsTx) {
    send(
        &ibus_tx.interface,
        IbusMsg::InterfaceSub {
            subscriber: ibus_tx.subscriber.clone(),
            ifname: None,
            af: None,
        },
    );
}

// Sends route redistribute update notification.
pub(crate) fn notify_redistribute_add(
    instances: &BTreeMap<InstanceId, InstanceHandle>,
    prefix: IpNetwork,
    route: &Route,
) {
    let msg = RouteMsg {
        protocol: route.protocol,
        prefix,
        distance: route.distance,
        metric: route.metric,
        tag: route.tag,
        opaque_attrs: route.opaque_attrs.clone(),
        nexthops: route.nexthops.clone(),
    };
    let msg = IbusMsg::RouteRedistributeAdd(msg);
    for instance in instances.values() {
        send(&instance.ibus_tx, msg.clone());
    }
}

// Sends route redistribute delete notification.
pub(crate) fn notify_redistribute_del(
    instances: &BTreeMap<InstanceId, InstanceHandle>,
    prefix: IpNetwork,
    protocol: Protocol,
) {
    let msg = RouteKeyMsg { protocol, prefix };
    let msg = IbusMsg::RouteRedistributeDel(msg);
    for instance in instances.values() {
        send(&instance.ibus_tx, msg.clone());
    }
}

// Sends route redistribute delete notification.
pub(crate) fn notify_nht_update(
    instances: &BTreeMap<InstanceId, InstanceHandle>,
    addr: IpAddr,
    metric: Option<u32>,
) {
    let msg = IbusMsg::NexthopUpd { addr, metric };
    for instance in instances.values() {
        send(&instance.ibus_tx, msg.clone());
    }
}

// ===== helper functions =====

fn send(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
