//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{RouteKeyMsg, RouteMsg};
use ipnetwork::IpNetwork;

use crate::rib::Route;
use crate::{Interface, Master};

// ===== global functions =====

pub(crate) async fn process_msg(master: &mut Master, msg: IbusMsg) {
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
            master.rib.connected_route_add(msg).await;
        }
        // Interface address delete notification.
        IbusMsg::InterfaceAddressDel(msg) => {
            // Remove connected route from the RIB.
            master.rib.connected_route_del(msg).await;
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
            master.rib.ip_route_add(msg).await;
        }
        IbusMsg::RouteIpDel(msg) => {
            // Remove route from the RIB.
            master.rib.ip_route_del(msg).await;
        }
        IbusMsg::RouteMplsAdd(msg) => {
            // Add MPLS route to the LIB.
            master.rib.mpls_route_add(msg).await;
        }
        IbusMsg::RouteMplsDel(msg) => {
            // Remove MPLS route from the LIB.
            master.rib.mpls_route_del(msg).await;
        }
        // Ignore other events.
        _ => {}
    }
}

// Requests information about all interfaces addresses.
pub(crate) fn request_addresses(ibus_tx: &IbusSender) {
    send(ibus_tx, IbusMsg::InterfaceDump);
}

// Sends route redistribute update notification.
pub(crate) fn notify_redistribute_add(
    ibus_tx: &IbusSender,
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
    send(ibus_tx, msg);
}

// Sends route redistribute delete notification.
pub(crate) fn notify_redistribute_del(
    ibus_tx: &IbusSender,
    prefix: IpNetwork,
    protocol: Protocol,
) {
    let msg = RouteKeyMsg { protocol, prefix };
    let msg = IbusMsg::RouteRedistributeDel(msg);
    send(ibus_tx, msg);
}

// ===== helper functions =====

fn send(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
