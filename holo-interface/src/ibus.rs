//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use holo_utils::ibus::{IbusClient, IbusClientId, IbusMsg, IbusSender};
use holo_utils::ip::{AddressFamily, IpNetworkKind};
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};
use ipnetwork::IpNetwork;

use crate::interface::{Interface, InterfaceSub};
use crate::{Master, netlink};

// ===== global functions =====

pub(crate) fn process_msg(
    master: &mut Master,
    client: IbusClient,
    msg: IbusMsg,
) {
    match msg {
        IbusMsg::InterfaceSub { ifname, af } => {
            let mut afs = BTreeSet::new();
            if let Some(af) = af {
                afs.insert(af);
            } else {
                afs.extend([AddressFamily::Ipv4, AddressFamily::Ipv6]);
            }

            if let Some(ifname) = ifname {
                if let Some(iface) = master.interfaces.get_mut_by_name(&ifname)
                {
                    notify_interface_update(&client.tx, iface);
                    for iface_addr in
                        iface.addresses.values().filter(|iface_addr| {
                            afs.contains(&iface_addr.addr.address_family())
                        })
                    {
                        notify_addr_add(
                            &client.tx,
                            iface.name.clone(),
                            iface_addr.addr,
                            iface_addr.flags,
                        );
                    }

                    let sub = InterfaceSub::new(afs, client.tx);
                    iface.subscriptions.insert(client.id, sub);
                }
            } else {
                for iface in master.interfaces.iter() {
                    notify_interface_update(&client.tx, iface);
                    for iface_addr in
                        iface.addresses.values().filter(|iface_addr| {
                            afs.contains(&iface_addr.addr.address_family())
                        })
                    {
                        notify_addr_add(
                            &client.tx,
                            iface.name.clone(),
                            iface_addr.addr,
                            iface_addr.flags,
                        );
                    }
                }
                let sub = InterfaceSub::new(afs, client.tx);
                master.interfaces.subscriptions.insert(client.id, sub);
            }
        }
        IbusMsg::InterfaceUnsub { ifname } => {
            if let Some(ifname) = ifname {
                if let Some(iface) = master.interfaces.get_mut_by_name(&ifname)
                {
                    iface.subscriptions.remove(&client.id);
                }
            } else {
                master.interfaces.subscriptions.remove(&client.id);
            }
        }
        IbusMsg::RouterIdSub {} => {
            notify_router_id_update(&client.tx, master.interfaces.router_id());
            master
                .interfaces
                .router_id_subscriptions
                .insert(client.id, client.tx);
        }
        IbusMsg::MacvlanAdd {
            parent_ifname,
            ifname,
            mac_addr,
        } => {
            if let Some(iface) = master.interfaces.get_by_name(&parent_ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::macvlan_create(
                    &master.netlink_tx,
                    ifname,
                    mac_addr,
                    ifindex,
                );
            }
        }
        IbusMsg::MacvlanDel { ifname } => {
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::iface_delete(&master.netlink_tx, ifindex);
            }
        }
        IbusMsg::InterfaceIpAddRequest { ifname, addr } => {
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::addr_install(&master.netlink_tx, ifindex, &addr);
            }
        }
        IbusMsg::InterfaceIpDelRequest { ifname, addr } => {
            if let Some(iface) = master.interfaces.get_by_name(&ifname)
                && let Some(ifindex) = iface.ifindex
            {
                netlink::addr_uninstall(&master.netlink_tx, ifindex, &addr);
            }
        }
        // Ignore other events.
        _ => {}
    }
}

// Cleans up all state associated with a disconnected client.
pub(crate) fn disconnect(master: &mut Master, id: IbusClientId) {
    master.interfaces.subscriptions.remove(&id);
    master.interfaces.router_id_subscriptions.remove(&id);
    for iface in master.interfaces.iter_mut() {
        iface.subscriptions.remove(&id);
    }
}

pub(crate) fn notify_router_id_update(
    ibus_tx: &IbusSender,
    router_id: Option<Ipv4Addr>,
) {
    let msg = IbusMsg::RouterIdUpdate(router_id);
    notify(ibus_tx, msg);
}

pub(crate) fn notify_interface_update(ibus_tx: &IbusSender, iface: &Interface) {
    let msg = IbusMsg::InterfaceUpd(InterfaceUpdateMsg {
        ifname: iface.name.clone(),
        ifindex: iface.ifindex.unwrap_or(0),
        mtu: iface.mtu.unwrap_or(0),
        flags: iface.flags,
        mac_address: iface.mac_address,
        msd: Default::default(),
    });
    notify(ibus_tx, msg);
}

pub(crate) fn notify_interface_del(ibus_tx: &IbusSender, ifname: String) {
    let msg = IbusMsg::InterfaceDel(ifname);
    notify(ibus_tx, msg);
}

pub(crate) fn notify_addr_add(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let msg = IbusMsg::InterfaceAddressAdd(AddressMsg {
        ifname,
        addr,
        flags,
    });
    notify(ibus_tx, msg);
}

pub(crate) fn notify_addr_del(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let msg = IbusMsg::InterfaceAddressDel(AddressMsg {
        ifname,
        addr,
        flags,
    });
    notify(ibus_tx, msg);
}

// ===== helper functions =====

fn notify(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
