//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_utils::ibus::{
    IbusMsg, IbusSender, InterfaceAddressMsg, InterfaceMsg, RouterIdMsg,
};
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{AddressFlags, AddressMsg, InterfaceUpdateMsg};
use ipnetwork::IpNetwork;

use crate::interface::Interface;
use crate::Master;

// ===== global functions =====

pub(crate) fn process_msg(master: &mut Master, msg: IbusMsg) {
    match msg {
        // Interface Message
        IbusMsg::Interface(iface_msg) => match iface_msg {
            InterfaceMsg::Dump => {
                for iface in master.interfaces.iter() {
                    notify_interface_update(&master.ibus_tx, iface);

                    for iface_addr in iface.addresses.values() {
                        notify_addr_add(
                            &master.ibus_tx,
                            iface.name.clone(),
                            iface_addr.addr,
                            iface_addr.flags,
                        );
                    }
                }
            }
            InterfaceMsg::Query { ifname, af } => {
                if let Some(iface) = master.interfaces.get_by_name(&ifname) {
                    notify_interface_update(&master.ibus_tx, iface);

                    for iface_addr in
                        iface.addresses.values().filter(|iface_addr| match af {
                            Some(af) => iface_addr.addr.address_family() == af,
                            None => true,
                        })
                    {
                        notify_addr_add(
                            &master.ibus_tx,
                            iface.name.clone(),
                            iface_addr.addr,
                            iface_addr.flags,
                        );
                    }
                }
            }
            _ => {}
        },

        // RouterId
        IbusMsg::RouterId(RouterIdMsg::Query) => {
            notify_router_id_update(
                &master.ibus_tx,
                master.interfaces.router_id(),
            );
        }
        // Ignore other events.
        _ => {}
    }
}

pub(crate) fn notify_router_id_update(
    ibus_tx: &IbusSender,
    router_id: Option<Ipv4Addr>,
) {
    let msg = RouterIdMsg::Update(router_id);
    notify(ibus_tx, msg.into());
}

pub(crate) fn notify_interface_update(ibus_tx: &IbusSender, iface: &Interface) {
    let update_msg = InterfaceUpdateMsg {
        ifname: iface.name.clone(),
        ifindex: iface.ifindex.unwrap_or(0),
        mtu: iface.mtu.unwrap_or(0),
        flags: iface.flags,
        mac_address: iface.mac_address,
    };
    let msg = InterfaceMsg::Update(update_msg);

    notify(ibus_tx, msg.into());
}

pub(crate) fn notify_interface_del(ibus_tx: &IbusSender, ifname: String) {
    let msg = InterfaceMsg::Delete(ifname);
    notify(ibus_tx, msg.into());
}

pub(crate) fn notify_addr_add(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let addr_msg = AddressMsg {
        ifname,
        addr,
        flags,
    };
    let msg = InterfaceAddressMsg::Add(addr_msg);
    notify(ibus_tx, msg.into());
}

pub(crate) fn notify_addr_del(
    ibus_tx: &IbusSender,
    ifname: String,
    addr: IpNetwork,
    flags: AddressFlags,
) {
    let msg = InterfaceAddressMsg::Delete(AddressMsg {
        ifname,
        addr,
        flags,
    });
    notify(ibus_tx, msg.into());
}

// ===== helper functions =====

fn notify(ibus_tx: &IbusSender, msg: IbusMsg) {
    let _ = ibus_tx.send(msg);
}
