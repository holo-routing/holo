//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![allow(clippy::single_match)]

use std::net::{Ipv4Addr, Ipv6Addr};

use futures::channel::mpsc::UnboundedReceiver;
use futures::TryStreamExt;
use holo_utils::southbound::InterfaceFlags;
use ipnetwork::IpNetwork;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::constants::{
    AF_INET, AF_INET6, ARPHRD_LOOPBACK, IFF_RUNNING, RTNLGRP_IPV4_IFADDR,
    RTNLGRP_IPV6_IFADDR, RTNLGRP_LINK,
};
use netlink_packet_route::rtnl::RtnlMessage;
use netlink_packet_route::{AddressMessage, LinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::new_connection;

use crate::Master;

// ===== helper functions =====

fn process_newlink_msg(master: &mut Master, msg: LinkMessage, notify: bool) {
    use netlink_packet_route::link::nlas::Nla;

    // Fetch interface attributes.
    let ifindex = msg.header.index;
    let mut ifname = None;
    let mut mtu = None;
    let mut flags = InterfaceFlags::empty();
    if msg.header.link_layer_type == ARPHRD_LOOPBACK {
        flags.insert(InterfaceFlags::LOOPBACK);
    }
    if msg.header.flags & IFF_RUNNING != 0 {
        flags.insert(InterfaceFlags::OPERATIVE);
    }
    for nla in msg.nlas.into_iter() {
        match nla {
            Nla::IfName(nla_ifname) => ifname = Some(nla_ifname),
            Nla::Mtu(nla_mtu) => mtu = Some(nla_mtu),
            _ => (),
        }
    }
    let (Some(ifname), Some(mtu)) = (ifname, mtu) else {
        return;
    };

    // Add or update interface.
    master.interface_update(ifname, ifindex, mtu, flags, notify);
}

fn process_dellink_msg(master: &mut Master, msg: LinkMessage, notify: bool) {
    use netlink_packet_route::link::nlas::Nla;

    // Fetch interface name.
    let mut ifname = None;
    for nla in msg.nlas.into_iter() {
        match nla {
            Nla::IfName(nla_ifname) => ifname = Some(nla_ifname),
            _ => (),
        }
    }
    let Some(ifname) = ifname else {
        return;
    };

    // Remove interface.
    master.interface_remove(ifname, notify);
}

fn process_newaddr_msg(master: &mut Master, msg: AddressMessage, notify: bool) {
    use netlink_packet_route::address::nlas::Nla;

    // Fetch address attributes.
    let mut addr = None;
    let ifindex = msg.header.index;
    for nla in msg.nlas.into_iter() {
        match nla {
            Nla::Address(nla_addr) => addr = Some(nla_addr),
            _ => (),
        }
    }
    let Some(addr) = addr else {
        return;
    };

    // Parse address.
    let Some(addr) =
        parse_address(msg.header.family, msg.header.prefix_len, addr)
    else {
        return;
    };

    // Add address to the interface.
    master.interface_addr_add(ifindex, addr, notify);
}

fn process_deladdr_msg(master: &mut Master, msg: AddressMessage, notify: bool) {
    use netlink_packet_route::address::nlas::Nla;

    // Fetch address attributes.
    let mut addr = None;
    let ifindex = msg.header.index;
    for nla in msg.nlas.into_iter() {
        match nla {
            Nla::Address(nla_addr) => addr = Some(nla_addr),
            _ => (),
        }
    }
    let Some(addr) = addr else {
        return;
    };

    // Parse address.
    let Some(addr) =
        parse_address(msg.header.family, msg.header.prefix_len, addr)
    else {
        return;
    };

    // Remove address from the interface.
    master.interface_addr_del(ifindex, addr, notify);
}

fn parse_address(
    family: u8,
    prefixlen: u8,
    bytes: Vec<u8>,
) -> Option<IpNetwork> {
    let addr = match family as u16 {
        AF_INET => {
            let mut addr_array: [u8; 4] = [0; 4];
            addr_array.copy_from_slice(&bytes);
            Ipv4Addr::from(addr_array).into()
        }
        AF_INET6 => {
            let mut addr_array: [u8; 16] = [0; 16];
            addr_array.copy_from_slice(&bytes);
            Ipv6Addr::from(addr_array).into()
        }
        _ => return None,
    };
    IpNetwork::new(addr, prefixlen).ok()
}

// ===== global functions =====

pub(crate) fn process_msg(
    master: &mut Master,
    msg: NetlinkMessage<RtnlMessage>,
) {
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RtnlMessage::NewLink(msg) => process_newlink_msg(master, msg, true),
            RtnlMessage::DelLink(msg) => process_dellink_msg(master, msg, true),
            RtnlMessage::NewAddress(msg) => {
                process_newaddr_msg(master, msg, true)
            }
            RtnlMessage::DelAddress(msg) => {
                process_deladdr_msg(master, msg, true)
            }
            _ => (),
        }
    }
}

pub(crate) async fn init(
    master: &mut Master,
) -> UnboundedReceiver<(NetlinkMessage<RtnlMessage>, SocketAddr)> {
    // Create netlink socket.
    let (conn, handle, _) =
        new_connection().expect("Failed to create netlink socket");
    tokio::spawn(conn);

    // Fetch interface information.
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .expect("Failed to fetch interface information")
    {
        process_newlink_msg(master, msg, false);
    }

    // Fetch address information.
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses
        .try_next()
        .await
        .expect("Failed to fetch interface address information")
    {
        process_newaddr_msg(master, msg, false);
    }

    // Start netlink monitor.
    let (mut conn, _, monitor) =
        new_connection().expect("Failed to create netlink socket");
    let groups = [RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR]
        .iter()
        .map(|group| 1 << (group - 1))
        .fold(0, std::ops::BitOr::bitor);
    let addr = SocketAddr::new(0, groups);
    conn.socket_mut()
        .socket_mut()
        .bind(&addr)
        .expect("Failed to bind netlink socket");
    tokio::spawn(conn);

    monitor
}
