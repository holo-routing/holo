//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use capctl::caps::CapState;
use futures::TryStreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use holo_utils::ip::IpAddrExt;
use holo_utils::mac_addr::MacAddr;
use holo_utils::southbound::InterfaceFlags;
use ipnetwork::IpNetwork;
use libc::{RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_LINK};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::address::{
    AddressAttribute, AddressFlags, AddressMessage,
};
use netlink_packet_route::link::{
    LinkAttribute, LinkFlags, LinkLayerType, LinkMessage, MacVlanMode,
};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    Handle, LinkMacVlan, LinkMessageBuilder, LinkUnspec, LinkVlan,
    new_connection,
};
use tracing::{error, trace};

use crate::Master;
use crate::interface::Owner;
use crate::mpsc::UnboundedSender;

pub type NetlinkMonitor =
    UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

pub enum NetlinkRequest {
    LinkAdd(LinkMessage),
    LinkSet(LinkMessage),
    LinkDel(u32),
    AddressAdd(u32, IpNetwork),
    AddressDel(u32, IpNetwork),
}

// ===== impl NetlinkRequest =====

impl NetlinkRequest {
    pub(crate) async fn execute(self, handle: &Handle) {
        match self {
            NetlinkRequest::LinkAdd(msg) => {
                let request = handle.link().add(msg);
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to create interface");
                }
            }
            NetlinkRequest::LinkSet(msg) => {
                let request = handle.link().set(msg);
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to update interface");
                }
            }
            NetlinkRequest::LinkDel(ifindex) => {
                let request = handle.link().del(ifindex);
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to delete interface");
                }
            }
            NetlinkRequest::AddressAdd(ifindex, addr) => {
                let request =
                    handle.address().add(ifindex, addr.ip(), addr.prefix());
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to install interface address");
                }
            }
            NetlinkRequest::AddressDel(ifindex, addr) => {
                let mut request =
                    handle.address().add(ifindex, addr.ip(), addr.prefix());
                let request =
                    handle.address().del(request.message_mut().clone());
                if let Err(error) = request.execute().await {
                    error!(%error, "failed to uninstall interface address");
                }
            }
        }
    }
}

// ===== helper functions =====

fn process_newlink_msg(master: &mut Master, msg: LinkMessage) {
    trace!(?msg, "received RTM_NEWLINK message");

    // Fetch interface attributes.
    let ifindex = msg.header.index;
    let mut ifname = None;
    let mut mtu = None;
    let mut mac_address: [u8; 6] = [0u8; 6];

    let mut flags = InterfaceFlags::empty();
    if msg.header.link_layer_type == LinkLayerType::Loopback {
        flags.insert(InterfaceFlags::LOOPBACK);
    }

    if msg.header.flags.contains(LinkFlags::Running) {
        flags.insert(InterfaceFlags::OPERATIVE);
    }
    if msg.header.flags.contains(LinkFlags::Broadcast) {
        flags.insert(InterfaceFlags::BROADCAST)
    }

    for nla in msg.attributes.into_iter() {
        match nla {
            LinkAttribute::IfName(nla_ifname) => ifname = Some(nla_ifname),
            LinkAttribute::Mtu(nla_mtu) => mtu = Some(nla_mtu),
            LinkAttribute::Address(addr) => {
                mac_address = addr.try_into().unwrap_or_default();
            }
            _ => (),
        }
    }
    let (Some(ifname), Some(mtu)) = (ifname, mtu) else {
        return;
    };

    // Add or update interface.
    master.interfaces.update(
        ifname,
        ifindex,
        mtu,
        flags,
        MacAddr::from(mac_address),
        &master.netlink_tx,
    );
}

fn process_dellink_msg(master: &mut Master, msg: LinkMessage) {
    trace!(?msg, "received RTM_DELLINK message");

    // Fetch interface ifindex.
    let ifindex = msg.header.index;

    // Remove interface.
    if let Some(iface) = master.interfaces.get_by_ifindex(ifindex) {
        let ifname = iface.name.clone();
        master
            .interfaces
            .remove(&ifname, Owner::SYSTEM, &master.netlink_tx);
    }
}

fn process_newaddr_msg(master: &mut Master, msg: AddressMessage) {
    trace!(?msg, "received RTM_NEWADDR message");

    // Fetch address attributes.
    let mut addr = None;
    let ifindex = msg.header.index;
    for nla in msg.attributes.into_iter() {
        match nla {
            AddressAttribute::Address(nla_addr) => addr = Some(nla_addr),
            AddressAttribute::Flags(nla_flags) => {
                // Ignore the address if it is still undergoing Duplicate
                // Address Detection (DAD) or has failed DAD.
                if nla_flags.contains(AddressFlags::Tentative)
                    || nla_flags.contains(AddressFlags::Dadfailed)
                {
                    return;
                }
            }
            _ => (),
        }
    }
    let Some(addr) = addr else {
        return;
    };

    // Parse address.
    let Some(addr) = parse_address(
        msg.header.family.into(),
        msg.header.prefix_len,
        addr.bytes(),
    ) else {
        return;
    };

    // Add address to the interface.
    master.interfaces.addr_add(ifindex, addr);
}

fn process_deladdr_msg(master: &mut Master, msg: AddressMessage) {
    trace!(?msg, "received RTM_DELADDR message");

    // Fetch address attributes.
    let mut addr = None;
    let ifindex = msg.header.index;
    for nla in msg.attributes.into_iter() {
        match nla {
            AddressAttribute::Address(nla_addr) => addr = Some(nla_addr),
            _ => (),
        }
    }
    let Some(addr) = addr else {
        return;
    };

    // Parse address.
    let Some(addr) = parse_address(
        msg.header.family.into(),
        msg.header.prefix_len,
        addr.bytes(),
    ) else {
        return;
    };

    // Remove address from the interface.
    master.interfaces.addr_del(ifindex, addr);
}

fn parse_address(
    family: u8,
    prefixlen: u8,
    bytes: Vec<u8>,
) -> Option<IpNetwork> {
    let addr = match family as i32 {
        libc::AF_INET => {
            let mut addr_array: [u8; 4] = [0; 4];
            addr_array.copy_from_slice(&bytes);
            Ipv4Addr::from(addr_array).into()
        }
        libc::AF_INET6 => {
            let mut addr_array: [u8; 16] = [0; 16];
            addr_array.copy_from_slice(&bytes);
            Ipv6Addr::from(addr_array).into()
        }
        _ => return None,
    };
    IpNetwork::new(addr, prefixlen).ok()
}

// ===== global functions =====

pub(crate) fn admin_status_change(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    ifindex: u32,
    enabled: bool,
) {
    // Create netlink message.
    let mut msg = LinkMessageBuilder::<LinkUnspec>::new().index(ifindex);
    msg = if enabled { msg.up() } else { msg.down() };
    let msg = msg.build();

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::LinkSet(msg)).unwrap();
}

pub(crate) fn mtu_change(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    ifindex: u32,
    mtu: u32,
) {
    // Create netlink message.
    let msg = LinkMessageBuilder::<LinkUnspec>::new()
        .index(ifindex)
        .mtu(mtu)
        .build();

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::LinkSet(msg)).unwrap();
}

pub(crate) fn vlan_create(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    name: String,
    parent_ifindex: u32,
    vlan_id: u16,
) {
    // Create netlink message.
    let msg = LinkMessageBuilder::<LinkVlan>::new(&name)
        .link(parent_ifindex)
        .id(vlan_id)
        .build();

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::LinkAdd(msg)).unwrap();
}

pub(crate) fn macvlan_create(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    name: String,
    mac_address: Option<MacAddr>,
    parent_ifindex: u32,
) {
    // Create netlink message
    let mut msg = LinkMessageBuilder::<LinkMacVlan>::new(&name)
        .link(parent_ifindex)
        .mode(MacVlanMode::Bridge)
        .up();
    if let Some(address) = mac_address {
        msg = msg.address(address.as_bytes().to_vec());
    }
    let msg = msg.build();

    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::LinkAdd(msg)).unwrap();
}

pub(crate) fn iface_delete(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    ifindex: u32,
) {
    // Enqueue netlink request.
    netlink_tx.send(NetlinkRequest::LinkDel(ifindex)).unwrap();
}

pub(crate) fn addr_install(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    ifindex: u32,
    addr: &IpNetwork,
) {
    // Enqueue netlink request.
    netlink_tx
        .send(NetlinkRequest::AddressAdd(ifindex, *addr))
        .unwrap();
}

pub(crate) fn addr_uninstall(
    netlink_tx: &UnboundedSender<NetlinkRequest>,
    ifindex: u32,
    addr: &IpNetwork,
) {
    // Enqueue netlink request.
    netlink_tx
        .send(NetlinkRequest::AddressDel(ifindex, *addr))
        .unwrap();
}

pub(crate) fn process_msg(
    master: &mut Master,
    msg: NetlinkMessage<RouteNetlinkMessage>,
) {
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                process_newlink_msg(master, msg)
            }
            RouteNetlinkMessage::DelLink(msg) => {
                process_dellink_msg(master, msg)
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                process_newaddr_msg(master, msg)
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                process_deladdr_msg(master, msg)
            }
            _ => (),
        }
    }
}

pub(crate) async fn start(master: &mut Master, handle: &Handle) {
    // Fetch interface information.
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .expect("Failed to fetch interface information")
    {
        process_newlink_msg(master, msg);
    }

    // Fetch address information.
    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses
        .try_next()
        .await
        .expect("Failed to fetch interface address information")
    {
        process_newaddr_msg(master, msg);
    }
}

pub(crate) fn init() -> (Handle, NetlinkMonitor) {
    // Create netlink socket.
    let (conn, handle, _) =
        new_connection().expect("Failed to create netlink socket");

    // Spawn the netlink connection on a separate thread with permanent elevated
    // capabilities.
    std::thread::spawn(|| {
        // Raise capabilities.
        let mut caps = CapState::get_current().unwrap();
        caps.effective = caps.permitted;
        if let Err(error) = caps.set_current() {
            error!("failed to update current capabilities: {}", error);
        }

        // Serve requests initiated by the netlink handle.
        futures::executor::block_on(conn)
    });

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

    (handle, monitor)
}
