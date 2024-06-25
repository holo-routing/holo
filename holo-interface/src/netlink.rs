//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{Ipv4Addr, Ipv6Addr};

use capctl::caps::CapState;
use futures::channel::mpsc::UnboundedReceiver;
use futures::TryStreamExt;
use holo_utils::ip::IpAddrExt;
use holo_utils::southbound::InterfaceFlags;
use ipnetwork::IpNetwork;
use libc::{RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_LINK};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{
    LinkAttribute, LinkFlag, LinkLayerType, LinkMessage,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{new_connection, Handle};
use tracing::{error, trace};

use crate::interface::Owner;
use crate::Master;

pub const MACVLAN_MODE_BRIDGE: u32 = 4;

pub type NetlinkMonitor =
    UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

// ===== helper functions =====

async fn process_newlink_msg(
    master: &mut Master,
    msg: LinkMessage,
    notify: bool,
) {
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

    if msg.header.flags.contains(&LinkFlag::Running) {
        flags.insert(InterfaceFlags::OPERATIVE);
    }
    if msg.header.flags.contains(&LinkFlag::Broadcast) {
        flags.insert(InterfaceFlags::BROADCAST)
    }

    for nla in msg.attributes.into_iter() {
        match nla {
            LinkAttribute::IfName(nla_ifname) => ifname = Some(nla_ifname),
            LinkAttribute::Mtu(nla_mtu) => mtu = Some(nla_mtu),
            LinkAttribute::Address(addr) => {
                mac_address = addr.try_into().unwrap_or([0u8; 6]);
            }
            _ => (),
        }
    }
    let (Some(ifname), Some(mtu)) = (ifname, mtu) else {
        return;
    };

    // Add or update interface.
    let ibus_tx = notify.then_some(&master.ibus_tx);
    master
        .interfaces
        .update(
            ifname,
            ifindex,
            mtu,
            flags,
            mac_address,
            &master.netlink_handle,
            ibus_tx,
        )
        .await;
}

async fn process_dellink_msg(
    master: &mut Master,
    msg: LinkMessage,
    notify: bool,
) {
    trace!(?msg, "received RTM_DELLINK message");

    // Fetch interface ifindex.
    let ifindex = msg.header.index;

    // Remove interface.
    if let Some(iface) = master.interfaces.get_by_ifindex(ifindex) {
        let ibus_tx = notify.then_some(&master.ibus_tx);
        let ifname = iface.name.clone();
        master
            .interfaces
            .remove(&ifname, Owner::SYSTEM, &master.netlink_handle, ibus_tx)
            .await;
    }
}

fn process_newaddr_msg(master: &mut Master, msg: AddressMessage, notify: bool) {
    trace!(?msg, "received RTM_NEWADDR message");

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

    // Add address to the interface.
    let ibus_tx = notify.then_some(&master.ibus_tx);
    master.interfaces.addr_add(ifindex, addr, ibus_tx);
}

fn process_deladdr_msg(master: &mut Master, msg: AddressMessage, notify: bool) {
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
    let ibus_tx = notify.then_some(&master.ibus_tx);
    master.interfaces.addr_del(ifindex, addr, ibus_tx);
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

pub(crate) async fn admin_status_change(
    handle: &Handle,
    ifindex: u32,
    enabled: bool,
) {
    // Create netlink request.
    let request = handle.link().set(ifindex);
    let request = if enabled {
        request.up()
    } else {
        request.down()
    };

    // Execute request.
    if let Err(error) = request.execute().await {
        error!(%ifindex, %enabled, %error, "failed to change interface's admin status");
    }
}

pub(crate) async fn mtu_change(handle: &Handle, ifindex: u32, mtu: u32) {
    // Create netlink request.
    let request = handle.link().set(ifindex).mtu(mtu);

    // Execute request.
    if let Err(error) = request.execute().await {
        error!(%ifindex, %mtu, %error, "failed to change interface's MTU");
    }
}

pub(crate) async fn vlan_create(
    handle: &Handle,
    name: String,
    parent_ifindex: u32,
    vlan_id: u16,
) {
    // Create netlink request.
    let request = handle.link().add().vlan(name, parent_ifindex, vlan_id);

    // Execute request.
    if let Err(error) = request.execute().await {
        error!(%parent_ifindex, %vlan_id, %error, "failed to create VLAN interface");
    }
}

/// Creates MacVlan interface
/// uses RTM_NEWLINK.
///
/// # Arguments
///
/// * `parent_ifindex` - index of the primary interface this macvlan will be bridging from
/// * `name` - name of the macvlan link that we will be creating
pub(crate) async fn macvlan_create(
    handle: &Handle,
    name: String,
    mac_address: Option<[u8; 6]>,
    parent_ifindex: u32,
) {
    // Create netlink request
    let mut request = handle.link().add().macvlan(
        name.clone(),
        parent_ifindex,
        MACVLAN_MODE_BRIDGE,
    );

    if let Some(address) = mac_address {
        request = request.address(address.to_vec());
    }

    // Execute request.
    if let Err(error) = request.execute().await {
        error!(%parent_ifindex, %name, %error, "Failed to create MacVlan interface");
    }
}

// Removes an interface completely from the system.
//
// At the moment, will mostly be used for uninstalling
// Macvlan interfaces when we are removing a VRRP instance.
pub(crate) async fn iface_delete(handle: &Handle, ifindex: u32) {
    let request = handle.link().del(ifindex);
    if let Err(err) = request.execute().await {
        error!(%ifindex, %err, "failed to delete interface.");
    }
}

pub(crate) async fn addr_install(
    handle: &Handle,
    ifindex: u32,
    addr: &IpNetwork,
) {
    // Create netlink request.
    let request = handle.address().add(ifindex, addr.ip(), addr.prefix());

    // Execute request.
    if let Err(error) = request.execute().await {
        error!(%ifindex, %addr, %error, "failed to install interface address");
    }
}

pub(crate) async fn addr_uninstall(
    handle: &Handle,
    ifindex: u32,
    addr: &IpNetwork,
) {
    // Create netlink request.
    let mut request = handle.address().add(ifindex, addr.ip(), addr.prefix());

    // Execute request.
    let request = handle.address().del(request.message_mut().clone());
    if let Err(error) = request.execute().await {
        error!(%ifindex, %addr, %error, "failed to uninstall interface address");
    }
}

pub(crate) async fn process_msg(
    master: &mut Master,
    msg: NetlinkMessage<RouteNetlinkMessage>,
) {
    if let NetlinkPayload::InnerMessage(msg) = msg.payload {
        match msg {
            RouteNetlinkMessage::NewLink(msg) => {
                process_newlink_msg(master, msg, true).await
            }
            RouteNetlinkMessage::DelLink(msg) => {
                process_dellink_msg(master, msg, true).await
            }
            RouteNetlinkMessage::NewAddress(msg) => {
                process_newaddr_msg(master, msg, true)
            }
            RouteNetlinkMessage::DelAddress(msg) => {
                process_deladdr_msg(master, msg, true)
            }
            _ => (),
        }
    }
}

pub(crate) async fn start(master: &mut Master) {
    // Fetch interface information.
    let mut links = master.netlink_handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .expect("Failed to fetch interface information")
    {
        process_newlink_msg(master, msg, false).await;
    }

    // Fetch address information.
    let mut addresses = master.netlink_handle.address().get().execute();
    while let Some(msg) = addresses
        .try_next()
        .await
        .expect("Failed to fetch interface address information")
    {
        process_newaddr_msg(master, msg, false);
    }
}

pub(crate) async fn init() -> (Handle, NetlinkMonitor) {
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
