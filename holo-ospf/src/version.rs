//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{IpAddr, Ipv4Addr};

use holo_utils::ip::{IpAddrKind, IpNetworkKind};
use holo_utils::protocol::Protocol;
use ipnetwork::{IpNetwork, Ipv4Network};

use crate::area::AreaVersion;
use crate::instance::InstanceVersion;
use crate::interface::InterfaceVersion;
use crate::lsdb::LsdbVersion;
use crate::neighbor::NeighborVersion;
use crate::network::NetworkVersion;
use crate::northbound::NorthboundVersion;
use crate::packet::lsa::LsaVersion;
use crate::packet::PacketVersion;
use crate::southbound::rx::SouthboundRxVersion;
use crate::spf::SpfVersion;

// OSPF version-specific code.
pub trait Version
where
    Self: 'static
        + Send
        + Sync
        + Clone
        + Default
        + Eq
        + PartialEq
        + std::fmt::Debug
        + AreaVersion<Self>
        + LsdbVersion<Self>
        + InstanceVersion<Self>
        + InterfaceVersion<Self>
        + NeighborVersion<Self>
        + NetworkVersion<Self>
        + NorthboundVersion<Self>
        + PacketVersion<Self>
        + LsaVersion<Self>
        + SouthboundRxVersion<Self>
        + SpfVersion<Self>,
{
    const PROTOCOL: Protocol;

    type IpAddr: IpAddrKind;
    type IpNetwork: IpNetworkKind<Self::IpAddr>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ospfv2();

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ospfv3();

// ===== impl Ospfv2 =====

impl Version for Ospfv2 {
    const PROTOCOL: Protocol = Protocol::OSPFV2;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;
}

// ===== impl Ospfv3 =====

impl Version for Ospfv3 {
    const PROTOCOL: Protocol = Protocol::OSPFV3;

    type IpAddr = IpAddr;
    type IpNetwork = IpNetwork;
}
