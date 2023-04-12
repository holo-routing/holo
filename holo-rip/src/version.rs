//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use holo_utils::ip::{
    AddressFamily, IpAddrKind, IpNetworkKind, SocketAddrKind,
};
use holo_utils::protocol::Protocol;
use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::interface::InterfaceVersion;
use crate::network::NetworkVersion;
use crate::northbound::NorthboundVersion;
use crate::packet::{DecodeErrorVersion, PduVersion};
use crate::{ripng, ripv2};

// RIP version-specific code.
pub trait Version
where
    Self: 'static
        + Send
        + Default
        + std::fmt::Debug
        + InterfaceVersion<Self>
        + NetworkVersion
        + NorthboundVersion<Self>,
{
    const PROTOCOL: Protocol;
    const ADDRESS_FAMILY: AddressFamily;

    type IpAddr: IpAddrKind;
    type IpNetwork: IpNetworkKind<Self::IpAddr>;
    type SocketAddr: SocketAddrKind<Self::IpAddr>;
    type Pdu: PduVersion<Self::IpAddr, Self::IpNetwork, Self::PduDecodeError>;
    type PduDecodeError: DecodeErrorVersion;
}

#[derive(Debug, Default)]
pub struct Ripv2();

#[derive(Debug, Default)]
pub struct Ripng();

// ===== impl Ripv2 =====

impl Version for Ripv2 {
    const PROTOCOL: Protocol = Protocol::RIPV2;
    const ADDRESS_FAMILY: AddressFamily = AddressFamily::Ipv4;

    type IpAddr = Ipv4Addr;
    type IpNetwork = Ipv4Network;
    type SocketAddr = SocketAddrV4;
    type Pdu = ripv2::packet::Pdu;
    type PduDecodeError = ripv2::packet::DecodeError;
}

// ===== impl Ripng =====

impl Version for Ripng {
    const PROTOCOL: Protocol = Protocol::RIPNG;
    const ADDRESS_FAMILY: AddressFamily = AddressFamily::Ipv6;

    type IpAddr = Ipv6Addr;
    type IpNetwork = Ipv6Network;
    type SocketAddr = SocketAddrV6;
    type Pdu = ripng::packet::Pdu;
    type PduDecodeError = ripng::packet::DecodeError;
}
