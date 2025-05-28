//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

use arbitrary::Arbitrary;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::{IpNetwork, IpNetworkError, Ipv4Network, Ipv6Network};
use num_derive::{FromPrimitive, ToPrimitive};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// Address Family identifier.
//
// IANA registry:
// http://www.iana.org/assignments/address-family-numbers
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(FromPrimitive, ToPrimitive)]
#[derive(Deserialize, Serialize)]
#[derive(Arbitrary)]
pub enum AddressFamily {
    Ipv4 = 1,
    Ipv6 = 2,
}

// Container for storing separate values for IPv4 and IPv6.
#[derive(Debug, Default)]
pub struct AddressFamilies<T> {
    pub ipv4: T,
    pub ipv6: T,
}

// Extension methods for IpAddr.
pub trait IpAddrExt {
    // Returns length of the IP address.
    fn length(&self) -> usize;

    // Returns vector of bytes that make up this address.
    fn bytes(&self) -> Vec<u8>;

    // Returns true if this is an usable address.
    fn is_usable(&self) -> bool;

    // Converts this IP address into a host prefix network.
    fn to_host_prefix(&self) -> IpNetwork;

    // Returns an unspecified address of the given address family.
    fn unspecified(af: AddressFamily) -> IpAddr;
}

// Extension methods for Ipv4Addr.
pub trait Ipv4AddrExt {
    const LENGTH: usize;

    // Returns true if this is an usable address.
    fn is_usable(&self) -> bool;

    // Converts this IPv4 address into a host prefix network.
    fn to_host_prefix(&self) -> Ipv4Network;
}

// Extension methods for Ipv6Addr.
pub trait Ipv6AddrExt {
    const LENGTH: usize;

    // Returns true if this is an usable address.
    fn is_usable(&self) -> bool;

    // Converts this IPv6 address into a host prefix network.
    fn to_host_prefix(&self) -> Ipv6Network;
}

// Extension methods for IpNetwork.
pub trait IpNetworkExt {
    // Apply mask to prefix.
    #[must_use]
    fn apply_mask(&self) -> IpNetwork;

    // Returns true if this is a routable network.
    fn is_routable(&self) -> bool;
}

// Extension methods for Ipv4Network.
pub trait Ipv4NetworkExt {
    const MAX_PREFIXLEN: u8;

    // Apply mask to prefix.
    #[must_use]
    fn apply_mask(&self) -> Ipv4Network;

    // Returns true if this is a host prefix.
    fn is_host_prefix(&self) -> bool;

    // Returns true if this is a routable network.
    fn is_routable(&self) -> bool;
}

// Extension methods for Ipv6Network.
pub trait Ipv6NetworkExt {
    const MAX_PREFIXLEN: u8;

    // Apply mask to prefix.
    #[must_use]
    fn apply_mask(&self) -> Ipv6Network;

    // Returns true if this is a host prefix.
    fn is_host_prefix(&self) -> bool;

    // Returns true if this is a routable network.
    fn is_routable(&self) -> bool;
}

pub trait IpAddrKind:
    std::fmt::Debug
    + std::fmt::Display
    + Clone
    + Copy
    + Eq
    + std::hash::Hash
    + Ord
    + PartialEq
    + PartialOrd
    + Send
    + Sync
    + DeserializeOwned
    + Serialize
    + Into<IpAddr>
{
    fn address_family(&self) -> AddressFamily;

    fn get(addr: IpAddr) -> Option<Self>;

    fn is_usable(&self) -> bool;
}

pub trait IpNetworkKind<I: IpAddrKind>:
    std::fmt::Debug
    + std::fmt::Display
    + Clone
    + Copy
    + Eq
    + std::hash::Hash
    + Ord
    + PartialEq
    + PartialOrd
    + Send
    + Sync
    + DeserializeOwned
    + Serialize
    + Into<IpNetwork>
{
    fn new(addr: I, prefix: u8) -> Result<Self, IpNetworkError>;

    fn default(af: AddressFamily) -> Self;

    fn address_family(&self) -> AddressFamily;

    fn get(prefix: IpNetwork) -> Option<Self>;

    fn contains(&self, ip: I) -> bool;

    fn is_supernet_of(self, other: Self) -> bool;

    fn ip(&self) -> I;

    fn mask(&self) -> I;

    #[must_use]
    fn apply_mask(&self) -> Self;

    fn is_routable(&self) -> bool;
}

pub trait SocketAddrKind<I: IpAddrKind>:
    std::fmt::Debug
    + std::fmt::Display
    + Clone
    + Copy
    + Eq
    + Ord
    + PartialEq
    + PartialOrd
    + Send
    + Sync
    + DeserializeOwned
    + Serialize
    + tokio::net::ToSocketAddrs
    + Into<SocketAddr>
{
    fn new(ip: I, port: u16) -> Self;

    fn get(sockaddr: SocketAddr) -> Option<Self>;

    fn ip(&self) -> &I;

    fn port(&self) -> u16;
}

// ===== impl AddressFamily =====

impl AddressFamily {
    pub fn addr_len(&self) -> usize {
        match self {
            AddressFamily::Ipv4 => Ipv4Addr::LENGTH,
            AddressFamily::Ipv6 => Ipv6Addr::LENGTH,
        }
    }

    pub fn max_prefixlen(&self) -> u8 {
        match self {
            AddressFamily::Ipv4 => Ipv4Network::MAX_PREFIXLEN,
            AddressFamily::Ipv6 => Ipv6Network::MAX_PREFIXLEN,
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::Ipv4 => write!(f, "IPv4"),
            AddressFamily::Ipv6 => write!(f, "IPv6"),
        }
    }
}

impl ToYang for AddressFamily {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            AddressFamily::Ipv4 => "ipv4".into(),
            AddressFamily::Ipv6 => "ipv6".into(),
        }
    }
}

impl TryFromYang for AddressFamily {
    fn try_from_yang(value: &str) -> Option<AddressFamily> {
        match value {
            "ipv4" => Some(AddressFamily::Ipv4),
            "ipv6" => Some(AddressFamily::Ipv6),
            _ => None,
        }
    }
}

// ===== impl AddressFamilies =====

impl<T> AddressFamilies<T> {
    // Returns a reference to the value corresponding to the given address
    // family.
    pub fn get(&self, af: AddressFamily) -> &T {
        match af {
            AddressFamily::Ipv4 => &self.ipv4,
            AddressFamily::Ipv6 => &self.ipv6,
        }
    }

    // Returns a mutable reference to the value corresponding to the given
    // address family.
    pub fn get_mut(&mut self, af: AddressFamily) -> &mut T {
        match af {
            AddressFamily::Ipv4 => &mut self.ipv4,
            AddressFamily::Ipv6 => &mut self.ipv6,
        }
    }

    // Returns an iterator over immutable references to all address family
    // values.
    pub fn iter(&self) -> impl Iterator<Item = (AddressFamily, &T)> {
        [
            (AddressFamily::Ipv4, &self.ipv4),
            (AddressFamily::Ipv6, &self.ipv6),
        ]
        .into_iter()
    }

    // Returns an iterator over mutable references to all address family
    // values.
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (AddressFamily, &mut T)> {
        [
            (AddressFamily::Ipv4, &mut self.ipv4),
            (AddressFamily::Ipv6, &mut self.ipv6),
        ]
        .into_iter()
    }
}

// ===== impl IpAddr =====

impl IpAddrExt for IpAddr {
    fn length(&self) -> usize {
        match self {
            IpAddr::V4(_) => Ipv4Addr::LENGTH,
            IpAddr::V6(_) => Ipv6Addr::LENGTH,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }

    fn is_usable(&self) -> bool {
        !(self.is_loopback() || self.is_multicast() || self.is_unspecified())
    }

    fn to_host_prefix(&self) -> IpNetwork {
        match self {
            IpAddr::V4(addr) => addr.to_host_prefix().into(),
            IpAddr::V6(addr) => addr.to_host_prefix().into(),
        }
    }

    fn unspecified(af: AddressFamily) -> IpAddr {
        match af {
            AddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl IpAddrKind for IpAddr {
    fn address_family(&self) -> AddressFamily {
        match self {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    fn get(addr: IpAddr) -> Option<Self> {
        Some(addr)
    }

    fn is_usable(&self) -> bool {
        IpAddrExt::is_usable(self)
    }
}

// ===== impl Ipv4Addr =====

impl Ipv4AddrExt for Ipv4Addr {
    const LENGTH: usize = 4;

    fn is_usable(&self) -> bool {
        !(self.is_loopback()
            || self.is_broadcast()
            || self.is_multicast()
            || self.is_unspecified())
    }

    fn to_host_prefix(&self) -> Ipv4Network {
        Ipv4Network::new(*self, Ipv4Network::MAX_PREFIXLEN).unwrap()
    }
}

impl IpAddrKind for Ipv4Addr {
    fn address_family(&self) -> AddressFamily {
        AddressFamily::Ipv4
    }

    fn get(addr: IpAddr) -> Option<Self> {
        match addr {
            IpAddr::V4(addr) => Some(addr),
            _ => None,
        }
    }

    fn is_usable(&self) -> bool {
        Ipv4AddrExt::is_usable(self)
    }
}

// ===== impl Ipv6Addr =====

impl Ipv6AddrExt for Ipv6Addr {
    const LENGTH: usize = 16;

    fn is_usable(&self) -> bool {
        !(self.is_loopback() || self.is_multicast() || self.is_unspecified())
    }

    fn to_host_prefix(&self) -> Ipv6Network {
        Ipv6Network::new(*self, Ipv6Network::MAX_PREFIXLEN).unwrap()
    }
}

impl IpAddrKind for Ipv6Addr {
    fn address_family(&self) -> AddressFamily {
        AddressFamily::Ipv6
    }

    fn get(addr: IpAddr) -> Option<Self> {
        match addr {
            IpAddr::V6(addr) => Some(addr),
            _ => None,
        }
    }

    fn is_usable(&self) -> bool {
        Ipv6AddrExt::is_usable(self)
    }
}

// ===== impl IpNetwork =====

impl IpNetworkExt for IpNetwork {
    fn apply_mask(&self) -> IpNetwork {
        match self {
            IpNetwork::V4(prefix) => {
                IpNetwork::V4(Ipv4NetworkExt::apply_mask(prefix))
            }
            IpNetwork::V6(prefix) => {
                IpNetwork::V6(Ipv6NetworkExt::apply_mask(prefix))
            }
        }
    }

    fn is_routable(&self) -> bool {
        match self {
            IpNetwork::V4(prefix) => Ipv4NetworkExt::is_routable(prefix),
            IpNetwork::V6(prefix) => Ipv6NetworkExt::is_routable(prefix),
        }
    }
}

impl IpNetworkKind<IpAddr> for IpNetwork {
    fn new(addr: IpAddr, prefix: u8) -> Result<Self, IpNetworkError> {
        IpNetwork::new(addr, prefix)
    }

    fn default(af: AddressFamily) -> Self {
        IpNetwork::new(IpAddr::unspecified(af), 0).unwrap()
    }

    fn address_family(&self) -> AddressFamily {
        match self {
            IpNetwork::V4(_) => AddressFamily::Ipv4,
            IpNetwork::V6(_) => AddressFamily::Ipv6,
        }
    }

    fn get(prefix: IpNetwork) -> Option<Self> {
        Some(prefix)
    }

    fn contains(&self, ip: IpAddr) -> bool {
        IpNetwork::contains(self, ip)
    }

    fn is_supernet_of(self, other: Self) -> bool {
        match (self, other) {
            (IpNetwork::V4(a), IpNetwork::V4(b)) => {
                Ipv4Network::is_supernet_of(a, b)
            }
            (IpNetwork::V6(a), IpNetwork::V6(b)) => {
                Ipv6Network::is_supernet_of(a, b)
            }
            _ => false,
        }
    }

    fn ip(&self) -> IpAddr {
        IpNetwork::ip(self)
    }

    fn mask(&self) -> IpAddr {
        IpNetwork::mask(self)
    }

    fn apply_mask(&self) -> Self {
        IpNetworkExt::apply_mask(self)
    }

    fn is_routable(&self) -> bool {
        IpNetworkExt::is_routable(self)
    }
}

// ===== impl Ipv4Network =====

impl Ipv4NetworkExt for Ipv4Network {
    const MAX_PREFIXLEN: u8 = 32;

    fn apply_mask(&self) -> Ipv4Network {
        Ipv4Network::new(self.network(), self.prefix()).unwrap()
    }

    fn is_host_prefix(&self) -> bool {
        self.prefix() == Self::MAX_PREFIXLEN
    }

    fn is_routable(&self) -> bool {
        !self.ip().is_broadcast()
            && !self.ip().is_loopback()
            && !self.ip().is_multicast()
            // Treat addresses in the 240.0.0.0/4 block (reserved for future
            // use) as non-routable.
            && self.ip().octets()[0] < 240
    }
}

impl IpNetworkKind<Ipv4Addr> for Ipv4Network {
    fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, IpNetworkError> {
        Ipv4Network::new(addr, prefix)
    }

    fn default(_family: AddressFamily) -> Self {
        Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()
    }

    fn address_family(&self) -> AddressFamily {
        AddressFamily::Ipv4
    }

    fn get(prefix: IpNetwork) -> Option<Self> {
        match prefix {
            IpNetwork::V4(prefix) => Some(prefix),
            _ => None,
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        Ipv4Network::contains(*self, ip)
    }

    fn is_supernet_of(self, other: Self) -> bool {
        Ipv4Network::is_supernet_of(self, other)
    }

    fn ip(&self) -> Ipv4Addr {
        Ipv4Network::ip(*self)
    }

    fn mask(&self) -> Ipv4Addr {
        Ipv4Network::mask(*self)
    }

    fn apply_mask(&self) -> Self {
        Ipv4NetworkExt::apply_mask(self)
    }

    fn is_routable(&self) -> bool {
        Ipv4NetworkExt::is_routable(self)
    }
}

// ===== impl Ipv6Network =====

impl Ipv6NetworkExt for Ipv6Network {
    const MAX_PREFIXLEN: u8 = 128;

    fn apply_mask(&self) -> Ipv6Network {
        Ipv6Network::new(self.network(), self.prefix()).unwrap()
    }

    fn is_host_prefix(&self) -> bool {
        self.prefix() == Self::MAX_PREFIXLEN
    }

    fn is_routable(&self) -> bool {
        !self.ip().is_loopback()
            && !self.ip().is_multicast()
            && !self.ip().is_unicast_link_local()
    }
}

impl IpNetworkKind<Ipv6Addr> for Ipv6Network {
    fn new(addr: Ipv6Addr, prefix: u8) -> Result<Self, IpNetworkError> {
        Ipv6Network::new(addr, prefix)
    }

    fn default(_family: AddressFamily) -> Self {
        Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()
    }

    fn address_family(&self) -> AddressFamily {
        AddressFamily::Ipv6
    }

    fn get(prefix: IpNetwork) -> Option<Self> {
        match prefix {
            IpNetwork::V6(prefix) => Some(prefix),
            _ => None,
        }
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        Ipv6Network::contains(self, ip)
    }

    fn is_supernet_of(self, other: Self) -> bool {
        Ipv6Network::is_supernet_of(self, other)
    }

    fn ip(&self) -> Ipv6Addr {
        Ipv6Network::ip(self)
    }

    fn mask(&self) -> Ipv6Addr {
        Ipv6Network::mask(self)
    }

    fn apply_mask(&self) -> Self {
        Ipv6NetworkExt::apply_mask(self)
    }

    fn is_routable(&self) -> bool {
        Ipv6NetworkExt::is_routable(self)
    }
}

// ===== impl SocketAddrV4 =====

impl SocketAddrKind<Ipv4Addr> for SocketAddrV4 {
    fn new(ip: Ipv4Addr, port: u16) -> Self {
        SocketAddrV4::new(ip, port)
    }

    fn get(sockaddr: SocketAddr) -> Option<Self> {
        match sockaddr {
            SocketAddr::V4(sockaddr) => Some(sockaddr),
            _ => None,
        }
    }

    fn ip(&self) -> &Ipv4Addr {
        self.ip()
    }

    fn port(&self) -> u16 {
        self.port()
    }
}

// ===== impl SocketAddrV6 =====

impl SocketAddrKind<Ipv6Addr> for SocketAddrV6 {
    fn new(ip: Ipv6Addr, port: u16) -> Self {
        SocketAddrV6::new(ip, port, 0, 0)
    }

    fn get(sockaddr: SocketAddr) -> Option<Self> {
        match sockaddr {
            SocketAddr::V6(sockaddr) => Some(sockaddr),
            _ => None,
        }
    }

    fn ip(&self) -> &Ipv6Addr {
        self.ip()
    }

    fn port(&self) -> u16 {
        self.port()
    }
}
