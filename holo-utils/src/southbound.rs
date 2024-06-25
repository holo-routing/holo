//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::net::IpAddr;

use bitflags::bitflags;
use enum_as_inner::EnumAsInner;
use holo_yang::{ToYang, TryFromYang};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::bier::{BfrId, BierInfo, Bsl, SubDomainId};
use crate::mpls::Label;
use crate::protocol::Protocol;

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct InterfaceFlags: u8 {
        const LOOPBACK = 0x01;
        const OPERATIVE = 0x02;
        const BROADCAST = 0x04;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AddressFlags: u8 {
        const UNNUMBERED = 0x01;
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum Nexthop {
    Address {
        ifindex: u32,
        addr: IpAddr,
        labels: Vec<Label>,
    },
    Interface {
        ifindex: u32,
    },
    Special(NexthopSpecial),
    Recursive {
        addr: IpAddr,
        labels: Vec<Label>,
        resolved: BTreeSet<Nexthop>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum NexthopSpecial {
    Blackhole,
    Unreachable,
    Prohibit,
}

// ===== Ibus messages =====

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct InterfaceUpdateMsg {
    pub ifname: String,
    pub ifindex: u32,
    pub mtu: u32,
    pub flags: InterfaceFlags,

    #[serde(skip)]
    pub mac_address: [u8; 6],
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct MacvlanCreateMsg {
    pub parent_name: String,
    pub name: String,
    pub mac_address: Option<[u8; 6]>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct InterfaceIpAddRequestMsg {
    pub ifindex: u32,
    pub addr: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct InterfaceIpDeleteRequestMsg {
    pub ifindex: u32,
    pub addr: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct AddressMsg {
    pub ifname: String,
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteMsg {
    pub protocol: Protocol,
    pub prefix: IpNetwork,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    #[serde(skip)]
    pub opaque_attrs: RouteOpaqueAttrs,
    pub nexthops: BTreeSet<Nexthop>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteKeyMsg {
    pub protocol: Protocol,
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierNbrInstallMsg {
    pub bier_info: BierInfo,
    pub nexthops: BTreeSet<Nexthop>,
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierNbrUninstallMsg {
    pub sd_id: SubDomainId,
    pub bfr_id: BfrId,
    pub bsl: Bsl,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelInstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: BTreeSet<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
    pub replace: bool,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelUninstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: BTreeSet<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
}

// Route opaque attributes.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
#[derive(EnumAsInner)]
pub enum RouteOpaqueAttrs {
    #[default]
    None,
    Ospf {
        route_type: OspfRouteType,
    },
    Isis {
        route_type: IsisRouteType,
    },
}

// OSPF route types in decreasing order of preference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum OspfRouteType {
    IntraArea,
    InterArea,
    Type1External,
    Type2External,
}

// IS-IS route types.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum IsisRouteType {
    L2IntraArea,
    L1IntraArea,
    L2External,
    L1External,
    L1InterArea,
    L1InterAreaExternal,
}

// ===== impl Nexthop =====

impl Nexthop {
    // Compares two `Nexthop` instances for equality.
    pub fn matches(&self, other: &Nexthop) -> bool {
        self == other
    }

    // Compares two `Nexthop` instances for equality, excluding the `labels`
    // field in the `Address` variant.
    pub fn matches_no_labels(&self, other: &Nexthop) -> bool {
        match (self, other) {
            (
                Nexthop::Address {
                    ifindex: ifindex1,
                    addr: addr1,
                    ..
                },
                Nexthop::Address {
                    ifindex: ifindex2,
                    addr: addr2,
                    ..
                },
            ) => ifindex1 == ifindex2 && addr1 == addr2,
            (
                Nexthop::Interface { ifindex: ifindex1 },
                Nexthop::Interface { ifindex: ifindex2 },
            ) => ifindex1 == ifindex2,
            (Nexthop::Special(nexthop1), Nexthop::Special(nexthop2)) => {
                nexthop1 == nexthop2
            }
            _ => false,
        }
    }

    // Removes all labels from a `Nexthop::Address` variant.
    pub fn remove_labels(&mut self) {
        if let Nexthop::Address { labels, .. } = self {
            *labels = Vec::new();
        }
    }

    // Copies the `labels` field from another `Nexthop` instance to this one.
    pub fn copy_labels(&mut self, other: &Nexthop) {
        if let (
            Nexthop::Address {
                labels: labels1, ..
            },
            Nexthop::Address {
                labels: labels2, ..
            },
        ) = (self, other)
        {
            labels1.clone_from(labels2)
        }
    }
}

// ===== impl NexthopSpecial =====

impl ToYang for NexthopSpecial {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            NexthopSpecial::Blackhole => "blackhole".into(),
            NexthopSpecial::Unreachable => "unreachable".into(),
            NexthopSpecial::Prohibit => "prohibit".into(),
        }
    }
}

impl TryFromYang for NexthopSpecial {
    fn try_from_yang(value: &str) -> Option<NexthopSpecial> {
        match value {
            "blackhole" => Some(NexthopSpecial::Blackhole),
            "unreachable" => Some(NexthopSpecial::Unreachable),
            "prohibit" => Some(NexthopSpecial::Prohibit),
            _ => None,
        }
    }
}

// ===== impl OspfRouteType =====

impl ToYang for OspfRouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            OspfRouteType::IntraArea => "intra-area".into(),
            OspfRouteType::InterArea => "inter-area".into(),
            OspfRouteType::Type1External => "external-1".into(),
            OspfRouteType::Type2External => "external-2".into(),
        }
    }
}

// ===== impl IsisRouteType =====

impl ToYang for IsisRouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            IsisRouteType::L2IntraArea => "l2-intra-area".into(),
            IsisRouteType::L1IntraArea => "l1-intra-area".into(),
            IsisRouteType::L2External => "l2-external".into(),
            IsisRouteType::L1External => "l1-external".into(),
            IsisRouteType::L1InterArea => "l1-inter-area".into(),
            IsisRouteType::L1InterAreaExternal => {
                "l1-inter-area-external".into()
            }
        }
    }
}
