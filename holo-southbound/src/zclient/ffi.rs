//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bitflags::bitflags;
use holo_utils::ip::AddressFamily;
use holo_utils::protocol::Protocol;
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

pub const ZEBRA_HEADER_SIZE: u16 = 10;
pub const ZEBRA_HEADER_MARKER: u8 = 254;
pub const ZSERV_VERSION: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum RouteType {
    System = 0,
    Kernel = 1,
    Connect = 2,
    Static = 3,
    Rip = 4,
    Ripng = 5,
    Ospf = 6,
    Ospf6 = 7,
    Isis = 8,
    Bgp = 9,
    Pim = 10,
    Eigrp = 11,
    Nhrp = 12,
    Hsls = 13,
    Olsr = 14,
    Table = 15,
    Ldp = 16,
    Vnc = 17,
    VncDirect = 18,
    VncDirectRh = 19,
    BgpDirect = 20,
    BgpDirectExt = 21,
    Babel = 22,
    Sharp = 23,
    Pbr = 24,
    Bfd = 25,
    Openfabric = 26,
    Vrrp = 27,
    Nhg = 28,
    Srte = 29,
    All = 30,
}

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum NexthopType {
    Ifindex = 1,
    Ipv4 = 2,
    Ipv4Ifindex = 3,
    Ipv6 = 4,
    Ipv6Ifindex = 5,
    Blackhole = 6,
}

#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum LspType {
    None = 0,
    Static = 1,
    Ldp = 2,
    Bgp = 3,
    OspfSr = 4,
    IsisSr = 5,
    Sharp = 6,
    Srte = 7,
}

bitflags! {
    #[derive(Default)]
    pub struct AddressFlags: u8 {
        const SECONDARY = 0x01;
        const PEER = 0x02;
        const UNNUMBERED = 0x04;
    }
}

pub mod zebra_message_types_t {
    pub type Type = u16;
    pub const INTERFACE_ADD: Type = 0;
    pub const INTERFACE_DELETE: Type = 1;
    pub const INTERFACE_ADDRESS_ADD: Type = 2;
    pub const INTERFACE_ADDRESS_DELETE: Type = 3;
    pub const INTERFACE_UP: Type = 4;
    pub const INTERFACE_DOWN: Type = 5;
    pub const INTERFACE_SET_MASTER: Type = 6;
    pub const INTERFACE_SET_PROTODOWN: Type = 7;
    pub const ROUTE_ADD: Type = 8;
    pub const ROUTE_DELETE: Type = 9;
    pub const ROUTE_NOTIFY_OWNER: Type = 10;
    pub const REDISTRIBUTE_ADD: Type = 11;
    pub const REDISTRIBUTE_DELETE: Type = 12;
    pub const REDISTRIBUTE_DEFAULT_ADD: Type = 13;
    pub const REDISTRIBUTE_DEFAULT_DELETE: Type = 14;
    pub const ROUTER_ID_ADD: Type = 15;
    pub const ROUTER_ID_DELETE: Type = 16;
    pub const ROUTER_ID_UPDATE: Type = 17;
    pub const HELLO: Type = 18;
    pub const CAPABILITIES: Type = 19;
    pub const NEXTHOP_REGISTER: Type = 20;
    pub const NEXTHOP_UNREGISTER: Type = 21;
    pub const NEXTHOP_UPDATE: Type = 22;
    pub const INTERFACE_NBR_ADDRESS_ADD: Type = 23;
    pub const INTERFACE_NBR_ADDRESS_DELETE: Type = 24;
    pub const INTERFACE_BFD_DEST_UPDATE: Type = 25;
    pub const BFD_DEST_REGISTER: Type = 26;
    pub const BFD_DEST_DEREGISTER: Type = 27;
    pub const BFD_DEST_UPDATE: Type = 28;
    pub const BFD_DEST_REPLAY: Type = 29;
    pub const REDISTRIBUTE_ROUTE_ADD: Type = 30;
    pub const REDISTRIBUTE_ROUTE_DEL: Type = 31;
    pub const VRF_UNREGISTER: Type = 32;
    pub const VRF_ADD: Type = 33;
    pub const VRF_DELETE: Type = 34;
    pub const VRF_LABEL: Type = 35;
    pub const INTERFACE_VRF_UPDATE: Type = 36;
    pub const BFD_CLIENT_REGISTER: Type = 37;
    pub const BFD_CLIENT_DEREGISTER: Type = 38;
    pub const INTERFACE_ENABLE_RADV: Type = 39;
    pub const INTERFACE_DISABLE_RADV: Type = 40;
    pub const IPV4_NEXTHOP_LOOKUP_MRIB: Type = 41;
    pub const INTERFACE_LINK_PARAMS: Type = 42;
    pub const MPLS_LABELS_ADD: Type = 43;
    pub const MPLS_LABELS_DELETE: Type = 44;
    pub const MPLS_LABELS_REPLACE: Type = 45;
    pub const SR_POLICY_SET: Type = 46;
    pub const SR_POLICY_DELETE: Type = 47;
    pub const SR_POLICY_NOTIFY_STATUS: Type = 48;
    pub const IPMR_ROUTE_STATS: Type = 49;
    pub const LABEL_MANAGER_CONNECT: Type = 50;
    pub const LABEL_MANAGER_CONNECT_ASYNC: Type = 51;
    pub const GET_LABEL_CHUNK: Type = 52;
    pub const RELEASE_LABEL_CHUNK: Type = 53;
    pub const FEC_REGISTER: Type = 54;
    pub const FEC_UNREGISTER: Type = 55;
    pub const FEC_UPDATE: Type = 56;
    pub const ADVERTISE_DEFAULT_GW: Type = 57;
    pub const ADVERTISE_SVI_MACIP: Type = 58;
    pub const ADVERTISE_SUBNET: Type = 59;
    pub const ADVERTISE_ALL_VNI: Type = 60;
    pub const LOCAL_ES_ADD: Type = 61;
    pub const LOCAL_ES_DEL: Type = 62;
    pub const REMOTE_ES_VTEP_ADD: Type = 63;
    pub const REMOTE_ES_VTEP_DEL: Type = 64;
    pub const LOCAL_ES_EVI_ADD: Type = 65;
    pub const LOCAL_ES_EVI_DEL: Type = 66;
    pub const VNI_ADD: Type = 67;
    pub const VNI_DEL: Type = 68;
    pub const L3VNI_ADD: Type = 69;
    pub const L3VNI_DEL: Type = 70;
    pub const REMOTE_VTEP_ADD: Type = 71;
    pub const REMOTE_VTEP_DEL: Type = 72;
    pub const MACIP_ADD: Type = 73;
    pub const MACIP_DEL: Type = 74;
    pub const IP_PREFIX_ROUTE_ADD: Type = 75;
    pub const IP_PREFIX_ROUTE_DEL: Type = 76;
    pub const REMOTE_MACIP_ADD: Type = 77;
    pub const REMOTE_MACIP_DEL: Type = 78;
    pub const DUPLICATE_ADDR_DETECTION: Type = 79;
    pub const PW_ADD: Type = 80;
    pub const PW_DELETE: Type = 81;
    pub const PW_SET: Type = 82;
    pub const PW_UNSET: Type = 83;
    pub const PW_STATUS_UPDATE: Type = 84;
    pub const RULE_ADD: Type = 85;
    pub const RULE_DELETE: Type = 86;
    pub const RULE_NOTIFY_OWNER: Type = 87;
    pub const TABLE_MANAGER_CONNECT: Type = 88;
    pub const GET_TABLE_CHUNK: Type = 89;
    pub const RELEASE_TABLE_CHUNK: Type = 90;
    pub const IPSET_CREATE: Type = 91;
    pub const IPSET_DESTROY: Type = 92;
    pub const IPSET_ENTRY_ADD: Type = 93;
    pub const IPSET_ENTRY_DELETE: Type = 94;
    pub const IPSET_NOTIFY_OWNER: Type = 95;
    pub const IPSET_ENTRY_NOTIFY_OWNER: Type = 96;
    pub const IPTABLE_ADD: Type = 97;
    pub const IPTABLE_DELETE: Type = 98;
    pub const IPTABLE_NOTIFY_OWNER: Type = 99;
    pub const VXLAN_FLOOD_CONTROL: Type = 100;
    pub const VXLAN_SG_ADD: Type = 101;
    pub const VXLAN_SG_DEL: Type = 102;
    pub const VXLAN_SG_REPLAY: Type = 103;
    pub const MLAG_PROCESS_UP: Type = 104;
    pub const MLAG_PROCESS_DOWN: Type = 105;
    pub const MLAG_CLIENT_REGISTER: Type = 106;
    pub const MLAG_CLIENT_UNREGISTER: Type = 107;
    pub const MLAG_FORWARD_MSG: Type = 108;
    pub const NHG_ADD: Type = 109;
    pub const NHG_DEL: Type = 110;
    pub const NHG_NOTIFY_OWNER: Type = 111;
    pub const EVPN_REMOTE_NH_ADD: Type = 112;
    pub const EVPN_REMOTE_NH_DEL: Type = 113;
    pub const SRV6_LOCATOR_ADD: Type = 114;
    pub const SRV6_LOCATOR_DELETE: Type = 115;
    pub const SRV6_MANAGER_GET_LOCATOR_CHUNK: Type = 116;
    pub const SRV6_MANAGER_RELEASE_LOCATOR_CHUNK: Type = 117;
    pub const ERROR: Type = 118;
    pub const CLIENT_CAPABILITIES: Type = 119;
    pub const OPAQUE_MESSAGE: Type = 120;
    pub const OPAQUE_REGISTER: Type = 121;
    pub const OPAQUE_UNREGISTER: Type = 122;
    pub const NEIGH_DISCOVER: Type = 123;
    pub const ROUTE_NOTIFY_REQUEST: Type = 124;
    pub const CLIENT_CLOSE_NOTIFY: Type = 125;
    pub const NHRP_NEIGH_ADDED: Type = 126;
    pub const NHRP_NEIGH_REMOVED: Type = 127;
    pub const NHRP_NEIGH_GET: Type = 128;
    pub const NHRP_NEIGH_REGISTER: Type = 129;
    pub const NHRP_NEIGH_UNREGISTER: Type = 130;
    pub const NEIGH_IP_ADD: Type = 131;
    pub const NEIGH_IP_DEL: Type = 132;
    pub const CONFIGURE_ARP: Type = 133;
    pub const GRE_GET: Type = 134;
    pub const GRE_UPDATE: Type = 135;
    pub const GRE_SOURCE_SET: Type = 136;
}

pub mod zebra_message_flags_t {
    pub type Type = u32;
    pub const NEXTHOP: Type = 0x01;
    pub const DISTANCE: Type = 0x02;
    pub const METRIC: Type = 0x04;
    pub const TAG: Type = 0x08;
    pub const MTU: Type = 0x10;
    pub const SRCPFX: Type = 0x20;
    pub const BACKUP_NEXTHOPS: Type = 0x40;
}

pub mod zebra_nexthop_flags_t {
    pub type Type = u8;
    pub const ONLINK: Type = 0x01;
    pub const LABEL: Type = 0x02;
    pub const WEIGHT: Type = 0x04;
    pub const HAS_BACKUP: Type = 0x08;
}

// ===== impl RouteType =====

impl From<Protocol> for RouteType {
    fn from(protocol: Protocol) -> RouteType {
        match protocol {
            Protocol::BFD => RouteType::Bfd,
            Protocol::LDP => RouteType::Ldp,
            Protocol::OSPFV2 => RouteType::Ospf,
            Protocol::OSPFV3 => RouteType::Ospf6,
            Protocol::RIPV2 => RouteType::Rip,
            Protocol::RIPNG => RouteType::Ripng,
        }
    }
}

// ===== impl NexthopType =====

impl From<(AddressFamily, bool)> for NexthopType {
    fn from(nexthop: (AddressFamily, bool)) -> NexthopType {
        match nexthop {
            (AddressFamily::Ipv4, false) => NexthopType::Ipv4,
            (AddressFamily::Ipv4, true) => NexthopType::Ipv4Ifindex,
            (AddressFamily::Ipv6, false) => NexthopType::Ipv6,
            (AddressFamily::Ipv6, true) => NexthopType::Ipv6Ifindex,
        }
    }
}
