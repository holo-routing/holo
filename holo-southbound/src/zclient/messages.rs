//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::BytesExt;
use holo_utils::ip::IpAddrExt;
use holo_utils::mpls::Label;
use ipnetwork::IpNetwork;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::zclient::error::{DecodeError, DecodeResult};
use crate::zclient::{ffi, Zclient};

// ZAPI Rx messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ZapiRxMsg {
    RouterIdUpd(ZapiRtrIdInfo),
    InterfaceUpd(ZapiRxIfaceInfo),
    AddressAdd(ZapiRxAddressInfo),
    AddressDel(ZapiRxAddressInfo),
    RouteAdd(ZapiRxRouteInfo),
    RouteDel(ZapiRxRouteInfo),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiRtrIdInfo {
    pub router_id: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiRxIfaceInfo {
    pub ifname: String,
    pub ifindex: Option<u32>,
    pub mtu: u32,
    pub operative: bool,
    pub loopback: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiRxAddressInfo {
    pub ifindex: u32,
    pub addr: IpNetwork,
    #[serde(default)]
    pub unnumbered: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiRxRouteInfo {
    pub proto: ffi::RouteType,
    pub instance: u16,
    pub prefix: IpNetwork,
    pub nexthops: Vec<ZapiRxNexthopInfo>,
    pub distance: u8,
    pub metric: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiRxNexthopInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifindex: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackhole: Option<u8>,
}

// ZAPI Tx messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ZapiTxMsg {
    Hello(ZapiTxHelloInfo),
    InterfaceAdd,
    RouterIdAdd(ZapiTxRtrIdInfo),
    RouterIdDel(ZapiTxRtrIdInfo),
    RedistributeDfltAdd(ZapiTxRedistDfltInfo),
    RedistributeDfltDel(ZapiTxRedistDfltInfo),
    RedistributeAdd(ZapiTxRedistInfo),
    RedistributeDel(ZapiTxRedistInfo),
    RouteReplace(ZapiTxRouteInfo),
    RouteDel(ZapiTxRouteInfo),
    LabelsAdd(ZapiTxLabelsInfo),
    LabelsReplace(ZapiTxLabelsInfo),
    LabelsDel(ZapiTxLabelsInfo),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxHelloInfo {
    pub redist_default: ffi::RouteType,
    pub instance: u16,
    pub session_id: u32,
    pub receive_notify: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxRtrIdInfo {
    pub afi: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxRedistDfltInfo {
    pub afi: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxRedistInfo {
    pub afi: u16,
    pub proto: ffi::RouteType,
    pub instance: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxRouteInfo {
    pub proto: ffi::RouteType,
    pub instance: u16,
    pub prefix: IpNetwork,
    pub nexthops: Vec<ZapiTxNexthopInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxLabelsInfo {
    pub lsp_type: ffi::LspType,
    pub local_label: Label,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<ZapiTxLabelsRouteInfo>,
    pub nexthops: Vec<ZapiTxNexthopInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxLabelsRouteInfo {
    pub prefix: IpNetwork,
    pub proto: ffi::RouteType,
    pub instance: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZapiTxNexthopInfo {
    pub nhtype: ffi::NexthopType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<IpAddr>,
    pub ifindex: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<(ffi::LspType, Label)>,
}

// ===== ZAPI Rx decode methods =====

impl ZapiRxMsg {
    pub(crate) fn decode(
        buf: Bytes,
        cmd: u16,
        vrf_id: u32,
    ) -> DecodeResult<Self> {
        let msg = match cmd {
            ffi::zebra_message_types_t::ROUTER_ID_UPDATE => {
                let info = ZapiRtrIdInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::RouterIdUpd(info)
            }
            ffi::zebra_message_types_t::INTERFACE_ADD
            | ffi::zebra_message_types_t::INTERFACE_UP
            | ffi::zebra_message_types_t::INTERFACE_DOWN
            | ffi::zebra_message_types_t::INTERFACE_DELETE => {
                let info = ZapiRxIfaceInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::InterfaceUpd(info)
            }
            ffi::zebra_message_types_t::INTERFACE_ADDRESS_ADD => {
                let info = ZapiRxAddressInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::AddressAdd(info)
            }
            ffi::zebra_message_types_t::INTERFACE_ADDRESS_DELETE => {
                let info = ZapiRxAddressInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::AddressDel(info)
            }
            ffi::zebra_message_types_t::REDISTRIBUTE_ROUTE_ADD => {
                let info = ZapiRxRouteInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::RouteAdd(info)
            }
            ffi::zebra_message_types_t::REDISTRIBUTE_ROUTE_DEL => {
                let info = ZapiRxRouteInfo::decode(buf, cmd, vrf_id)?;
                ZapiRxMsg::RouteDel(info)
            }
            _ => {
                return Err(DecodeError::MalformedMessage(format!(
                    "unknown message type: {}",
                    cmd
                )))
            }
        };

        Ok(msg)
    }
}

impl std::fmt::Display for ZapiRxMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZapiRxMsg::RouterIdUpd(_) => write!(f, "router-id-update"),
            ZapiRxMsg::InterfaceUpd(_) => write!(f, "interface-update"),
            ZapiRxMsg::AddressAdd(_) => write!(f, "address-add"),
            ZapiRxMsg::AddressDel(_) => write!(f, "address-delete"),
            ZapiRxMsg::RouteAdd(_) => write!(f, "route-add"),
            ZapiRxMsg::RouteDel(_) => write!(f, "route-delete"),
        }
    }
}

impl ZapiRtrIdInfo {
    fn decode(mut buf: Bytes, _cmd: u16, _vrf_id: u32) -> DecodeResult<Self> {
        let family = buf.get_u8();
        if family as i32 != libc::AF_INET {
            return Err(DecodeError::MalformedMessage(format!(
                "invalid router-id address-family: {}",
                family
            )));
        }
        let router_id = Ipv4Addr::from(buf.get_u32());
        let _plen = buf.get_u8();
        let router_id = if router_id.is_unspecified() {
            None
        } else {
            Some(router_id)
        };

        Ok(ZapiRtrIdInfo { router_id })
    }
}

impl ZapiRxIfaceInfo {
    fn decode(mut buf: Bytes, _cmd: u16, _vrf_id: u32) -> DecodeResult<Self> {
        let mut ifname = [0; 16];
        buf.copy_to_slice(&mut ifname);
        let ifname = String::from_utf8(ifname.to_vec()).unwrap();
        let ifname = ifname.trim_matches(char::from(0)).to_string();
        let ifindex = buf.get_u32();
        let ifindex = if ifindex != 0 { Some(ifindex) } else { None };
        let _status = buf.get_u8();
        let flags = buf.get_u64();
        let _ptm_enable = buf.get_u8();
        let _ptm_status = buf.get_u8();
        let _metric = buf.get_u32();
        let _speed = buf.get_u32();
        #[cfg(not(feature = "zebra-8-4-compat"))]
        let _txqlen = buf.get_u32();
        let mtu = buf.get_u32();

        let operative = flags & (libc::IFF_RUNNING as u64) != 0;
        let loopback = flags & (libc::IFF_LOOPBACK as u64) != 0;

        Ok(ZapiRxIfaceInfo {
            ifname,
            ifindex,
            mtu,
            operative,
            loopback,
        })
    }
}

impl ZapiRxAddressInfo {
    fn decode(mut buf: Bytes, _cmd: u16, _vrf_id: u32) -> DecodeResult<Self> {
        let ifindex = buf.get_u32();
        let flags = buf.get_u8();
        let family = buf.get_u8();
        let (addr, max_plen) = match family as i32 {
            libc::AF_INET => (IpAddr::from(buf.get_ipv4()), 32),
            libc::AF_INET6 => (IpAddr::from(buf.get_ipv6()), 128),
            _ => {
                return Err(DecodeError::MalformedMessage(format!(
                    "invalid address-family: {}",
                    family
                )))
            }
        };
        let plen = std::cmp::min(buf.get_u8(), max_plen);
        let addr = IpNetwork::new(addr, plen)?;
        let unnumbered = flags & (ffi::AddressFlags::UNNUMBERED.bits()) != 0;

        Ok(ZapiRxAddressInfo {
            ifindex,
            addr,
            unnumbered,
        })
    }
}

impl ZapiRxRouteInfo {
    fn decode(mut buf: Bytes, _cmd: u16, _vrf_id: u32) -> DecodeResult<Self> {
        let proto = buf.get_u8();
        let proto = match ffi::RouteType::from_u8(proto) {
            Some(proto) => proto,
            None => return Err(DecodeError::UnknownProtocol(proto)),
        };

        let instance = buf.get_u16();
        let _flags = buf.get_u32();
        let message = buf.get_u32();
        let _safi = buf.get_u8();

        // Parse prefix.
        let family = buf.get_u8();
        let plen = buf.get_u8();
        let pwire_len = prefix_wire_len(plen);
        let mut prefix_bytes = vec![0; pwire_len as usize];
        buf.copy_to_slice(&mut prefix_bytes);

        let addr = match family as i32 {
            libc::AF_INET => {
                let mut prefix_array = [0u8; 4];
                prefix_bytes.resize(4, 0);
                prefix_array.copy_from_slice(&prefix_bytes);
                IpAddr::from(prefix_array)
            }
            libc::AF_INET6 => {
                let mut prefix_array = [0u8; 16];
                prefix_bytes.resize(16, 0);
                prefix_array.copy_from_slice(&prefix_bytes);
                IpAddr::from(prefix_array)
            }
            _ => {
                return Err(DecodeError::MalformedMessage(format!(
                    "invalid route address-family: {}",
                    family
                )))
            }
        };
        let prefix = IpNetwork::new(addr, plen)?;

        // Parse nexthop.
        let mut nexthops = vec![];
        if message & ffi::zebra_message_flags_t::NEXTHOP != 0 {
            let nexthop_num = buf.get_u16();

            for _i in 0..nexthop_num {
                let _vrf_id = buf.get_u32();
                let nh_type = buf.get_u8();
                let flags = buf.get_u8();

                let nh_type = match ffi::NexthopType::from_u8(nh_type) {
                    Some(nh_type) => nh_type,
                    None => {
                        return Err(DecodeError::UnknownNexthopType(nh_type))
                    }
                };

                let addr = match nh_type {
                    ffi::NexthopType::Ipv4 | ffi::NexthopType::Ipv4Ifindex => {
                        Some(IpAddr::from(buf.get_ipv4()))
                    }
                    ffi::NexthopType::Ipv6 | ffi::NexthopType::Ipv6Ifindex => {
                        Some(IpAddr::from(buf.get_ipv6()))
                    }
                    _ => None,
                };

                let ifindex = match nh_type {
                    ffi::NexthopType::Ifindex
                    | ffi::NexthopType::Ipv4Ifindex
                    | ffi::NexthopType::Ipv6Ifindex => Some(buf.get_u32()),
                    _ => None,
                };

                let blackhole = match nh_type {
                    ffi::NexthopType::Blackhole => Some(buf.get_u8()),
                    _ => None,
                };

                // Parse additional attributes.
                let _weight = if flags & ffi::zebra_nexthop_flags_t::WEIGHT != 0
                {
                    buf.get_u32()
                } else {
                    0
                };

                // Add nexthop.
                nexthops.push(ZapiRxNexthopInfo {
                    ifindex,
                    addr,
                    blackhole,
                });
            }
        }

        // Parse additional attributes.
        let distance = if message & ffi::zebra_message_flags_t::DISTANCE != 0 {
            buf.get_u8()
        } else {
            0
        };
        let metric = if message & ffi::zebra_message_flags_t::METRIC != 0 {
            buf.get_u32()
        } else {
            0
        };
        // TODO: parse tag, mtu and tableid.

        Ok(ZapiRxRouteInfo {
            proto,
            instance,
            prefix,
            nexthops,
            distance,
            metric,
        })
    }
}

// ===== ZAPI Tx encode methods =====

impl ZapiTxMsg {
    pub(crate) fn encode(&self, zclient: &Zclient) -> BytesMut {
        let mut buf = BytesMut::with_capacity(2048);

        // Get ZAPI command type.
        let cmd = match self {
            ZapiTxMsg::Hello(_) => ffi::zebra_message_types_t::HELLO,
            ZapiTxMsg::InterfaceAdd => {
                ffi::zebra_message_types_t::INTERFACE_ADD
            }
            ZapiTxMsg::RouterIdAdd(_) => {
                ffi::zebra_message_types_t::ROUTER_ID_ADD
            }
            ZapiTxMsg::RouterIdDel(_) => {
                ffi::zebra_message_types_t::ROUTER_ID_DELETE
            }
            ZapiTxMsg::RedistributeDfltAdd(_) => {
                ffi::zebra_message_types_t::REDISTRIBUTE_DEFAULT_ADD
            }
            ZapiTxMsg::RedistributeDfltDel(_) => {
                ffi::zebra_message_types_t::REDISTRIBUTE_DEFAULT_DELETE
            }
            ZapiTxMsg::RedistributeAdd(_) => {
                ffi::zebra_message_types_t::REDISTRIBUTE_ADD
            }
            ZapiTxMsg::RedistributeDel(_) => {
                ffi::zebra_message_types_t::REDISTRIBUTE_DELETE
            }
            ZapiTxMsg::RouteReplace(_) => ffi::zebra_message_types_t::ROUTE_ADD,
            ZapiTxMsg::RouteDel(_) => ffi::zebra_message_types_t::ROUTE_DELETE,
            ZapiTxMsg::LabelsAdd(_) => {
                ffi::zebra_message_types_t::MPLS_LABELS_ADD
            }
            ZapiTxMsg::LabelsReplace(_) => {
                ffi::zebra_message_types_t::MPLS_LABELS_REPLACE
            }
            ZapiTxMsg::LabelsDel(_) => {
                ffi::zebra_message_types_t::MPLS_LABELS_DELETE
            }
        };

        // Encode ZAPI header.
        zclient.encode_zapi_header(&mut buf, cmd);

        // Encode message body.
        match self {
            ZapiTxMsg::Hello(info) => {
                info.encode(&mut buf);
            }
            ZapiTxMsg::RouterIdAdd(info) | ZapiTxMsg::RouterIdDel(info) => {
                info.encode(&mut buf);
            }
            ZapiTxMsg::RedistributeDfltAdd(info)
            | ZapiTxMsg::RedistributeDfltDel(info) => {
                info.encode(&mut buf);
            }
            ZapiTxMsg::RedistributeAdd(info)
            | ZapiTxMsg::RedistributeDel(info) => {
                info.encode(&mut buf);
            }
            ZapiTxMsg::RouteReplace(info) | ZapiTxMsg::RouteDel(info) => {
                info.encode(&mut buf);
            }
            ZapiTxMsg::LabelsAdd(info)
            | ZapiTxMsg::LabelsReplace(info)
            | ZapiTxMsg::LabelsDel(info) => {
                info.encode(&mut buf);
            }
            _ => (),
        };

        // Rewrite message length in the ZAPI header.
        let msg_len = buf.len() as u16;
        buf[0..2].copy_from_slice(&msg_len.to_be_bytes());

        // Return buffer
        buf
    }
}

impl std::fmt::Display for ZapiTxMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZapiTxMsg::Hello(_) => write!(f, "hello"),
            ZapiTxMsg::InterfaceAdd => write!(f, "interface-add"),
            ZapiTxMsg::RouterIdAdd(_) => write!(f, "router-id-add"),
            ZapiTxMsg::RouterIdDel(_) => write!(f, "router-id-delete"),
            ZapiTxMsg::RedistributeDfltAdd(_) => {
                write!(f, "redistribute-default-add")
            }
            ZapiTxMsg::RedistributeDfltDel(_) => {
                write!(f, "redistribute-default-delete")
            }
            ZapiTxMsg::RedistributeAdd(_) => write!(f, "redistribute-add"),
            ZapiTxMsg::RedistributeDel(_) => write!(f, "redistribute-delete"),
            ZapiTxMsg::RouteReplace(_) => write!(f, "route-replace"),
            ZapiTxMsg::RouteDel(_) => write!(f, "route-delete"),
            ZapiTxMsg::LabelsAdd(_) => write!(f, "labels-add"),
            ZapiTxMsg::LabelsReplace(_) => write!(f, "labels-replace"),
            ZapiTxMsg::LabelsDel(_) => write!(f, "labels-delete"),
        }
    }
}

impl ZapiTxHelloInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.redist_default as u8);
        buf.put_u16(self.instance);
        buf.put_u32(self.session_id);
        buf.put_u8(self.receive_notify);
        buf.put_u8(0); // synchronous
    }
}

impl ZapiTxRtrIdInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi);
    }
}

impl ZapiTxRedistDfltInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.afi as u8);
    }
}

impl ZapiTxRedistInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.afi as u8);
        buf.put_u8(self.proto as u8);
        buf.put_u16(self.instance);
    }
}

impl ZapiTxRouteInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        // Encode protocol and instance.
        buf.put_u8(self.proto as u8);
        buf.put_u16(self.instance);

        // Encode route flags.
        buf.put_u32(0);

        // Encode message flags.
        let mut flags = 0;
        if !self.nexthops.is_empty() {
            flags |= ffi::zebra_message_flags_t::NEXTHOP;
        }
        if self.distance.is_some() {
            flags |= ffi::zebra_message_flags_t::DISTANCE;
        }
        if self.metric.is_some() {
            flags |= ffi::zebra_message_flags_t::METRIC;
        }
        if self.tag.is_some() {
            flags |= ffi::zebra_message_flags_t::TAG;
        }
        buf.put_u32(flags);

        // Encode SAFI (always unicast).
        buf.put_u8(1);

        // Encode prefix.
        let family = match self.prefix {
            IpNetwork::V4(_) => libc::AF_INET,
            IpNetwork::V6(_) => libc::AF_INET6,
        };
        buf.put_u8(family.try_into().unwrap());
        let plen = self.prefix.prefix();
        let pwire_len = prefix_wire_len(plen) as usize;
        let prefix_bytes = self.prefix.ip().bytes();
        buf.put_u8(plen);
        buf.put_slice(&prefix_bytes[0..pwire_len]);

        // Encode nexthops.
        buf.put_u16(self.nexthops.len() as u16);
        for nexthop in &self.nexthops {
            nexthop.encode(buf);
        }

        // Encode distance.
        if let Some(distance) = self.distance {
            buf.put_u8(distance);
        }

        // Encode metric.
        if let Some(metric) = self.metric {
            buf.put_u32(metric);
        }

        // Encode distance.
        if let Some(tag) = self.tag {
            buf.put_u32(tag);
        }
    }
}

impl ZapiTxLabelsInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        if self.route.is_some() {
            buf.put_u8(1); // ZAPI_LABELS_FTN
        } else {
            buf.put_u8(0);
        }
        buf.put_u8(self.lsp_type as u8);
        buf.put_u32(self.local_label.get());

        // Encode route (if any).
        if let Some(route) = &self.route {
            let family = match route.prefix {
                IpNetwork::V4(_) => libc::AF_INET,
                IpNetwork::V6(_) => libc::AF_INET6,
            };
            buf.put_u16(family.try_into().unwrap());

            let plen = route.prefix.prefix();
            let pwire_len = prefix_wire_len(plen) as usize;
            let prefix_bytes = route.prefix.ip().bytes();

            buf.put_u8(plen);
            buf.put_slice(&prefix_bytes[0..pwire_len]);

            buf.put_u8(route.proto as u8);
            buf.put_u16(route.instance);
        }

        // Encode nexthops.
        buf.put_u16(self.nexthops.len() as u16);
        for nexthop in &self.nexthops {
            nexthop.encode(buf);
        }
    }
}

impl ZapiTxNexthopInfo {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        // Nexthop VRF ID.
        buf.put_u32(0);

        // Nexthop type.
        buf.put_u8(self.nhtype as u8);

        // Nexthop flags.
        let mut flags = 0;
        if self.label.is_some() {
            flags |= ffi::zebra_nexthop_flags_t::LABEL;
        }
        buf.put_u8(flags);

        // Nexthop address.
        if let Some(addr) = &self.addr {
            let len = addr.length();
            let bytes = addr.bytes();
            buf.put_slice(&bytes[0..len]);
        }

        // Nexthop ifindex.
        buf.put_u32(self.ifindex);

        // Nexthop label.
        if let Some((label_type, label)) = self.label {
            buf.put_u8(1);
            #[cfg(not(feature = "zebra-8-4-compat"))]
            buf.put_u8(label_type as u8);
            buf.put_u32_le(label.get());
        }
    }
}

// ===== helper functions =====

fn prefix_wire_len(plen: u8) -> u8 {
    (plen + 7) / 8
}
