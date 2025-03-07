//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::ip::AddressFamily;
use internet_checksum::Checksum;
use serde::{Deserialize, Serialize};

use crate::version::VrrpVersion;

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

//
// VRRP V2 Packet Format.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Auth Type   |   Adver Int   |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         IP Address (1)                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            .                                  |
// |                            .                                  |
// |                            .                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         IP Address (n)                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Authentication Data (1)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Authentication Data (2)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// VRRP v3 Packet Format
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    IPv4 Fields or IPv6 Fields                 |
// ...                                                             ...
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  | Virtual Rtr ID|   Priority    |IPvX Addr Count|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Reserve| Max Advertise Interval|          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                       IPvX Address(es)                        |
// +                                                               +
// +                                                               +
// +                                                               +
// +                                                               +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct VrrpHdr {
    pub version: VrrpVersion,
    pub hdr_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    //
    pub auth_type: u8, // for vrrp v3 this will represent the reserve field
    pub adver_int: u16,
    pub checksum: u16,
    pub ip_addresses: Vec<IpAddr>,
    // The following two are only used for backward compatibility.
    pub auth_data: Option<u32>,
    pub auth_data2: Option<u32>,
}

//
// IP packet header
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv4Hdr {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_address: Ipv4Addr,
    pub dst_address: Ipv4Addr,
    pub options: Option<u32>,
    pub padding: Option<u8>,
}

// IPv6 packet header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Ipv6Hdr {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct EthernetHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ArpHdr {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_length: u8,
    pub proto_length: u8,
    pub operation: u16,
    pub sender_hw_address: [u8; 6],
    pub sender_proto_address: Ipv4Addr,
    pub target_hw_address: [u8; 6],
    pub target_proto_address: Ipv4Addr,
}

/// Headers for VRRP packets with ipv6 headers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Vrrp4Packet {
    pub ip: Ipv4Hdr,
    pub vrrp: VrrpHdr,
}

/// Headers for VRRP packets with ipv6 headers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Vrrp6Packet {
    pub ip: Ipv6Hdr,
    pub vrrp: VrrpHdr,
}

// Neighbor Advertisement Packet (basically ICMPV6 + NA fields)
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |R|S|O|                     Reserved                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                       Target Address                          +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Options ...
//  +-+-+-+-+-+-+-+-+-+-+-+-
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct NeighborAdvertisement {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub r: u8,
    pub s: u8,
    pub o: u8,
    pub reserved: u32,
    pub target_address: Ipv6Addr,
}

#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ChecksumError,
    PacketLengthError { vrid: u8 },
    IpTtlError { ttl: u8 },
}

// ===== impl Packet =====

impl VrrpHdr {
    const V2_MAX_LEN: usize = 96;
    const V2_MIN_LEN: usize = 16;
    const V2_MAX_IP_COUNT: usize = 20;

    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);
        let ver_type = (self.version.version() << 4) | self.hdr_type;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(self.count_ip);

        match self.version {
            VrrpVersion::V2 => {
                buf.put_u8(self.auth_type);
                let adv = self.adver_int as u8;

                buf.put_u8(adv);
                buf.put_u16(self.checksum);
                for addr in &self.ip_addresses {
                    if let IpAddr::V4(ipv4_addr) = addr {
                        buf.put_ipv4(ipv4_addr);
                    }
                }

                if let Some(auth_data) = self.auth_data {
                    buf.put_u32(auth_data);
                }
                if let Some(auth_data2) = self.auth_data2 {
                    buf.put_u32(auth_data2);
                }

                // generate checksum
                let mut check = Checksum::new();
                check.add_bytes(&buf);
                buf[6..8].copy_from_slice(&check.checksum());
            }
            VrrpVersion::V3(address_family) => {
                let res_adv_int =
                    ((self.auth_type as u16) << 12) | self.adver_int;
                buf.put_u16(res_adv_int);

                buf.put_u16(self.checksum);
                match address_family {
                    AddressFamily::Ipv4 => {
                        for addr in &self.ip_addresses {
                            if let IpAddr::V4(ipv4_addr) = addr {
                                buf.put_ipv4(ipv4_addr);
                            }
                        }
                    }
                    AddressFamily::Ipv6 => {
                        for addr in &self.ip_addresses {
                            if let IpAddr::V6(ipv6_addr) = addr {
                                buf.put_ipv6(ipv6_addr);
                            }
                        }
                    }
                }
            }
        }
        buf
    }

    // Decodes VRRP packet from a bytes buffer.
    pub fn decode(
        data: &[u8],
        addr_family: AddressFamily,
    ) -> DecodeResult<Self> {
        let pkt_size = data.len();
        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let ver = ver_type >> 4;

        let hdr_type = ver_type & 0x0F;
        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();

        // auth data
        let mut auth_data: Option<u32> = None;
        let mut auth_data2: Option<u32> = None;
        let mut auth_type: u8 = 0;
        let mut adver_int: u16 = 0;
        let mut checksum: u16 = 0;
        let mut ip_addresses: Vec<IpAddr> = vec![];
        let mut version = VrrpVersion::V2;

        if ver == 2 {
            auth_type = buf.get_u8();
            adver_int = buf.get_u8() as u16;
            if !(Self::V2_MIN_LEN..=Self::V2_MAX_LEN).contains(&pkt_size)
                || count_ip as usize > Self::V2_MAX_IP_COUNT
                || (count_ip * 4) + 16 != pkt_size as u8
            {
                return Err(DecodeError::PacketLengthError { vrid });
            }
            checksum = buf.get_u16();

            for _ in 0..count_ip {
                ip_addresses.push(IpAddr::V4(buf.get_ipv4()));
            }

            auth_data = Some(buf.get_u32());
            auth_data2 = Some(buf.get_u32());
        } else if ver == 3 {
            let res_adv_int = buf.get_u16();
            auth_type = (res_adv_int >> 12) as u8;
            let advert: u16 = res_adv_int & 0x0FFF;
            adver_int = advert;

            // TODO: add checksum confirmation when receiving the packet
            checksum = buf.get_u16();
            match addr_family {
                AddressFamily::Ipv4 => {
                    version = VrrpVersion::V3(AddressFamily::Ipv4);
                    for _ in 0..count_ip {
                        ip_addresses.push(IpAddr::V4(buf.get_ipv4()));
                    }
                }
                AddressFamily::Ipv6 => {
                    version = VrrpVersion::V3(AddressFamily::Ipv6);
                    for _ in 0..count_ip {
                        ip_addresses.push(IpAddr::V6(buf.get_ipv6()));
                    }
                }
            }
        }

        // Checksum Calculation
        let mut check = Checksum::new();
        check.add_bytes(data);
        if check.checksum() != [0, 0] {
            return Err(DecodeError::ChecksumError);
        }

        Ok(Self {
            version,
            hdr_type,
            vrid,
            priority,
            count_ip,
            auth_type,
            adver_int,
            checksum,
            ip_addresses,
            auth_data,
            auth_data2,
        })
    }
}

impl Ipv4Hdr {
    const MIN_LEN: usize = 20;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        buf.put_u8((self.version << 4) | self.ihl);
        buf.put_u8(self.tos);
        buf.put_u16(self.total_length);
        buf.put_u16(self.identification);

        // flag_off -> flags[4 bits] + offset[12 bits]
        let flag_off: u16 = ((self.flags as u16) << 12) | self.offset;
        buf.put_u16(flag_off);
        buf.put_u8(self.ttl);
        buf.put_u8(self.protocol);
        buf.put_u16(self.checksum);
        buf.put_ipv4(&self.src_address);
        buf.put_ipv4(&self.dst_address);

        // the header length for IP is between 20 and 24
        // when 24, the options and padding fields are present.
        if let (Some(options), Some(padding)) = (self.options, self.padding) {
            let opt_pad: u32 = (options << 8) | (padding as u32);
            buf.put_u32(opt_pad);
        }

        let mut check = Checksum::new();
        check.add_bytes(&buf);
        buf[10..12].copy_from_slice(&check.checksum());
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        let ver_ihl = buf.get_u8();
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;

        let tos = buf.get_u8();
        let total_length = buf.get_u16();
        let identification = buf.get_u16();

        // flag_off -> flags[4 bits] + offset[12 bits]
        let flag_off = buf.get_u16();
        let flags: u8 = (flag_off >> 12) as u8;
        let offset: u16 = flag_off & 0xFFF;

        let ttl = buf.get_u8();

        if ttl != 255 {
            return Err(DecodeError::IpTtlError { ttl });
        }
        let protocol = buf.get_u8();
        let checksum = buf.get_u16();

        let src_address = buf.get_ipv4();
        let dst_address = buf.get_ipv4();

        let mut options: Option<u32> = None;
        let mut padding: Option<u8> = None;

        if ihl > Self::MIN_LEN as u8 {
            let opt_pad = buf.get_u32();
            options = Some(opt_pad >> 8);
            padding = Some((opt_pad & 0xFF) as u8);
        }

        let mut check = Checksum::new();
        check.add_bytes(data);
        if check.checksum() != [0, 0] {
            return Err(DecodeError::ChecksumError);
        }

        Ok(Self {
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            src_address,
            dst_address,
            options,
            padding,
        })
    }
}

impl Ipv6Hdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let v: u32 = ((self.version as u32) << 28)
            | ((self.traffic_class as u32) << 20)
            | self.flow_label;

        buf.put_u32(v);
        buf.put_u16(self.payload_length);
        buf.put_u8(self.next_header);
        buf.put_u8(self.hop_limit);
        buf.put_ipv6(&self.source_address);
        buf.put_ipv6(&self.destination_address);
        buf
    }

    pub fn pseudo_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_ipv6(&self.source_address);
        buf.put_ipv6(&self.destination_address);
        buf.put_u32(self.payload_length as u32);
        buf.put_u32(self.next_header as u32);
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        // version, traffic, flow_label -> version[4b], traffic[8b], flow_label[20b]
        let ver_traff_flow = buf.get_u32();
        let version: u8 = (ver_traff_flow >> 28) as u8;
        let traffic_class: u8 = ((ver_traff_flow >> 20) & 0x000000FF) as u8;
        let flow_label: u32 = ver_traff_flow & 0x000FFFFF;

        let payload_length = buf.get_u16();
        let next_header = buf.get_u8();
        let hop_limit = buf.get_u8();

        if hop_limit != 255 {
            return Err(DecodeError::IpTtlError { ttl: hop_limit });
        }
        let source_address = buf.get_ipv6();
        let destination_address = buf.get_ipv6();

        Ok(Self {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address,
            destination_address,
        })
    }
}

impl EthernetHdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        self.dst_mac.iter().for_each(|i| buf.put_u8(*i));
        self.src_mac.iter().for_each(|i| buf.put_u8(*i));
        buf.put_u16(self.ethertype);
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let dst_mac = &data[0..6].try_into();
        let dst_mac: [u8; 6] = dst_mac.unwrap();

        let src_mac = &data[6..12].try_into();
        let src_mac: [u8; 6] = src_mac.unwrap();

        Ok(Self {
            dst_mac,
            src_mac,
            ethertype: libc::ETH_P_IP as _,
        })
    }
}

impl Vrrp4Packet {
    // maximum size of IP + vrrp header.
    const MAX_LEN: usize = 130;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::MAX_LEN);
        buf.put(self.ip.encode());
        buf.put(self.vrrp.encode());
        buf
    }
}

impl Vrrp6Packet {
    const MAX_LEN: usize = 2944;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::MAX_LEN);
        buf.put(self.ip.encode());
        buf.put(self.vrrp.encode());
        buf
    }
}

impl NeighborAdvertisement {
    const PKT_LEN: usize = 192;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::PKT_LEN);
        buf.put_u8(self.icmp_type);
        buf.put_u8(self.code);
        buf.put_u16(self.checksum);

        let rso_reserved = ((self.r as u32) << 31)
            | ((self.s as u32) << 30)
            | ((self.o as u32) << 29)
            | ((self.reserved) >> 3);

        buf.put_u32(rso_reserved);
        buf.put_ipv6(&self.target_address);
        buf
    }
}

impl ArpHdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(28);
        buf.put_u16(self.hw_type);
        buf.put_u16(self.proto_type);
        buf.put_u8(self.hw_length);
        buf.put_u8(self.proto_length);
        buf.put_u16(self.operation);
        buf.put_slice(&self.sender_hw_address);
        buf.put_ipv4(&self.sender_proto_address);
        buf.put_slice(&self.target_hw_address);
        buf.put_ipv4(&self.target_proto_address);
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        let mut sender_hw_address: [u8; 6] = [0; 6];
        let mut target_hw_address: [u8; 6] = [0; 6];

        let hw_type = buf.get_u16();
        let proto_type = buf.get_u16();
        let hw_length = buf.get_u8();
        let proto_length = buf.get_u8();
        let operation = buf.get_u16();
        buf.copy_to_slice(&mut sender_hw_address);
        let sender_proto_address = buf.get_ipv4();
        buf.copy_to_slice(&mut target_hw_address);
        let target_proto_address = buf.get_ipv4();

        Ok(Self {
            hw_type,
            proto_type,
            hw_length,
            proto_length,
            operation,
            sender_hw_address,
            sender_proto_address,
            target_hw_address,
            target_proto_address,
        })
    }
}
