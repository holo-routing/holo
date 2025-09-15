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
use holo_utils::mac_addr::MacAddr;
use holo_utils::socket::TTL_MAX;
use internet_checksum::Checksum;
use rand::prelude::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::instance::Version;
use crate::network::{
    ICMP_PROTO_NUMBER, VRRP_MULTICAST_ADDR_IPV4, VRRP_PROTO_NUMBER,
};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

//
// VRRP v2 Packet Format.
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
// VRRP v3 Packet Format
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
//
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct VrrpHdr {
    pub version: Version,
    pub hdr_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub adver_int: u16,
    pub checksum: u16,
    pub ip_addresses: Vec<IpAddr>,
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
    pub total_length: u16,
    pub src_address: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct EthernetHdr {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ethertype: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ArpHdr {
    pub sender_hw_address: MacAddr,
    pub sender_proto_address: Ipv4Addr,
    pub target_proto_address: Ipv4Addr,
}

// Headers for VRRP packets with IPv4 headers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Vrrp4Packet {
    pub ip: Ipv4Hdr,
    pub vrrp: VrrpHdr,
}

// Neighbor Advertisement Packet (ICMPV6 + NA fields).
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
    pub target_address: Ipv6Addr,
}

#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ChecksumError,
    IncompletePacket,
    PacketLengthError { vrid: u8, version: Version },
    IpTtlError { ttl: u8 },
    VersionError { vrid: u8 },
}

// ===== impl Packet =====

impl VrrpHdr {
    // Minimum number of bytes in a VRRP header (either v2 or v3).
    const MIN_LEN: usize = 8;
    // Byte offset where the checksum field is located within the VRRP header.
    pub const CHECKSUM_OFFSET: i32 = 6;
    // Maximum number of virtual IP addresses allowed in a VRRP advertisement.
    const MAX_VIRTUAL_IP_COUNT: u8 = 20;

    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);
        let ver_type = (self.version.version() << 4) | self.hdr_type;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(self.count_ip);

        match self.version {
            Version::V2 => {
                buf.put_u8(0);
                buf.put_u8(self.adver_int as u8);
                buf.put_u16(self.checksum);
                for addr in &self.ip_addresses {
                    if let IpAddr::V4(ipv4_addr) = addr {
                        buf.put_ipv4(ipv4_addr);
                    }
                }
                buf.put_u32(0);
                buf.put_u32(0);
            }
            Version::V3(_) => {
                buf.put_u16(self.adver_int & 0x0FFF);
                buf.put_u16(self.checksum);
                for addr in &self.ip_addresses {
                    buf.put_ip(addr);
                }
            }
        }

        // Generate checksum.
        if let AddressFamily::Ipv4 = self.version.address_family() {
            let mut check = Checksum::new();
            check.add_bytes(&buf);
            buf[6..8].copy_from_slice(&check.checksum());
        }

        buf
    }

    // Decodes VRRP packet from a bytes buffer.
    pub fn decode(data: &[u8], af: AddressFamily) -> DecodeResult<Self> {
        let pkt_size = data.len();
        if pkt_size < Self::MIN_LEN {
            return Err(DecodeError::IncompletePacket);
        }

        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.try_get_u8()?;
        let ver = ver_type >> 4;
        let hdr_type = ver_type & 0x0F;
        let vrid = buf.try_get_u8()?;

        let version = match (ver, af) {
            (2, AddressFamily::Ipv4) => Version::V2,
            (3, AddressFamily::Ipv4) => Version::V3(AddressFamily::Ipv4),
            (3, AddressFamily::Ipv6) => Version::V3(AddressFamily::Ipv6),
            _ => return Err(DecodeError::VersionError { vrid }),
        };

        let priority = buf.try_get_u8()?;
        let count_ip = buf.try_get_u8()?;

        // Check for required Virtual IP count.
        // Size Checks:
        //  1. Count of IP Addresses.
        //  2. Check of the expected packet size.
        if count_ip > Self::MAX_VIRTUAL_IP_COUNT
            || Self::expected_length(version, count_ip) != pkt_size
        {
            return Err(DecodeError::PacketLengthError { vrid, version });
        }

        let adver_int;
        let checksum;
        let mut ip_addresses = vec![];

        match version {
            Version::V2 => {
                let _auth_type = buf.try_get_u8()?;
                adver_int = buf.try_get_u8()? as u16;
                checksum = buf.try_get_u16()?;
                for _ in 0..count_ip {
                    ip_addresses.push(IpAddr::V4(buf.try_get_ipv4()?));
                }
                let _auth_data = buf.try_get_u32()?;
                let _auth_data2 = buf.try_get_u32()?;
            }
            Version::V3(af) => {
                adver_int = buf.try_get_u16()? & 0x0FFF;
                checksum = buf.try_get_u16()?;
                for _ in 0..count_ip {
                    match af {
                        AddressFamily::Ipv4 => {
                            ip_addresses.push(IpAddr::V4(buf.try_get_ipv4()?));
                        }
                        AddressFamily::Ipv6 => {
                            ip_addresses.push(IpAddr::V6(buf.try_get_ipv6()?));
                        }
                    }
                }
            }
        }

        // Checksum validation. IPv6's validation is offloaded to the kernel.
        if let AddressFamily::Ipv4 = af {
            let mut check = Checksum::new();
            check.add_bytes(data);
            if check.checksum() != [0, 0] {
                return Err(DecodeError::ChecksumError);
            }
        }

        Ok(Self {
            version,
            hdr_type,
            vrid,
            priority,
            count_ip,
            adver_int,
            checksum,
            ip_addresses,
        })
    }

    // Once we have the number of IPs expected, we can calculate the expected
    // length of the packet.
    pub fn expected_length(version: Version, count_ip: u8) -> usize {
        // Get number of bytes the authentication header sections will occupy.
        let auth_len = match version {
            Version::V2 => 8,
            Version::V3(_) => 0,
        };

        // [Minimum Length] + [virtual ip size] + size of pkt's auth section.
        Self::MIN_LEN
            + (version.address_family().addr_len() * usize::from(count_ip))
            + auth_len
    }
}

impl Ipv4Hdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        let version: u8 = 4;
        let ihl: u8 = 5;
        buf.put_u8((version << 4) | ihl);

        // Tos.
        buf.put_u8(0xc0);

        // Total Length ip header + payload.
        buf.put_u16(self.total_length);

        // Identification.
        if cfg!(test) {
            // Generate random ID.
            let mut rng = rand::rng();
            let mut ids: Vec<u16> = (u16::MIN..u16::MAX).collect();
            ids.shuffle(&mut rng);
            buf.put_u16(*(ids.first().unwrap()));
        } else {
            // When testing, have the ID as 0.
            buf.put_u16(0x00);
        }

        // Flags & offset -> flags[4 bits] + offset[12 bits].
        buf.put_u16(0x00);

        // Ttl.
        buf.put_u8(TTL_MAX);

        // Protocol.
        buf.put_u8(VRRP_PROTO_NUMBER as u8);

        // Checksum.
        buf.put_u16(0x00);
        buf.put_ipv4(&self.src_address);

        // Destination Address.
        buf.put_ipv4(&VRRP_MULTICAST_ADDR_IPV4);

        let mut check = Checksum::new();
        check.add_bytes(&buf);
        buf[10..12].copy_from_slice(&check.checksum());
        buf
    }
}

// ===== impl EthernetHdr =====

impl EthernetHdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        self.dst_mac.as_bytes().iter().for_each(|i| buf.put_u8(*i));
        self.src_mac.as_bytes().iter().for_each(|i| buf.put_u8(*i));
        buf.put_u16(self.ethertype);
        buf
    }
}

// ===== impl Vrrp4Packet =====

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

// ===== impl NeighborAdvertisement =====

impl NeighborAdvertisement {
    const PKT_LEN: usize = 192;
    // Number of bytes in the ipv6 pseudo header
    const PSEUDO_LENGTH: usize = 40;
    const PAYLOAD_LENGTH: u32 = 24;
    const ICMP_TYPE: u8 = 136;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::PKT_LEN);
        buf.put_u8(Self::ICMP_TYPE);
        buf.put_u8(0_u8); // Code.
        buf.put_u16(0_u16); // Checksum.

        let rso_reserved: u32 = 5_u32 << 29; // rso values. r[1], s[0], r[1].
        // reserved = 0.

        buf.put_u32(rso_reserved);
        buf.put_ipv6(&self.target_address);
        buf
    }

    pub fn pseudo_header(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::PSEUDO_LENGTH);
        buf.put_ipv6(&self.target_address);
        buf.put_ipv6(&self.target_address);
        buf.put_u32(Self::PAYLOAD_LENGTH);
        buf.put_i32(ICMP_PROTO_NUMBER);
        buf
    }
}

// ===== impl ArpHdr ====

impl ArpHdr {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(28);
        buf.put_u16(1_u16); // Hardware type = 1.
        buf.put_u16(libc::ETH_P_IP as _); // Proto Type.
        buf.put_u8(6_u8); // Harware(Mac Addr) Length = 6.
        buf.put_u8(4_u8); // Proto(Ip) length = 4.
        buf.put_u16(1_u16); // Operation = 1.
        buf.put_mac(&self.sender_hw_address);
        buf.put_ipv4(&self.sender_proto_address);
        buf.put_slice(&[0xff; 6]); // Target hw address (Broadcast address).
        buf.put_ipv4(&self.target_proto_address);
        buf
    }
}
