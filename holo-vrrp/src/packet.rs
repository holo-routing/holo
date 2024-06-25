//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use serde::{Deserialize, Serialize};

use crate::error::{self, Error, GlobalError, VirtualRouterError};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

//
// VRRP Packet Format.
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct VrrpHdr {
    pub version: u8,
    pub hdr_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub auth_type: u8,
    pub adver_int: u8,
    pub checksum: u16,
    pub ip_addresses: Vec<Ipv4Addr>,

    // the following two are only used for backward compatibility.
    pub auth_data: u32,
    pub auth_data2: u32,
}

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

#[repr(C)]
pub struct ARPframe {
    // Ethernet Header
    pub dst_mac: [u8; 6], // destination MAC address
    pub src_mac: [u8; 6], // source MAC address
    pub ethertype: u16,   // ether type

    // ARP
    pub hardware_type: u16, // network link type (0x1=ethernet)
    pub protocol_type: u16, // upper-layer protocol for resolution
    pub hw_addr_len: u8,    // length of hardware address (bytes)
    pub proto_addr_len: u8, // upper-layer protocol address length
    pub opcode: u16,        // operation (0x1=request, 0x2=reply)
    pub sender_hw_addr: [u8; 6], // sender hardware address
    pub sender_proto_addr: [u8; 4], // internetwork address of sender
    pub target_hw_addr: [u8; 6], // hardware address of target
    pub target_proto_addr: [u8; 4], // internetwork address of target
}

impl ARPframe {
    pub fn new(eth_pkt: EthernetHdr, arp_pkt: ArpPacket) -> Self {
        Self {
            dst_mac: eth_pkt.dst_mac,
            src_mac: eth_pkt.src_mac,
            ethertype: eth_pkt.ethertype.to_be(),

            hardware_type: arp_pkt.hw_type.to_be(),
            protocol_type: arp_pkt.proto_type.to_be(),
            hw_addr_len: arp_pkt.hw_length,
            proto_addr_len: arp_pkt.proto_length,
            opcode: arp_pkt.operation.to_be(),

            sender_hw_addr: arp_pkt.sender_hw_address,
            sender_proto_addr: arp_pkt.sender_proto_address,
            target_hw_addr: arp_pkt.target_hw_address,
            target_proto_addr: arp_pkt.target_proto_address,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct EthernetHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_length: u8,
    pub proto_length: u8,
    pub operation: u16,
    pub sender_hw_address: [u8; 6],    // src mac
    pub sender_proto_address: [u8; 4], // src ip
    pub target_hw_address: [u8; 6],    // src mac
    pub target_proto_address: [u8; 4], // src ip
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct VrrpPacket {
    pub ip: Ipv4Hdr,
    pub vrrp: VrrpHdr,
}

#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ChecksumError,
    PacketLengthError,
    IpTtlError,
    VersionError,
}

impl DecodeError {
    pub fn err(&self) -> error::Error {
        match self {
            DecodeError::ChecksumError => {
                Error::GlobalError(GlobalError::ChecksumError)
            }
            DecodeError::PacketLengthError => {
                Error::VirtualRouterError(VirtualRouterError::PacketLengthError)
            }
            DecodeError::IpTtlError => {
                Error::GlobalError(GlobalError::IpTtlError)
            }
            DecodeError::VersionError => {
                Error::GlobalError(GlobalError::VersionError)
            }
        }
    }
}

// ===== impl Packet =====

impl VrrpHdr {
    const MIN_PKT_LENGTH: usize = 16;
    const MAX_PKT_LENGTH: usize = 80;
    const MAX_IP_COUNT: usize = 16;

    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);
        let ver_type = (self.version << 4) | self.hdr_type;
        buf.put_u8(ver_type);
        buf.put_u8(self.vrid);
        buf.put_u8(self.priority);
        buf.put_u8(self.count_ip);
        buf.put_u8(self.auth_type);
        buf.put_u8(self.adver_int);
        buf.put_u16(self.checksum);
        for addr in &self.ip_addresses {
            buf.put_ipv4(addr);
        }

        buf.put_u32(self.auth_data);
        buf.put_u32(self.auth_data2);
        buf
    }

    // Decodes VRRP packet from a bytes buffer.
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        // 1. pkt length verification
        let pkt_size = data.len();

        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version = ver_type >> 4;
        let hdr_type = ver_type & 0x0F;
        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();
        let auth_type = buf.get_u8();
        let adver_int = buf.get_u8();

        if !(Self::MIN_PKT_LENGTH..=Self::MAX_PKT_LENGTH).contains(&pkt_size)
            || count_ip as usize > Self::MAX_IP_COUNT
            || (count_ip * 4) + 16 != pkt_size as u8
        {
            return Err(DecodeError::PacketLengthError);
        }

        let checksum = buf.get_u16();

        // confirm checksum. checksum position is the third item in 16 bit words
        let calculated_checksum = checksum::calculate(data, 3);
        if calculated_checksum != checksum {
            return Err(DecodeError::ChecksumError);
        }

        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for _ in 0..count_ip {
            ip_addresses.push(buf.get_ipv4());
        }

        let auth_data = buf.get_u32();
        let auth_data2 = buf.get_u32();

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

    pub fn generate_checksum(&mut self) {
        self.checksum = checksum::calculate(self.encode().chunk(), 3);
    }
}

impl Ipv4Hdr {
    const MIN_HDR_LENGTH: usize = 20;
    const MAX_HDR_LENGTH: usize = 24;

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        buf.put_u8(self.version << 4 | self.ihl);
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
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        let ver_ihl = buf.get_u8();
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;

        // verify if header length matches packet information
        // A Malory may have declared a wrong number of ips
        // in count_ip than they actually have in the body. This may
        // lead to trying to read data that is either out of bounds or
        // fully not reading data sent.
        if ihl as usize != data.len() / 4 {
            return Err(DecodeError::PacketLengthError);
        }

        if ihl < (Self::MIN_HDR_LENGTH as u8 / 4) {
            return Err(DecodeError::PacketLengthError);
        }

        if ihl > (Self::MAX_HDR_LENGTH as u8 / 4) {
            return Err(DecodeError::PacketLengthError);
        }

        let tos = buf.get_u8();
        let total_length = buf.get_u16();
        let identification = buf.get_u16();

        // flag_off -> flags[4 bits] + offset[12 bits]
        let flag_off = buf.get_u16();
        let flags: u8 = (flag_off >> 12) as u8;
        let offset: u16 = flag_off & 0xFFF;

        let ttl = buf.get_u8();
        let protocol = buf.get_u8();
        let checksum = buf.get_u16();
        // confirm checksum. checksum position is the 5th 16 bit word
        let calculated_checksum = checksum::calculate(data, 5);
        if calculated_checksum != checksum {
            return Err(DecodeError::ChecksumError);
        }

        let src_address = buf.get_ipv4();
        let dst_address = buf.get_ipv4();

        let mut options: Option<u32> = None;
        let mut padding: Option<u8> = None;

        if ihl > Self::MIN_HDR_LENGTH as u8 {
            let opt_pad = buf.get_u32();
            options = Some(opt_pad >> 8);
            padding = Some((opt_pad & 0xFF) as u8);
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
            ethertype: 0x0800,
        })
    }

    pub fn vrrp(vrid: u8) -> Self {
        Self {
            dst_mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x12],
            src_mac: [0x00, 0x00, 0x5e, 0x00, 0x01, vrid],
            ethertype: 0x0800, // IP ethertype
        }
    }
}

impl VrrpPacket {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(130);
        buf.put(self.ip.encode());
        buf.put(self.vrrp.encode());
        buf
    }
}

impl ArpPacket {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(28);
        buf.put_u16(self.hw_type);
        buf.put_u16(self.proto_type);
        buf.put_u8(self.hw_length);
        buf.put_u8(self.proto_length);
        buf.put_u16(self.operation);

        for x in self.sender_hw_address {
            buf.put_u8(x);
        }
        for x in self.sender_proto_address {
            buf.put_u8(x);
        }
        for x in self.target_hw_address {
            buf.put_u8(x)
        }
        for x in self.target_proto_address {
            buf.put_u8(x)
        }
        buf
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        if data.len() != 28 {
            return Err(DecodeError::PacketLengthError);
        }
        let mut buf = Bytes::copy_from_slice(data);

        let hw_type = buf.get_u16();
        let proto_type = buf.get_u16();
        let hw_length = buf.get_u8();
        let proto_length = buf.get_u8();
        let operation = buf.get_u16();

        let sender_hw_address: [u8; 6] = [0_u8; 6];
        for mut _x in &sender_hw_address {
            _x = &buf.get_u8();
        }

        let sender_proto_address: [u8; 4] = [0_u8; 4];
        for mut _x in &sender_proto_address {
            _x = &buf.get_u8();
        }

        let target_hw_address: [u8; 6] = [0_u8; 6];
        for mut _x in &target_hw_address {
            _x = &buf.get_u8();
        }

        let target_proto_address: [u8; 4] = [0_u8; 4];
        for mut _x in &target_proto_address {
            _x = &buf.get_u8();
        }

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

pub mod checksum {
    pub fn calculate(data: &[u8], checksum_position: usize) -> u16 {
        let mut result: u16 = 0;

        // since data is in u8's, we need pairs of the data to get u16
        for (i, pair) in data.chunks(2).enumerate() {
            // the fifth pair is the checksum field, which is ignored
            if i == checksum_position {
                continue;
            }

            result =
                add_values(result, ((pair[0] as u16) << 8) | pair[1] as u16);
        }

        // do a one's complement to get the sum
        !result
    }

    fn add_values(mut first: u16, mut second: u16) -> u16 {
        let mut carry: u32 = 10;
        let mut result: u16 = 0;

        while carry != 0 {
            let tmp_res = first as u32 + second as u32;
            result = (tmp_res & 0xFFFF) as u16;
            carry = tmp_res >> 16;
            first = result;
            second = carry as u16;
        }
        result
    }
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.err().fmt(f)
    }
}

impl std::error::Error for DecodeError {}
