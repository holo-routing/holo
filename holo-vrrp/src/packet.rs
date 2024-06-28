//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use crate::error::{self, Error, GlobalError, VirtualRouterError};
use std::net::Ipv4Addr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use serde::{Deserialize, Serialize};

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
pub struct VrrpPacket {
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
pub struct Ipv4Packet {
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
            },
            DecodeError::PacketLengthError => {
                Error::VirtualRouterError(VirtualRouterError::PacketLengthError)
            },
            DecodeError::IpTtlError => {
                Error::GlobalError(GlobalError::IpTtlError)
            },
            DecodeError::VersionError => {
                Error::GlobalError(GlobalError::VersionError)
            },
        }
    }
}

// ===== impl Packet =====

impl VrrpPacket {
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
        let count_ip = data[3];

        if pkt_size < Self::MIN_PKT_LENGTH 
            || pkt_size >Self::MAX_PKT_LENGTH 
            || count_ip as usize > Self::MAX_IP_COUNT //  too many Virtual IPs being described
            || (count_ip * 4) + 16 != pkt_size as u8 // length of packet is not same as length expected (as calculated from count_ip)
            {
                return Err(DecodeError::PacketLengthError)
            }

        
        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let version = ver_type >> 4;
        let hdr_type = ver_type & 0x0F;
        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();
        let auth_type = buf.get_u8();
        let adver_int = buf.get_u8();
        let checksum = buf.get_u16();

        // confirm checksum. checksum position is the third item in 16 bit words
        let calculated_checksum = checksum::calculate(data, 3);
        if calculated_checksum != checksum {
            return Err(DecodeError::ChecksumError);
        }

        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for addr in 0..count_ip {
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
            auth_data: auth_data,
            auth_data2: auth_data2,
        })
    }
}

impl Ipv4Packet {
    const MIN_HDR_LENGTH: usize = 20;
    const MAX_HDR_LENGTH: usize = 24;

    fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // ver_ihl -> version[4 bits] + ihl[4 bits]
        let ver_ihl: u8 = (self.version << 4) | self.ihl;
        buf.put_u8(ver_ihl);
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
            let tmp_res = (first as u32 + second as u32) as u32;
            result = (tmp_res & 0xFFFF) as u16;
            carry = tmp_res >> 16;
            first = result as u16;
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
