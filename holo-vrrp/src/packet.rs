//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr};

//use bitflags::bitflags;
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
pub struct VRRPPacket {
    // version + type [4 bits each]
    ver_type: u8, 
    vrid: u8,
    priority: u8,
    count_ip: u8,
    auth_type: u8,
    adver_int: u8,
    checksum: u16,
    ip_addresses: Vec<Ipv4Addr>,

    // the following two are only used for backward compatibility. 
    auth_data: u32,
    auth_data2: u32
}

// VRRP decode errors.
#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    ChecksumError,
    PacketLengthError(PacketLengthError),
    IpTtlError(u8),
    VersionError(u8)
}
 
#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PacketLengthError {

    // A maximum number of 16 IP addresses are allowed for 
    // VRRP. Referenced from count_ip field
    AddressCount(usize),

    // specified on the vrrp-ietf. when length of the 
    // vrrp packet is less than 16 bytes. 
    TooShort(usize),

    // total 
    TooLong(usize),

    // when the number of ips specified under count_ip
    // does not correspond to the actual length of the packet
    // (total_length = 16 + (4 * no of ips))
    CorruptedLength

}

// ===== impl Packet =====

impl VRRPPacket {
    // Encodes VRRP packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(114);
        buf.put_u8(self.ver_type);
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
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> { 

        // 1. pkt length verification
        let pkt_size = data.len();
        let count_ip = data[3];

        if pkt_size < 16 { 
            return Err(DecodeError::PacketLengthError(PacketLengthError::TooShort(pkt_size)))
        }
        
        if pkt_size > 80 {
            return Err(DecodeError::PacketLengthError(PacketLengthError::TooLong(pkt_size)))
        }

        if count_ip > 16 {
            return Err(
                DecodeError::PacketLengthError(PacketLengthError::AddressCount(count_ip as usize))
            )
        }

        // check if the ip_count has been verified with the actual length
        // A Mallory may have tried carrying out something naughty
        if (count_ip * 4) + 16 != pkt_size as u8 {
            return Err(
                DecodeError::PacketLengthError(PacketLengthError::CorruptedLength)
            )
        }
        


        let mut buf: Bytes = Bytes::copy_from_slice(data);
        let ver_type = buf.get_u8();
        let vrid = buf.get_u8();
        let priority = buf.get_u8();
        let count_ip = buf.get_u8();    
        let auth_type = buf.get_u8();
        let adver_int = buf.get_u8();
        let checksum = buf.get_u16();
        
        let mut ip_addresses: Vec<Ipv4Addr> = vec![];
        for addr in 0..count_ip {
            ip_addresses.push(buf.get_ipv4());
        }
        let auth_data = buf.get_u32();
        let auth_data2 = buf.get_u32();


        Ok(Self {
            ver_type,
            vrid,
            priority,
            count_ip,
            auth_type,
            adver_int,
            checksum,
            ip_addresses,
            auth_data,
            auth_data2
        })

    }
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::ChecksumError => {
                write!(f, "Checksum is not valid")
            },
            
            DecodeError::IpTtlError(rx_ttl) => {
                write!(f, "TTL less than 255: {rx_ttl}")
            },
            DecodeError::VersionError(rx_version) => {
                write!(f, "Invalid version: {rx_version}")
            }
            DecodeError::PacketLengthError(err) => {
                std::fmt::Display::fmt(err, f)
            }
        }
    }
}

impl std::fmt::Display for PacketLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketLengthError::TooLong(rx_len) => {
                write!(f, "Too many bytes for VRRP packet: {rx_len}")
            },
            PacketLengthError::TooShort(rx_len) => {
                write!(f, "Not enough bytes for VRRP packets: {rx_len}")
            },
            PacketLengthError::AddressCount(rx_count) => {
                write!(f, "Too many IP addresses {rx_count}")
            },
            PacketLengthError::CorruptedLength => {
                write!(f, "Count_ip not corresponding with no of bytes in packet")
            },
        }
    }
}

impl std::error::Error for DecodeError {}
