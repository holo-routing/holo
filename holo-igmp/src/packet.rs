//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
use std::net::Ipv4Addr;
use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use internet_checksum::Checksum;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

// Type aliases.
pub type DecodeResult<T> = Result<T, DecodeError>;

// Decode errors.
#[derive(Debug, Deserialize, Serialize)]
pub enum DecodeError {
    InsufficientData,
    InvalidChecksum,
    InvalidVersion(u8),
    UnknownPacketType(u8),
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  |    Unused     |           Checksum            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Group Address                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IgmpMessage {
    pub version: u8,
    pub igmp_type: PacketType,
    pub unused: Option<u8>,
    pub checksum: u16,
    pub group_address: Option<Ipv4Addr>,
}

// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------------------------------------------------------
// |      Type     | Max Resp Time |           Checksum            |
// +---------------------------------------------------------------
// |                         Group Address                         |
// +---------------------------------------------------------------

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct IgmpV2Message {
    pub igmp_type: PacketType,
    pub max_resp_time: Option<u8>,
    pub checksum: u16,
    pub group_address: Option<Ipv4Addr>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct MembershipReportV2(pub IgmpV2Message);

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone)]
pub struct LeaveGroupV2(pub IgmpV2Message);

impl Deref for MembershipReportV2 {
    type Target = IgmpV2Message;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for LeaveGroupV2 {
    type Target = IgmpV2Message;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// IGMP Packet Type.
//
// IANA registry:
// https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml#igmp-type-numbers-2
#[derive(Clone, Copy, Debug, Eq, Hash, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PacketType {
    MembershipQueryType = 0x11,
    MembershipReportV1Type = 0x12,
    MembershipReportV2Type = 0x16,
    LeaveGroupV2Type = 0x17,
}

// IGMP2 Packets
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Packet {
    MembershipReport(MembershipReportV2),
    LeaveGroup(LeaveGroupV2),
}

// ===== impl Packet =====

impl Packet {
    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        if buf.len() < 8 {
            return Err(DecodeError::InsufficientData);
        }

        let mut buf_orig = buf.clone();
        let pkt_type = buf_orig.get_u8();

        let pkt_type = match PacketType::from_u8(pkt_type) {
            Some(pkt_type) => pkt_type,
            None => return Err(DecodeError::InvalidVersion(pkt_type)),
        };

        let packet = match pkt_type {
            PacketType::MembershipReportV2Type => {
                Packet::MembershipReport(MembershipReportV2::decode(buf)?)
            }
            PacketType::LeaveGroupV2Type => {
                Packet::LeaveGroup(LeaveGroupV2::decode(buf)?)
            }
            _ => {
                return Err(DecodeError::UnknownPacketType(pkt_type as u8));
            }
        };
        Ok(packet)
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(255);

        match self {
            Packet::MembershipReport(report) => {
                report.encode(&mut buf);
            }
            Packet::LeaveGroup(leave) => {
                leave.encode(&mut buf);
            }
        }

        return buf.freeze();
    }
}

const CKSUM_RANGE: std::ops::Range<usize> = 2..4;

fn update_cksum(buf: &mut BytesMut) {
    let mut cksum = Checksum::new();
    cksum.add_bytes(buf);
    buf[CKSUM_RANGE].copy_from_slice(&cksum.checksum());
}

fn verify_cksum(data: &[u8]) -> DecodeResult<()> {
    let mut cksum = Checksum::new();
    cksum.add_bytes(data);
    if cksum.checksum() != [0, 0] {
        return Err(DecodeError::InvalidChecksum);
    }
    Ok(())
}

// ===== impl MembershipReportV2 =====

impl MembershipReportV2 {
    const LENGTH: usize = 8;

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        let buf_orig = buf.clone();

        if buf.len() < Self::LENGTH {
            return Err(DecodeError::InsufficientData);
        }

        let pkt_type = buf.get_u8();
        let pkt_type = match PacketType::from_u8(pkt_type) {
            Some(pkt_type) => pkt_type,
            None => return Err(DecodeError::InvalidVersion(pkt_type)),
        };

        if pkt_type != PacketType::MembershipReportV2Type {
            return Err(DecodeError::UnknownPacketType(pkt_type as u8));
        }

        let max_resp_time = Some(buf.get_u8());
        let checksum = buf.get_u16();

        if verify_cksum(buf_orig.as_ref()).is_err() {
            return Err(DecodeError::InvalidChecksum);
        }

        let group_address = Some(Ipv4Addr::new(
            buf.get_u8(),
            buf.get_u8(),
            buf.get_u8(),
            buf.get_u8(),
        ));

        let msg = IgmpV2Message {
            igmp_type: pkt_type,
            max_resp_time,
            checksum,
            group_address,
        };

        Ok(MembershipReportV2(msg))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.igmp_type as u8);
        buf.put_u8(self.max_resp_time.unwrap_or(0));
        buf.put_u16(0);
        if let Some(addr) = self.group_address {
            buf.put_ipv4(&addr);
        }

        update_cksum(buf);
    }
}

// ===== impl LeaveGroupV2 =====

impl LeaveGroupV2 {
    const LENGTH: usize = 8;

    pub fn decode(buf: &mut Bytes) -> DecodeResult<Self> {
        // make a copy of the buffer for checksum validation
        let buf_orig = buf.clone();

        if buf.len() < Self::LENGTH {
            return Err(DecodeError::InsufficientData);
        }

        let pkt_type = buf.get_u8();
        let pkt_type = match PacketType::from_u8(pkt_type) {
            Some(pkt_type) => pkt_type,
            None => return Err(DecodeError::InvalidVersion(pkt_type)),
        };

        if pkt_type != PacketType::LeaveGroupV2Type {
            return Err(DecodeError::UnknownPacketType(pkt_type as u8));
        }

        let _responce_time = buf.get_u8();

        let checksum = buf.get_u16();

        if verify_cksum(buf_orig.as_ref()).is_err() {
            return Err(DecodeError::InvalidChecksum);
        }

        let group_address = Some(buf.get_ipv4());

        let msg = IgmpV2Message {
            igmp_type: pkt_type,
            max_resp_time: Some(0),
            checksum,
            group_address,
        };

        Ok(LeaveGroupV2(msg))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.igmp_type as u8);
        buf.put_u8(0); // max_resp_time is not used in LeaveGroupV2
        buf.put_u16(0);
        if let Some(addr) = self.group_address {
            buf.put_ipv4(&addr);
        }

        update_cksum(buf);
    }
}
