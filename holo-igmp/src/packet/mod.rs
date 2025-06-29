pub mod packet;

use bytes::{Buf, Bytes, BytesMut};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::igmp::packet::packet::{
    DecodeError, DecodeResult, LeaveGroupV2, MembershipReportV2,
};

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
