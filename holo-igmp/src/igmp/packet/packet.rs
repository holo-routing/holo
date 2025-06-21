use std::net::Ipv4Addr;
use std::ops::Deref;

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

use crate::packet::PacketType;

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
