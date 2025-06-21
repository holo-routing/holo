use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::BytesMutExt;
use num_traits::FromPrimitive;

use crate::igmp::packet::packet::{
    DecodeError, DecodeResult, IgmpV2Message, LeaveGroupV2, MembershipReportV2,
};
use crate::packet::PacketType;

fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }

    if let Some(&last_byte) = chunks.remainder().first() {
        let word = u16::from_be_bytes([last_byte, 0]) as u32;
        sum = sum.wrapping_add(word);
    }

    // Fold overflow
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn is_valid_checksum(data: &[u8]) -> bool {
    compute_checksum(data) == 0
}

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

        // Validate checksum
        if !is_valid_checksum(&buf_orig[0..buf_orig.len()]) {
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
        let checksum = compute_checksum(&buf[0..buf.len()]);

        // overwrite the checksum
        buf[2] = (checksum >> 8) as u8;
        buf[3] = (checksum & 0xFF) as u8;
    }
}

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
        if !is_valid_checksum(&buf_orig[0..buf_orig.len()]) {
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

        let checksum = compute_checksum(&buf[0..buf.len()]);

        // overwrite the checksum
        buf[2] = (checksum >> 8) as u8;
        buf[3] = (checksum & 0xFF) as u8;
    }
}
