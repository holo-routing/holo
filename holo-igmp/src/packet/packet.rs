use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use internet_checksum::Checksum;
use num_traits::FromPrimitive;

use crate::igmp::packet::packet::{
    DecodeError, DecodeResult, IgmpV2Message, LeaveGroupV2, MembershipReportV2,
};
use crate::packet::PacketType;

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
