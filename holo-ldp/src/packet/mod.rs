//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod error;
pub mod message;
pub mod messages;
pub mod pdu;
pub mod tlv;

use std::net::{IpAddr, Ipv4Addr};

pub use error::*;
pub use message::*;
pub use messages::*;
pub use pdu::*;
pub use tlv::*;

// Information about a received packet.
pub struct PacketInfo {
    pub src_addr: IpAddr,
    pub multicast: Option<bool>,
}

// LDP packet decoding context.
pub struct DecodeCxt {
    pub pkt_info: PacketInfo,
    pub pdu_max_len: u16,
    pub validate_pdu_hdr: Option<Box<PduHdrValidationCb>>,
    pub validate_msg_hdr: Option<Box<MsgHdrValidationCb>>,
}

// PDU/message header validation callbacks.
pub type PduHdrValidationCb =
    dyn Fn(Ipv4Addr, u16) -> DecodeResult<()> + Send + Sync;
pub type MsgHdrValidationCb =
    dyn Fn(u16, u32) -> DecodeResult<()> + Send + Sync;
