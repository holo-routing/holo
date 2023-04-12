//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_new::new;
use holo_utils::bfd::State;
use holo_utils::bytes::TLS_BUF;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

//
// Generic BFD Control Packet Format.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       My Discriminator                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Your Discriminator                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Desired Min TX Interval                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Required Min RX Interval                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Required Min Echo RX Interval                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Eq, new, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Packet {
    #[new(value = "1")]
    pub version: u8,
    pub diag: u8,
    pub state: State,
    pub flags: PacketFlags,
    pub detect_mult: u8,
    pub my_discr: u32,
    pub your_discr: u32,
    pub desired_min_tx: u32,
    pub req_min_rx: u32,
    pub req_min_echo_rx: u32,
}

// BFD Diagnostic Codes.
//
// IANA registry:
// https://www.iana.org/assignments/bfd-parameters/bfd-parameters.xhtml#bfd-parameters-1
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DiagnosticCode {
    Nothing = 0,
    TimeExpired = 1,
    EchoFailed = 2,
    NbrDown = 3,
    FwdPlaneReset = 4,
    PathDown = 5,
    ConcatPathDown = 6,
    AdminDown = 7,
    RevConcatPathDown = 8,
    MisConnectivity = 9,
}

// BFD packet flags.
bitflags! {
    #[derive(Default)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct PacketFlags: u8 {
        const P = 1 << 5;
        const F = 1 << 4;
        const C = 1 << 3;
        const A = 1 << 2;
        const D = 1 << 1;
        const M = 1 << 0;
    }
}

// BFD decode errors.
#[derive(Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum DecodeError {
    IncompletePacket,
    InvalidVersion(u8),
    InvalidPacketLength(u8),
}

// ===== impl Packet =====

impl Packet {
    pub const VERSION: u8 = 1;
    pub const MANDATORY_SECTION_LEN: u8 = 24;

    // Encodes BFD packet into a bytes buffer.
    pub fn encode(&self) -> BytesMut {
        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            buf.put_u8(self.version << 5 | self.diag);
            buf.put_u8((self.state as u8) << 6 | self.flags.bits());
            buf.put_u8(self.detect_mult);
            // The length will be initialized later.
            buf.put_u8(0);
            buf.put_u32(self.my_discr);
            buf.put_u32(self.your_discr);
            buf.put_u32(self.desired_min_tx);
            buf.put_u32(self.req_min_rx);
            buf.put_u32(self.req_min_echo_rx);

            // Initialize packet length.
            buf[3] = buf.len() as u8;
            buf.clone()
        })
    }

    // Decodes BFD packet from a bytes buffer.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut buf = Bytes::copy_from_slice(data);

        // Validate the packet length.
        if data.len() < Self::MANDATORY_SECTION_LEN as _ {
            return Err(DecodeError::IncompletePacket);
        }

        let first_byte = buf.get_u8();
        let sec_byte = buf.get_u8();
        let version = first_byte >> 5;
        if version != Self::VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }
        let diag = first_byte & 0x0F;
        let state = State::from_u8(sec_byte >> 6).unwrap();
        let flags = PacketFlags::from_bits_truncate(sec_byte & 0x3F);
        let detect_mult = buf.get_u8();
        let length = buf.get_u8();
        if length != Self::MANDATORY_SECTION_LEN {
            return Err(DecodeError::InvalidPacketLength(length));
        }
        let my_discr = buf.get_u32();
        let your_discr = buf.get_u32();
        let desired_min_tx = buf.get_u32();
        let req_min_rx = buf.get_u32();
        let req_min_echo_rx = buf.get_u32();

        let packet = Packet {
            version,
            diag,
            state,
            flags,
            detect_mult,
            my_discr,
            your_discr,
            desired_min_tx,
            req_min_rx,
            req_min_echo_rx,
        };

        Ok(packet)
    }
}

// ===== impl DecodeError =====

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::IncompletePacket => {
                write!(f, "Incomplete packet")
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "Invalid BFD version: {}", version)
            }
            DecodeError::InvalidPacketLength(len) => {
                write!(f, "Invalid packet length: {}", len)
            }
        }
    }
}

impl std::error::Error for DecodeError {}
