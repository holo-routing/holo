//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt, TLS_BUF};
use serde::{Deserialize, Serialize};

use crate::packet::error::{DecodeError, DecodeResult};
use crate::packet::message::Message;
use crate::packet::DecodeCxt;

//
// LDP PDU.
//
// Each LDP PDU is an LDP header followed by one or more LDP messages.
// The LDP header is:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Version                      |         PDU Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         LDP Identifier                        |
// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pdu {
    // PDU header.
    pub version: u16,
    pub lsr_id: Ipv4Addr,
    pub lspace_id: u16,

    // Messages.
    pub messages: VecDeque<Message>,
}

//
// PDU decode information.
//
// Used as a control block during the decode process, and used to return
// detailed error information.
//
#[derive(Debug)]
pub struct PduDecodeInfo {
    pub version: u16,
    pub lsr_id: Ipv4Addr,
    pub lspace_id: u16,
    pub pdu_raw: Bytes,
    pub pdu_len: u16,
    pub pdu_rlen: u16,
}

// ===== impl Pdu =====

impl Pdu {
    pub const VERSION: u16 = 1;
    pub const HDR_SIZE: u16 = 10;
    pub const HDR_MIN_LEN: u16 = 6;
    pub const HDR_DEAD_LEN: u16 = 4;
    pub const DFLT_MAX_LEN: u16 = 4096;
    pub const MAX_SIZE: usize = u16::MAX as usize + Self::HDR_DEAD_LEN as usize;

    pub(crate) fn new(lsr_id: Ipv4Addr, lspace_id: u16) -> Pdu {
        Pdu {
            version: Pdu::VERSION,
            lsr_id,
            lspace_id,
            messages: VecDeque::new(),
        }
    }

    // Encodes LDP PDU into a bytes buffer.
    //
    // If the size of all messages exceeds the provided maximum PDU length, the
    // messages are split into multiple PDUs as needed.
    pub fn encode(&self, max_pdu_len: u16) -> BytesMut {
        let mut buf_final = BytesMut::new();

        TLS_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();

            // Encode PDU header.
            self.encode_hdr(&mut buf);

            // Iterate over all messages.
            let mut msgs = self.messages.iter().peekable();
            while let Some(msg) = msgs.next() {
                let len = buf.len();

                // Encode message.
                msg.encode(&mut buf);

                // Check if the maximum PDU length was exceeded.
                if buf.len() > max_pdu_len as usize {
                    let mut new_msg = buf.split_to(len);
                    std::mem::swap(&mut new_msg, &mut buf);

                    // Add full PDU.
                    Pdu::init_pdu_length(&mut buf);
                    buf_final.extend(buf.clone());

                    // Prepare other PDU.
                    buf.clear();
                    self.encode_hdr(&mut buf);
                    buf.extend(new_msg);
                }

                // Check if this is the last message.
                if msgs.peek().is_none() {
                    // Add full PDU.
                    Pdu::init_pdu_length(&mut buf);
                    buf_final.extend(buf.clone());
                }
            }
        });

        buf_final
    }

    fn encode_hdr(&self, buf: &mut BytesMut) {
        buf.put_u16(self.version);
        // The length will be initialized later.
        buf.put_u16(0);
        buf.put_ipv4(&self.lsr_id);
        buf.put_u16(self.lspace_id);
    }

    fn init_pdu_length(buf: &mut BytesMut) {
        let pkt_len = buf.len() as u16 - Pdu::HDR_DEAD_LEN;
        buf[2..4].copy_from_slice(&pkt_len.to_be_bytes());
    }

    // Decode buffer into a PDU containing one or more messages.
    // NOTE: Pdu::get_pdu_size() must be called before this method to ensure the
    // given buffer doesn't contain an incomplete PDU.
    pub fn decode(data: &[u8], cxt: &DecodeCxt) -> DecodeResult<Self> {
        // Decode LDP PDU header.
        let mut buf = Bytes::copy_from_slice(data);
        let mut pdui = Pdu::decode_hdr(&mut buf, cxt)?;
        let mut pdu = Pdu::new(pdui.lsr_id, pdui.lspace_id);

        // Decode LDP messages.
        while pdui.pdu_rlen >= Message::HDR_SIZE {
            if let Some(msg) = Message::decode(&mut buf, cxt, &mut pdui)? {
                pdu.messages.push_back(msg);
            }
        }
        // Check for trailing data.
        if pdui.pdu_rlen != 0 {
            return Err(DecodeError::InvalidPduLength(pdui.pdu_len));
        }

        Ok(pdu)
    }

    fn decode_hdr(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
    ) -> DecodeResult<PduDecodeInfo> {
        let buf_copy = buf.clone();

        // Parse and validate LDP version.
        let version = buf.get_u16();
        if version != Pdu::VERSION {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Parse PDU length, LSR-ID and labelspace.
        let pdu_len = buf.get_u16();
        let lsr_id = buf.get_ipv4();
        let lspace_id = buf.get_u16();

        // Save slice containing the entire PDU.
        let pdu_size = pdu_len + Pdu::HDR_DEAD_LEN;
        let pdu_raw = buf_copy.slice(0..pdu_size as usize);

        // Calculate remaining bytes in the PDU.
        let pdu_rlen = pdu_len - Pdu::HDR_MIN_LEN;

        // Call custom validation closure.
        if let Some(validate_pdu_hdr) = &cxt.validate_pdu_hdr {
            (validate_pdu_hdr)(lsr_id, lspace_id)?;
        }

        Ok(PduDecodeInfo {
            version,
            lsr_id,
            lspace_id,
            pdu_raw,
            pdu_len,
            pdu_rlen,
        })
    }

    // Parse data and check whether the buffer contains the whole PDU, returning
    // the PDU size in case of success.
    pub fn get_pdu_size(data: &[u8], cxt: &DecodeCxt) -> DecodeResult<usize> {
        // Validate that the buffer contains enough room for at least the PDU
        // header and one message header.
        let buf_size = data.len();
        if buf_size < (Pdu::HDR_SIZE as usize + Message::HDR_SIZE as usize) {
            return Err(DecodeError::IncompletePdu);
        }

        // Ensure the buffer is big enough to hold the entire PDU.
        let mut buf = Bytes::copy_from_slice(&data[0..4]);
        let _version = buf.get_u16();
        let pdu_len = buf.get_u16();
        if pdu_len < (Pdu::HDR_MIN_LEN + Message::HDR_SIZE)
            || pdu_len > cxt.pdu_max_len
            || pdu_len as usize > (buf_size - Pdu::HDR_DEAD_LEN as usize)
        {
            return Err(DecodeError::IncompletePdu);
        }

        // Return the PDU size.
        Ok(pdu_len as usize + Pdu::HDR_DEAD_LEN as usize)
    }
}
