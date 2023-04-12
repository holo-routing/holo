//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::packet::error::DecodeResult;
use crate::packet::message::{
    Message, MessageDecodeInfo, MessageKind, MessageType,
};
use crate::packet::DecodeCxt;

//
// KeepAlive Message.
//
// Encoding format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0|   KeepAlive (0x0201)        |      Message Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Message ID                                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Optional Parameters                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeepaliveMsg {
    pub msg_id: u32,
}

// ===== impl KeepaliveMsg =====

impl MessageKind for KeepaliveMsg {
    const U_BIT: bool = false;

    fn msg_id(&self) -> u32 {
        self.msg_id
    }

    fn msg_type(&self) -> MessageType {
        MessageType::Keepalive
    }

    fn encode_body(&self, _buf: &mut BytesMut) {}

    fn decode_body(
        buf: &mut Bytes,
        cxt: &DecodeCxt,
        msgi: &mut MessageDecodeInfo,
    ) -> DecodeResult<Message> {
        // Create new message.
        let mut msg = KeepaliveMsg {
            msg_id: msgi.msg_id,
        };

        // Decode optional TLV(s).
        msg.decode_opt_tlvs(buf, cxt, msgi)?;

        Ok(Message::Keepalive(msg))
    }
}
