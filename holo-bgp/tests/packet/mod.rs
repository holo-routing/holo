//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod ip;
mod keepalive;
mod notification;
mod open;
mod route_refresh;
mod update;

use holo_bgp::neighbor::PeerType;
use holo_bgp::packet::message::{
    DecodeCxt, EncodeCxt, Message, NegotiatedCapability,
};
use holo_protocol::assert_eq_hex;

//
// Helper functions.
//

fn test_encode_msg(bytes_expected: &[u8], msg: &Message) {
    let cxt = EncodeCxt {
        capabilities: [NegotiatedCapability::FourOctetAsNumber].into(),
    };

    let bytes_actual = msg.encode(&cxt);
    assert_eq_hex!(bytes_expected, bytes_actual);
}

fn test_decode_msg(bytes: &[u8], msg_expected: &Message) {
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 65550,
        capabilities: [NegotiatedCapability::FourOctetAsNumber].into(),
    };

    let msg_size = Message::get_message_len(bytes)
        .expect("Buffer doesn't contain a full BGP message");
    let msg_actual = Message::decode(&bytes[0..msg_size], &cxt).unwrap();
    assert_eq!(*msg_expected, msg_actual);
}
