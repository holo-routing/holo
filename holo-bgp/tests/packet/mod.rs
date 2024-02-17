//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod keepalive;
mod notification;
mod open;
mod route_refresh;
mod update;

use holo_bgp::neighbor::PeerType;
use holo_bgp::packet::message::{
    Capability, DecodeCxt, EncodeCxt, FourOctetAsNumber, Message,
};

//
// Helper functions.
//

fn test_encode_msg(bytes_expected: &[u8], msg: &Message) {
    let cxt = EncodeCxt {
        capabilities: [Capability::FourOctetAsNumber {
            asn: FourOctetAsNumber(65550),
        }]
        .into(),
    };

    let bytes_actual = msg.encode(&cxt);
    let data = format!("{:#04x?}", bytes_actual.as_ref());
    let _ = std::fs::write("/tmp/test-data", data);
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_msg(bytes: &[u8], msg_expected: &Message) {
    let cxt = DecodeCxt {
        peer_type: PeerType::Internal,
        peer_as: 65550,
        capabilities: [Capability::FourOctetAsNumber {
            asn: FourOctetAsNumber(65550),
        }]
        .into(),
    };

    let msg_actual = Message::decode(&bytes, &cxt).unwrap();
    assert_eq!(*msg_expected, msg_actual);
}
