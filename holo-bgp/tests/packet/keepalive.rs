//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_bgp::packet::message::{KeepaliveMsg, Message};

use super::{test_decode_msg, test_encode_msg};

static KEEPALIVE1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
        ],
        Message::Keepalive(KeepaliveMsg {}),
    )
});

#[test]
fn test_encode_keepalive1() {
    let (ref bytes, ref msg) = *KEEPALIVE1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_keepalive1() {
    let (ref bytes, ref msg) = *KEEPALIVE1;
    test_decode_msg(bytes, msg);
}
