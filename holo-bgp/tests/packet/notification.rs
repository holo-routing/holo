//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_bgp::packet::consts::{ErrorCode, MessageHeaderErrorSubcode};
use holo_bgp::packet::message::{Message, NotificationMsg};

use super::{test_decode_msg, test_encode_msg};

static NOTIFICATION1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x03, 0x01, 0x02, 0xff,
            0xff,
        ],
        Message::Notification(NotificationMsg {
            error_code: ErrorCode::MessageHeaderError as u8,
            error_subcode: MessageHeaderErrorSubcode::BadMessageLength as u8,
            data: vec![0xff, 0xff],
        }),
    )
});

#[test]
fn test_encode_notification1() {
    let (ref bytes, ref msg) = *NOTIFICATION1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_notification1() {
    let (ref bytes, ref msg) = *NOTIFICATION1;
    test_decode_msg(bytes, msg);
}
