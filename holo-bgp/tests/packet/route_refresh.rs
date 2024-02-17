//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_bgp::packet::consts::{Afi, Safi};
use holo_bgp::packet::message::{Message, RouteRefreshMsg};

use super::{test_decode_msg, test_encode_msg};

static ROUTE_REFRESH1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x05, 0x00, 0x01, 0x00,
            0x01,
        ],
        Message::RouteRefresh(RouteRefreshMsg {
            afi: Afi::Ipv4 as u16,
            safi: Safi::Unicast as u8,
        }),
    )
});

#[test]
fn test_encode_route_refresh1() {
    let (ref bytes, ref msg) = *ROUTE_REFRESH1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_route_refresh1() {
    let (ref bytes, ref msg) = *ROUTE_REFRESH1;
    test_decode_msg(bytes, msg);
}
