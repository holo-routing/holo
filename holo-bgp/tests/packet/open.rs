//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use const_addrs::ip4;
use holo_bgp::packet::consts::{Afi, BGP_VERSION, Safi};
use holo_bgp::packet::message::{Capability, Message, OpenMsg};

use super::{test_decode_msg, test_encode_msg};

static OPEN1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01,
            0x00, 0xb4, 0x01, 0x01, 0x01, 0x01, 0x00,
        ],
        Message::Open(OpenMsg {
            version: BGP_VERSION,
            my_as: 1,
            holdtime: 180,
            identifier: ip4!("1.1.1.1"),
            capabilities: [].into(),
        }),
    )
});

static OPEN2: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x25, 0x01, 0x04, 0x00, 0x01,
            0x00, 0xb4, 0x01, 0x01, 0x01, 0x01, 0x08, 0x02, 0x06, 0x01, 0x04,
            0x00, 0x01, 0x00, 0x01,
        ],
        Message::Open(OpenMsg {
            version: BGP_VERSION,
            my_as: 1,
            holdtime: 180,
            identifier: ip4!("1.1.1.1"),
            capabilities: [Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }]
            .into(),
        }),
    )
});

static OPEN3: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x3d, 0x01, 0x04, 0x00, 0x01,
            0x00, 0xb4, 0x01, 0x01, 0x01, 0x01, 0x20, 0x02, 0x06, 0x01, 0x04,
            0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00,
            0x01, 0x02, 0x06, 0x41, 0x04, 0x00, 0x01, 0x00, 0x0e, 0x02, 0x02,
            0x02, 0x00, 0x02, 0x02, 0x46, 0x00,
        ],
        Message::Open(OpenMsg {
            version: BGP_VERSION,
            my_as: 1,
            holdtime: 180,
            identifier: ip4!("1.1.1.1"),
            capabilities: [
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::MultiProtocol {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAsNumber { asn: 65550 },
                Capability::RouteRefresh,
                Capability::EnhancedRouteRefresh,
            ]
            .into(),
        }),
    )
});

#[test]
fn test_encode_open1() {
    let (ref bytes, ref msg) = *OPEN1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_open1() {
    let (ref bytes, ref msg) = *OPEN1;
    test_decode_msg(bytes, msg);
}

#[test]
fn test_encode_open2() {
    let (ref bytes, ref msg) = *OPEN2;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_open2() {
    let (ref bytes, ref msg) = *OPEN2;
    test_decode_msg(bytes, msg);
}

#[test]
fn test_encode_open3() {
    let (ref bytes, ref msg) = *OPEN3;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_open3() {
    let (ref bytes, ref msg) = *OPEN3;
    test_decode_msg(bytes, msg);
}
