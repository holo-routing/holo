//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use holo_rip::packet::{Command, PduVersion};
use holo_rip::ripng::packet::{
    DecodeError, DecodeResult, Pdu, Rte, RteIpv6, RteNexthop,
};
use holo_rip::route::Metric;
use ipnetwork::Ipv6Network;

//
// Helper functions.
//

fn test_encode_pdu(bytes_expected: &[u8], pdu: &DecodeResult<Pdu>) {
    let bytes_actual = pdu.as_ref().unwrap().encode();
    assert_eq!(bytes_expected, bytes_actual);
}

fn test_decode_pdu(bytes: &[u8], pdu_expected: &DecodeResult<Pdu>) {
    let pdu_actual = Pdu::decode(&bytes);
    assert_eq!(*pdu_expected, pdu_actual);
}

//
// Test PDUs.
//

static REQUEST1: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10,
        ],
        Ok(Pdu {
            command: Command::Request,
            version: 1,
            rtes: vec![Rte::Ipv6(RteIpv6 {
                prefix: Ipv6Network::from_str("::/0").unwrap(),
                tag: 0,
                metric: Metric::from(Metric::INFINITE),
            })],
            rte_errors: vec![],
        }),
    )
});

static RESPONSE1: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x80, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x80, 0x02,
            0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x80, 0x03,
        ],
        Ok(Pdu {
            command: Command::Response,
            version: 1,
            rtes: vec![
                Rte::Ipv6(RteIpv6 {
                    prefix: Ipv6Network::from_str("2001:db8:1000::1/128")
                        .unwrap(),
                    tag: 0,
                    metric: Metric::from(1),
                }),
                Rte::Ipv6(RteIpv6 {
                    prefix: Ipv6Network::from_str("2001:db8:1000::3/128")
                        .unwrap(),
                    tag: 0,
                    metric: Metric::from(2),
                }),
                Rte::Ipv6(RteIpv6 {
                    prefix: Ipv6Network::from_str("2001:db8:1000::4/128")
                        .unwrap(),
                    tag: 0,
                    metric: Metric::from(3),
                }),
            ],
            rte_errors: vec![],
        }),
    )
});

static RESPONSE2: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x50, 0xbf, 0xcf, 0xff, 0xfe, 0xbe, 0x99, 0x99, 0x00, 0x00,
            0x00, 0xff, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01,
        ],
        Ok(Pdu {
            command: Command::Response,
            version: 1,
            rtes: vec![
                Rte::Nexthop(RteNexthop {
                    addr: Some(
                        Ipv6Addr::from_str("fe80::50bf:cfff:febe:9999")
                            .unwrap(),
                    ),
                }),
                Rte::Ipv6(RteIpv6 {
                    prefix: Ipv6Network::from_str("2001:db8:1000::/64")
                        .unwrap(),
                    tag: 0,
                    metric: Metric::from(1),
                }),
            ],
            rte_errors: vec![],
        }),
    )
});

static RESPONSE3: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x02, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x80, 0x01,
        ],
        Err(DecodeError::InvalidVersion(2)),
    )
});

static RESPONSE4: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x80, 0x01,
        ],
        Err(DecodeError::InvalidCommand(3)),
    )
});

static RESPONSE5: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x80, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x81, 0x02,
            0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x80, 0x14,
        ],
        Ok(Pdu {
            command: Command::Response,
            version: 1,
            rtes: vec![],
            rte_errors: vec![
                DecodeError::InvalidRtePrefix(
                    Ipv6Addr::from_str("::1").unwrap(),
                ),
                DecodeError::InvalidRtePrefixLength(129),
                DecodeError::InvalidRteMetric(20),
            ],
        }),
    )
});

//
// Tests.
//

#[test]
fn test_encode_request1() {
    let (ref bytes, ref pdu) = *REQUEST1;
    test_encode_pdu(bytes, pdu);
}

#[test]
fn test_decode_request1() {
    let (ref bytes, ref pdu) = *REQUEST1;
    test_decode_pdu(bytes, pdu);
}

#[test]
fn test_encode_response1() {
    let (ref bytes, ref pdu) = *RESPONSE1;
    test_encode_pdu(bytes, pdu);
}

#[test]
fn test_decode_response1() {
    let (ref bytes, ref pdu) = *RESPONSE1;
    test_decode_pdu(bytes, pdu);
}

#[test]
fn test_encode_response2() {
    let (ref bytes, ref pdu) = *RESPONSE2;
    test_encode_pdu(bytes, pdu);
}

#[test]
fn test_decode_response2() {
    let (ref bytes, ref pdu) = *RESPONSE2;
    test_decode_pdu(bytes, pdu);
}

#[test]
fn test_decode_response3() {
    let (ref bytes, ref pdu) = *RESPONSE3;
    test_decode_pdu(bytes, pdu);
}

#[test]
fn test_decode_response4() {
    let (ref bytes, ref pdu) = *RESPONSE4;
    test_decode_pdu(bytes, pdu);
}

#[test]
fn test_decode_response5() {
    let (ref bytes, ref pdu) = *RESPONSE5;
    test_decode_pdu(bytes, pdu);
}
