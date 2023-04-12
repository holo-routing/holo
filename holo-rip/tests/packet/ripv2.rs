//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::LazyLock as Lazy;

use holo_rip::packet::{Command, PduVersion};
use holo_rip::ripv2::packet::{
    DecodeError, DecodeResult, Pdu, Rte, RteIpv4, RteZero,
};
use holo_rip::route::Metric;
use ipnetwork::Ipv4Network;

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
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10,
        ],
        Ok(Pdu {
            command: Command::Request,
            version: 2,
            rtes: vec![Rte::Zero(RteZero {
                metric: Metric::from(Metric::INFINITE),
            })],
            rte_errors: vec![],
        }),
    )
});

static RESPONSE1: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x02,
            0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ],
        Ok(Pdu {
            command: Command::Response,
            version: 2,
            rtes: vec![
                Rte::Ipv4(RteIpv4 {
                    tag: 0,
                    prefix: Ipv4Network::from_str("10.0.2.0/24").unwrap(),
                    nexthop: None,
                    metric: Metric::from(1),
                }),
                Rte::Ipv4(RteIpv4 {
                    tag: 0,
                    prefix: Ipv4Network::from_str("10.0.3.0/24").unwrap(),
                    nexthop: None,
                    metric: Metric::from(3),
                }),
                Rte::Ipv4(RteIpv4 {
                    tag: 0,
                    prefix: Ipv4Network::from_str("10.0.4.0/24").unwrap(),
                    nexthop: None,
                    metric: Metric::from(2),
                }),
            ],
            rte_errors: vec![],
        }),
    )
});

static RESPONSE2: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x02,
            0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00,
        ],
        Err(DecodeError::InvalidVersion(1)),
    )
});

static RESPONSE3: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x02,
            0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00,
        ],
        Err(DecodeError::InvalidCommand(3)),
    )
});

static RESPONSE4: Lazy<(Vec<u8>, DecodeResult<Pdu>)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x02,
            0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0xff,
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0xff, 0xff, 0xff,
            0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02,
            0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
        ],
        Ok(Pdu {
            command: Command::Response,
            version: 2,
            rtes: vec![],
            rte_errors: vec![
                DecodeError::InvalidRteAddressFamily(1),
                DecodeError::InvalidRtePrefix(
                    Ipv4Addr::from_str("127.0.0.1").unwrap(),
                    Ipv4Addr::from_str("255.255.255.255").unwrap(),
                ),
                DecodeError::InvalidRteNexthop(
                    Ipv4Addr::from_str("127.0.0.1").unwrap(),
                ),
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
