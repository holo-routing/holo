//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::atomic::AtomicU32;
use std::sync::{Arc, LazyLock as Lazy};

use const_addrs::{ip4, net4};
use holo_rip::packet::{AuthCtx, Command, PduVersion};
use holo_rip::ripv2::packet::{
    DecodeError, DecodeResult, Pdu, Rte, RteIpv4, RteZero,
};
use holo_rip::route::Metric;
use holo_utils::crypto::CryptoAlgo;

//
// Helper functions.
//

fn test_encode_pdu(
    bytes_expected: &[u8],
    pdu: &DecodeResult<Pdu>,
    auth: &Option<AuthCtx>,
) {
    let bytes_actual = pdu.as_ref().unwrap().encode(auth.as_ref());
    assert_eq!(bytes_expected, bytes_actual);
}

fn test_decode_pdu(
    bytes: &[u8],
    pdu_expected: &DecodeResult<Pdu>,
    auth: &Option<AuthCtx>,
) {
    let pdu_actual = Pdu::decode(&bytes, auth.as_ref());
    assert_eq!(*pdu_expected, pdu_actual);
}

//
// Test PDUs.
//

static REQUEST1: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ],
            None,
            Ok(Pdu {
                command: Command::Request,
                version: 2,
                rtes: vec![Rte::Zero(RteZero {
                    metric: Metric::from(Metric::INFINITE),
                })],
                rte_errors: vec![],
                auth_seqno: None,
            }),
        )
    });

static RESPONSE1: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x02, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x03, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x04, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02,
            ],
            None,
            Ok(Pdu {
                command: Command::Response,
                version: 2,
                rtes: vec![
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.2.0/24"),
                        nexthop: None,
                        metric: Metric::from(1),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.3.0/24"),
                        nexthop: None,
                        metric: Metric::from(3),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.4.0/24"),
                        nexthop: None,
                        metric: Metric::from(2),
                    }),
                ],
                rte_errors: vec![],
                auth_seqno: None,
            }),
        )
    });

static RESPONSE2: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x02, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00,
            ],
            None,
            Err(DecodeError::InvalidVersion(1)),
        )
    });

static RESPONSE3: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x02, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00,
            ],
            None,
            Err(DecodeError::InvalidCommand(3)),
        )
    });

static RESPONSE4: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00,
                0x02, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x7f, 0x00,
                0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x03, 0x00, 0xff, 0xff, 0xff, 0x00, 0x7f, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x04, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x14,
            ],
            None,
            Ok(Pdu {
                command: Command::Response,
                version: 2,
                rtes: vec![],
                rte_errors: vec![
                    DecodeError::InvalidRteAddressFamily(1),
                    DecodeError::InvalidRtePrefix(
                        ip4!("127.0.0.1"),
                        ip4!("255.255.255.255"),
                    ),
                    DecodeError::InvalidRteNexthop(ip4!("127.0.0.1")),
                    DecodeError::InvalidRteMetric(20),
                ],
                auth_seqno: None,
            }),
        )
    });

static RESPONSE5: Lazy<(Vec<u8>, Option<AuthCtx>, DecodeResult<Pdu>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x03, 0x00, 0x7c,
                0x01, 0x10, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x01,
                0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x03, 0x03,
                0x03, 0x03, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x01, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x02, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00,
                0x04, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0x00, 0x01, 0xec, 0xc9,
                0xca, 0x82, 0xe0, 0x75, 0xa0, 0x2a, 0xe2, 0x27, 0x56, 0x98,
                0xd1, 0x6d, 0x1d, 0x5d,
            ],
            Some(AuthCtx::new(
                "HOLO".to_owned(),
                CryptoAlgo::Md5,
                Arc::new(AtomicU32::new(69)),
            )),
            Ok(Pdu {
                command: Command::Response,
                version: 2,
                rtes: vec![
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("1.1.1.1/32"),
                        nexthop: None,
                        metric: Metric::from(1),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("3.3.3.3/32"),
                        nexthop: None,
                        metric: Metric::from(2),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.1.0/24"),
                        nexthop: None,
                        metric: Metric::from(1),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.2.0/24"),
                        nexthop: None,
                        metric: Metric::from(1),
                    }),
                    Rte::Ipv4(RteIpv4 {
                        tag: 0,
                        prefix: net4!("10.0.4.0/24"),
                        nexthop: None,
                        metric: Metric::from(2),
                    }),
                ],
                rte_errors: vec![],
                auth_seqno: Some(69),
            }),
        )
    });

//
// Tests.
//

#[test]
fn test_encode_request1() {
    let (ref bytes, ref auth, ref pdu) = *REQUEST1;
    test_encode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_request1() {
    let (ref bytes, ref auth, ref pdu) = *REQUEST1;
    test_decode_pdu(bytes, pdu, auth);
}

#[test]
fn test_encode_response1() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE1;
    test_encode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_response1() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE1;
    test_decode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_response2() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE2;
    test_decode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_response3() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE3;
    test_decode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_response4() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE4;
    test_decode_pdu(bytes, pdu, auth);
}

#[test]
fn test_encode_response5() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE5;
    test_encode_pdu(bytes, pdu, auth);
}

#[test]
fn test_decode_response5() {
    let (ref bytes, ref auth, ref pdu) = *RESPONSE5;
    test_decode_pdu(bytes, pdu, auth);
}
