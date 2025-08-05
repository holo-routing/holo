//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::LazyLock as Lazy;

use holo_isis::packet::pdu::{Pdu, Snp, SnpTlvs};
use holo_isis::packet::tlv::{
    ExtendedSeqNum, ExtendedSeqNumTlv, LspEntriesTlv, LspEntry,
};
use holo_isis::packet::{LanId, LevelNumber, LspId};
use holo_utils::keychain::Key;

use super::{test_decode_pdu, test_encode_pdu};

//
// Test packets.
//

static CSNP1: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x21, 0x01, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x61, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x09, 0x30, 0x04, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x47, 0x04, 0x79, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xbc,
            0x41, 0x04, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0xc0, 0x3b, 0x0b, 0x0c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x12, 0x34,
        ],
        None,
        Pdu::Snp(Snp::new(
            LevelNumber::L1,
            LanId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]),
            Some((
                LspId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                LspId::from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            )),
            SnpTlvs {
                lsp_entries: vec![LspEntriesTlv {
                    list: vec![
                        LspEntry {
                            rem_lifetime: 1145,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                            ]),
                            cksum: 0xb847,
                            seqno: 0,
                        },
                        LspEntry {
                            rem_lifetime: 1145,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
                            ]),
                            cksum: 0xbc41,
                            seqno: 2,
                        },
                        LspEntry {
                            rem_lifetime: 1162,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
                            ]),
                            cksum: 0xc03b,
                            seqno: 2,
                        },
                    ],
                }],
                ext_seqnum: Some(ExtendedSeqNumTlv::new(ExtendedSeqNum {
                    session: 0x00000001,
                    packet: 0x1234,
                })),
                unknown: vec![],
            },
        )),
    )
});

static PSNP1: Lazy<(Vec<u8>, Option<&Key>, Pdu)> = Lazy::new(|| {
    (
        vec![
            0x83, 0x11, 0x01, 0x00, 0x1a, 0x01, 0x00, 0x00, 0x00, 0x53, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x09, 0x40, 0x04, 0x8e, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xb0, 0x53, 0x04, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x01, 0xd6, 0xe4, 0x04, 0x78, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xb8,
            0x47, 0x04, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0xbc, 0x41,
        ],
        None,
        Pdu::Snp(Snp::new(
            LevelNumber::L1,
            LanId::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00]),
            None,
            SnpTlvs {
                lsp_entries: vec![LspEntriesTlv {
                    list: vec![
                        LspEntry {
                            rem_lifetime: 1166,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                            ]),
                            cksum: 0xb053,
                            seqno: 2,
                        },
                        LspEntry {
                            rem_lifetime: 1185,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00,
                            ]),
                            cksum: 0xd6e4,
                            seqno: 1,
                        },
                        LspEntry {
                            rem_lifetime: 1144,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                            ]),
                            cksum: 0xb847,
                            seqno: 2,
                        },
                        LspEntry {
                            rem_lifetime: 1144,
                            lsp_id: LspId::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
                            ]),
                            cksum: 0xbc41,
                            seqno: 2,
                        },
                    ],
                }],
                ext_seqnum: None,
                unknown: vec![],
            },
        )),
    )
});

//
// Tests.
//

#[test]
fn test_encode_csnp1() {
    let (ref bytes, ref auth, ref csnp) = *CSNP1;
    test_encode_pdu(bytes, csnp, auth);
}

#[test]
fn test_decode_csnp1() {
    let (ref bytes, ref auth, ref csnp) = *CSNP1;
    test_decode_pdu(bytes, csnp, auth);
}

#[test]
fn test_encode_psnp1() {
    let (ref bytes, ref auth, ref psnp) = *PSNP1;
    test_encode_pdu(bytes, psnp, auth);
}

#[test]
fn test_decode_psnp1() {
    let (ref bytes, ref auth, ref psnp) = *PSNP1;
    test_decode_pdu(bytes, psnp, auth);
}
