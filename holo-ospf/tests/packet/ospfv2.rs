//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock as Lazy};

use bytes::Bytes;
use holo_ospf::ospfv2::packet::lsa::*;
use holo_ospf::ospfv2::packet::lsa_opaque::*;
use holo_ospf::ospfv2::packet::*;
use holo_ospf::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use holo_ospf::packet::lsa::{Lsa, LsaKey};
use holo_ospf::packet::tlv::*;
use holo_ospf::packet::{DbDescFlags, Packet, PacketType};
use holo_ospf::version::Ospfv2;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::AddressFamily;
use holo_utils::keychain::Key;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use ipnetwork::Ipv4Network;
use maplit::{btreemap, btreeset};

const SRC_ADDR: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

//
// Helper functions.
//

fn test_encode_packet(
    bytes_expected: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet: &Packet<Ospfv2>,
) {
    // Prepare authentication context.
    let mut auth = None;
    let auth_seqno;
    if let Some((auth_key, seqno)) = auth_data {
        auth_seqno = Arc::new(AtomicU64::new(*seqno));
        auth = Some(AuthEncodeCtx::new(auth_key, &auth_seqno, SRC_ADDR.into()));
    }

    // Encode the packet.
    let bytes_actual = packet.encode(auth);
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_packet(
    bytes: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet_expected: &Packet<Ospfv2>,
) {
    // Prepare authentication context.
    let mut auth = None;
    let auth_method;
    if let Some((auth_key, _)) = auth_data {
        auth_method = AuthMethod::ManualKey(auth_key.clone());
        auth = Some(AuthDecodeCtx::new(&auth_method, SRC_ADDR.into()));
    };

    // Encode the packet.
    let mut buf = Bytes::copy_from_slice(bytes);
    let packet_actual =
        Packet::decode(AddressFamily::Ipv4, &mut buf, auth).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_lsa(bytes_expected: &[u8], lsa: &Lsa<Ospfv2>) {
    assert_eq!(bytes_expected, lsa.raw.as_ref());
}

fn test_decode_lsa(bytes: &[u8], lsa_expected: &Lsa<Ospfv2>) {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let lsa_actual = Lsa::decode(AddressFamily::Ipv4, &mut bytes).unwrap();
    assert_eq!(*lsa_expected, lsa_actual);
}

//
// Test packets.
//

static HELLO1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x30, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0xf6, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
                    auth_seqno: None,
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [Ipv4Addr::from_str("1.1.1.1").unwrap()].into(),
            }),
        )
    });

static HELLO1_MD5: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x10,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0x9d, 0xd5, 0xa8, 0x03, 0x86, 0xee, 0x71, 0x67,
                0x44, 0x1a, 0x37, 0xa9, 0x04, 0x27, 0xfc, 0xc7,
            ],
            Some((
                Key::new(1, CryptoAlgo::Md5, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    auth_seqno: Some(843436052),
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(Ipv4Addr::from_str("10.0.1.3").unwrap().into()),
                bdr: Some(Ipv4Addr::from_str("10.0.1.2").unwrap().into()),
                neighbors: [
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("3.3.3.3").unwrap(),
                ]
                .into(),
            }),
        )
    });

static HELLO1_HMAC_SHA1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x14,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0x8a, 0xbd, 0xb5, 0x24, 0x96, 0x63, 0xe6, 0xcc,
                0x4e, 0x11, 0xac, 0xdc, 0x37, 0x83, 0x8c, 0xc9, 0xf5, 0xc0,
                0x8d, 0xcd,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    auth_seqno: Some(843436052),
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(Ipv4Addr::from_str("10.0.1.3").unwrap().into()),
                bdr: Some(Ipv4Addr::from_str("10.0.1.2").unwrap().into()),
                neighbors: [
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("3.3.3.3").unwrap(),
                ]
                .into(),
            }),
        )
    });

static HELLO1_HMAC_SHA256: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x20,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0x26, 0x39, 0xac, 0x92, 0xa3, 0xcc, 0x7e, 0x92,
                0xe1, 0x25, 0x3a, 0xa2, 0x59, 0xc9, 0xb5, 0x72, 0xbf, 0xc2,
                0x8f, 0x05, 0x36, 0xa2, 0xcb, 0x0a, 0x4b, 0x46, 0x66, 0x6a,
                0x69, 0x62, 0x6f, 0x04,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    auth_seqno: Some(843436052),
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(Ipv4Addr::from_str("10.0.1.3").unwrap().into()),
                bdr: Some(Ipv4Addr::from_str("10.0.1.2").unwrap().into()),
                neighbors: [
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("3.3.3.3").unwrap(),
                ]
                .into(),
            }),
        )
    });

static HELLO1_HMAC_SHA384: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x30,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0xbe, 0xe2, 0x9b, 0x71, 0x5a, 0x18, 0xe8, 0x37,
                0xcd, 0x06, 0x47, 0xab, 0x7c, 0x8d, 0x2e, 0x5d, 0x52, 0x75,
                0x6b, 0x3f, 0x6e, 0x1b, 0x70, 0x21, 0x22, 0x70, 0xe8, 0x22,
                0x7f, 0x3d, 0xd3, 0xd6, 0x1d, 0xfb, 0xa2, 0xec, 0x28, 0x12,
                0x72, 0x23, 0x96, 0xdc, 0xdf, 0xe4, 0xe6, 0xe5, 0x8c, 0x7a,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    auth_seqno: Some(843436052),
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(Ipv4Addr::from_str("10.0.1.3").unwrap().into()),
                bdr: Some(Ipv4Addr::from_str("10.0.1.2").unwrap().into()),
                neighbors: [
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("3.3.3.3").unwrap(),
                ]
                .into(),
            }),
        )
    });

static HELLO1_HMAC_SHA512: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x40,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x02, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0xea, 0x86, 0xf8, 0xd8, 0x7d, 0xd2, 0x4f, 0xc3,
                0x29, 0x15, 0x9e, 0x5c, 0x54, 0x71, 0x1d, 0xbe, 0x77, 0xf2,
                0x3a, 0x1b, 0x94, 0x23, 0xb8, 0xd7, 0x11, 0x8c, 0x78, 0x39,
                0x08, 0x9d, 0xc6, 0x3a, 0xbf, 0x7a, 0x63, 0xb2, 0xea, 0x60,
                0xd3, 0xbc, 0x19, 0x5b, 0xf5, 0x58, 0xa0, 0x89, 0x01, 0xae,
                0xb5, 0x6c, 0xbd, 0x1e, 0x2c, 0x7f, 0xdb, 0x03, 0x28, 0x97,
                0xf7, 0xbc, 0x92, 0xe3, 0x56, 0xc7,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    auth_seqno: Some(843436052),
                },
                network_mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(Ipv4Addr::from_str("10.0.1.3").unwrap().into()),
                bdr: Some(Ipv4Addr::from_str("10.0.1.2").unwrap().into()),
                neighbors: [
                    Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    Ipv4Addr::from_str("3.3.3.3").unwrap(),
                ]
                .into(),
            }),
        )
    });

static DBDESC1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x02, 0x00, 0x48, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0xd8, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x42, 0x00, 0x4e, 0xb8,
                0x8f, 0x2e, 0x00, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x02, 0x48, 0xd6,
                0x00, 0x30, 0x00, 0x03, 0x02, 0x05, 0xac, 0x10, 0x01, 0x00,
                0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xfc, 0xff,
                0x00, 0x24,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
                    auth_seqno: None,
                },
                mtu: 1500,
                options: Options::E | Options::O,
                dd_flags: DbDescFlags::empty(),
                dd_seq_no: 1320718126,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 3,
                        options: Options::E,
                        lsa_type: LsaTypeCode::Router.into(),
                        lsa_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        seq_no: 0x80000002,
                        cksum: 0x48d6,
                        length: 48,
                    },
                    LsaHdr {
                        age: 3,
                        options: Options::E,
                        lsa_type: LsaTypeCode::AsExternal.into(),
                        lsa_id: Ipv4Addr::from_str("172.16.1.0").unwrap(),
                        adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        seq_no: 0x80000001,
                        cksum: 0xfcff,
                        length: 36,
                    },
                ],
            }),
        )
    });

static LSREQUEST1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x03, 0x00, 0x30, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x46, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x05,
                0xac, 0x10, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01,
            ],
            None,
            Packet::LsRequest(LsRequest {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsRequest,
                    router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
                    auth_seqno: None,
                },
                entries: vec![
                    LsaKey {
                        lsa_type: LsaTypeCode::Router.into(),
                        adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        lsa_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    },
                    LsaKey {
                        lsa_type: LsaTypeCode::AsExternal.into(),
                        adv_rtr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        lsa_id: Ipv4Addr::from_str("172.16.1.0").unwrap(),
                    },
                ],
            }),
        )
    });

static LSUPDATE1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x04, 0x00, 0x78, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x40, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x31,
                0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x02, 0x37, 0xf4, 0x00, 0x24, 0x01, 0x00,
                0x00, 0x01, 0x0a, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00,
                0x03, 0x00, 0x00, 0x0a, 0x00, 0x31, 0x02, 0x03, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0xd2, 0x7a, 0x00, 0x1c, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x31, 0x02, 0x03, 0x0a, 0x00, 0x02, 0x00,
                0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0xfa, 0x44,
                0x00, 0x1c, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0a,
            ],
            None,
            Packet::LsUpdate(LsUpdate {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsUpdate,
                    router_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
                    auth_seqno: None,
                },
                lsas: vec![
                    Lsa::new(
                        49,
                        Some(Options::E),
                        Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        0x80000002,
                        LsaBody::Router(LsaRouter {
                            flags: LsaRouterFlags::B,
                            links: vec![LsaRouterLink {
                                link_type: LsaRouterLinkType::StubNetwork,
                                link_id: Ipv4Addr::from_str("10.0.1.0")
                                    .unwrap(),
                                link_data: Ipv4Addr::from_str("255.255.255.0")
                                    .unwrap(),
                                metric: 10,
                            }],
                        }),
                    ),
                    Lsa::new(
                        49,
                        Some(Options::E),
                        Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        0x80000001,
                        LsaBody::SummaryNetwork(LsaSummary {
                            mask: Ipv4Addr::from_str("255.255.255.255")
                                .unwrap(),
                            metric: 0,
                        }),
                    ),
                    Lsa::new(
                        49,
                        Some(Options::E),
                        Ipv4Addr::from_str("10.0.2.0").unwrap(),
                        Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        0x80000001,
                        LsaBody::SummaryNetwork(LsaSummary {
                            mask: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                            metric: 10,
                        }),
                    ),
                ],
            }),
        )
    });

static LSACK1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x05, 0x00, 0x54, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0xa0, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0x09, 0x36, 0x00, 0x1c, 0x00, 0x01, 0x02, 0x03, 0x0a, 0x00,
                0x03, 0x00, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0x54, 0xdf, 0x00, 0x1c, 0x00, 0x01, 0x02, 0x03, 0x0a, 0x00,
                0x04, 0x00, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0x49, 0xe9, 0x00, 0x1c,
            ],
            None,
            Packet::LsAck(LsAck {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsAck,
                    router_id: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    area_id: Ipv4Addr::from_str("0.0.0.1").unwrap(),
                    auth_seqno: None,
                },
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: Ipv4Addr::from_str("3.3.3.3").unwrap(),
                        adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        seq_no: 0x80000001,
                        cksum: 0x0936,
                        length: 28,
                    },
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: Ipv4Addr::from_str("10.0.3.0").unwrap(),
                        adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        seq_no: 0x80000001,
                        cksum: 0x54df,
                        length: 28,
                    },
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: Ipv4Addr::from_str("10.0.4.0").unwrap(),
                        adv_rtr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        seq_no: 0x80000001,
                        cksum: 0x49e9,
                        length: 28,
                    },
                ],
            }),
        )
    });

//
// Test LSAs.
//

static LSA1: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x31, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x02, 0x37, 0xf4, 0x00, 0x24, 0x01, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03,
            0x00, 0x00, 0x0a,
        ],
        Lsa::new(
            49,
            Some(Options::E),
            Ipv4Addr::from_str("2.2.2.2").unwrap(),
            Ipv4Addr::from_str("2.2.2.2").unwrap(),
            0x80000002,
            LsaBody::Router(LsaRouter {
                flags: LsaRouterFlags::B,
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::StubNetwork,
                    link_id: Ipv4Addr::from_str("10.0.1.0").unwrap(),
                    link_data: Ipv4Addr::from_str("255.255.255.0").unwrap(),
                    metric: 10,
                }],
            }),
        ),
    )
});

static LSA2: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0x20, 0x95, 0x00, 0x44, 0x00, 0x01,
            0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x1f, 0x40, 0x00,
            0x00, 0x01, 0x00, 0x03, 0x00, 0x3e, 0x80, 0x00, 0x00, 0x0e, 0x00,
            0x0b, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x3a,
            0x98, 0x00,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            OpaqueLsaId::new(LsaOpaqueType::RouterInfo as u8, 0).into(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::RouterInfo(LsaRouterInfo {
                info_caps: Some(RouterInfoCaps::TE.into()),
                func_caps: None,
                sr_algo: Some(SrAlgoTlv::new(btreeset!(IgpAlgoType::Spf))),
                srgb: vec![SidLabelRangeTlv::new(
                    Sid::Label(Label::new(16000)),
                    8000,
                )],
                srlb: vec![SrLocalBlockTlv::new(
                    Sid::Label(Label::new(15000)),
                    1000,
                )],
                msds: None,
                srms_pref: None,
                info_hostname: Some(DynamicHostnameTlv::new("holo".to_owned())),
                unknown_tlvs: vec![],
            })),
        ),
    )
});

static LSA3: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xda, 0x91, 0x00, 0x2c, 0x00, 0x01,
            0x00, 0x14, 0x01, 0x20, 0x00, 0x40, 0x01, 0x01, 0x01, 0x01, 0x00,
            0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            Ipv4Addr::from_str("7.0.0.0").unwrap(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtPrefix(LsaExtPrefix {
                prefixes: btreemap! {
                    Ipv4Network::from_str("1.1.1.1/32").unwrap() => {
                        ExtPrefixTlv {
                            route_type: ExtPrefixRouteType::IntraArea,
                            af: 0,
                            flags: LsaExtPrefixFlags::N,
                            prefix: Ipv4Network::from_str("1.1.1.1/32").unwrap(),
                            prefix_sids: btreemap! {
                                IgpAlgoType::Spf => {
                                    PrefixSid {
                                        flags: PrefixSidFlags::empty(),
                                        algo: IgpAlgoType::Spf,
                                        sid: Sid::Index(10),
                                    }
                                }
                            },
                            unknown_tlvs: vec![],
                        }
                    },
                },
            })),
        ),
    )
});

static LSA4: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x0a, 0x08, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xe3, 0xca, 0x00, 0x30, 0x00, 0x01,
            0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x0a,
            0x00, 0x01, 0x01, 0x00, 0x02, 0x00, 0x07, 0x60, 0x00, 0x00, 0x00,
            0x00, 0x0f, 0xa0, 0x00,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            Ipv4Addr::from_str("8.0.0.0").unwrap(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtLink(LsaExtLink {
                link: Some(ExtLinkTlv {
                    link_type: LsaRouterLinkType::PointToPoint,
                    link_id: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    link_data: Ipv4Addr::from_str("10.0.1.1").unwrap(),
                    adj_sids: vec![AdjSid {
                        flags: AdjSidFlags::V | AdjSidFlags::L,
                        weight: 0,
                        nbr_router_id: None,
                        sid: Sid::Label(Label::new(4000)),
                    }],
                    msds: Default::default(),
                    unknown_tlvs: vec![],
                }),
            })),
        ),
    )
});

static GRACE_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv2>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0x42, 0x09, 0x03, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x01, 0x7e, 0xf4, 0x00, 0x24, 0x00, 0x01,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
        ],
        Lsa::new(
            1,
            Some(Options::O | Options::E),
            Ipv4Addr::from_str("3.0.0.0").unwrap(),
            Ipv4Addr::from_str("6.6.6.6").unwrap(),
            0x80000001,
            LsaBody::OpaqueLink(LsaOpaque::Grace(LsaGrace {
                grace_period: Some(GracePeriodTlv::new(120)),
                gr_reason: Some(GrReasonTlv::new(0)),
                addr: None,
                unknown_tlvs: vec![],
            })),
        ),
    )
});

//
// Tests.
//

#[test]
fn test_encode_hello1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_hello_md5() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_MD5;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_md5() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_MD5;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_decode_packet(bytes, auth, hello);
}

#[test]
fn test_encode_dbdesc1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESC1;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdesc1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESC1;
    test_decode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_encode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_encode_packet(bytes, auth, request);
}

#[test]
fn test_decode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_decode_packet(bytes, auth, request);
}

#[test]
fn test_encode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_encode_packet(bytes, auth, lsupdate);
}

#[test]
fn test_decode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_decode_packet(bytes, auth, lsupdate);
}

#[test]
fn test_encode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_encode_packet(bytes, auth, lsack);
}

#[test]
fn test_decode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_decode_packet(bytes, auth, lsack);
}

#[test]
fn test_encode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_lsa4() {
    let (ref bytes, ref lsa) = *LSA4;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa4() {
    let (ref bytes, ref lsa) = *LSA4;
    test_decode_lsa(bytes, lsa);
}

#[test]
fn test_encode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_decode_lsa(bytes, lsa);
}
