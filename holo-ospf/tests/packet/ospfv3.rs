//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv6Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock as Lazy};

use bytes::Bytes;
use const_addrs::{ip, ip4, net};
use holo_ospf::ospfv3::packet::lsa::*;
use holo_ospf::ospfv3::packet::*;
use holo_ospf::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use holo_ospf::packet::lls::{
    ExtendedOptionsFlags, ReverseMetricFlags, ReverseTeMetricFlags,
};
use holo_ospf::packet::lsa::{Lsa, LsaKey};
use holo_ospf::packet::tlv::*;
use holo_ospf::packet::{DbDescFlags, Packet, PacketType};
use holo_ospf::version::Ospfv3;
use holo_protocol::assert_eq_hex;
use holo_utils::bier::{BierEncapId, BiftId};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::AddressFamily;
use holo_utils::keychain::Key;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use maplit::{btreemap, btreeset};

const SRC_ADDR: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

//
// Helper functions.
//

fn test_encode_packet(
    bytes_expected: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet: &Packet<Ospfv3>,
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
    assert_eq_hex!(bytes_expected, bytes_actual);
}

fn test_decode_packet(
    bytes: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet_expected: &Packet<Ospfv3>,
    af: AddressFamily,
) {
    // Prepare authentication context.
    let mut auth = None;
    let auth_method;
    if let Some((auth_key, _)) = auth_data {
        auth_method = AuthMethod::ManualKey(auth_key.clone());
        auth = Some(AuthDecodeCtx::new(&auth_method, SRC_ADDR.into()));
    };

    // Decode the packet.
    let mut buf = Bytes::copy_from_slice(bytes);
    let packet_actual = Packet::decode(af, &mut buf, auth).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_lsa(bytes_expected: &[u8], lsa: &Lsa<Ospfv3>) {
    assert_eq_hex!(bytes_expected, lsa.raw);
}

fn test_decode_lsa(
    bytes: &[u8],
    lsa_expected: &Lsa<Ospfv3>,
    af: AddressFamily,
) {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let lsa_actual = Lsa::decode(af, &mut bytes).unwrap();
    assert_eq!(*lsa_expected, lsa_actual);
}

//
// Test packets.
//

static HELLO1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x02, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x50, 0xd3, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
                0x00, 0x03, 0x00, 0x13, 0x00, 0x04, 0x00, 0x01, 0x12, 0x34,
                0x00, 0x13, 0x00, 0x04, 0x01, 0x02, 0x43, 0x21, 0x00, 0x14,
                0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::L,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: Some(holo_ospf::packet::lls::LlsHelloData {
                    eof: Some(
                        ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS,
                    ),
                    reverse_metric: vec![
                        (0 as u8, (ReverseMetricFlags::H, 0x1234)),
                        (1 as u8, (ReverseMetricFlags::O, 0x4321)),
                    ]
                    .iter()
                    .map(|&entry| entry)
                    .collect(),
                    reverse_te_metric: Some((ReverseTeMetricFlags::O, 0x5678)),
                }),
            }),
        )
    });

static HELLO1_HMAC_SHA1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0x72, 0xac, 0xc6, 0xd9,
                0xaf, 0x89, 0x4a, 0x11, 0xb6, 0x43, 0xe0, 0x7c, 0x77, 0xce,
                0x6b, 0xf9, 0x9a, 0xd1, 0x4f, 0x4b,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA1_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
            0x04, 0x00, 0x01, 0x12, 0x34, 0x00, 0x13, 0x00, 0x04, 0x01, 0x02,
            0x43, 0x21, 0x00, 0x14, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x56, 0x78,
            // 0x00, 0x00, 0x00, 0x03,
            // 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
            // 0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            // 0x00, 0x32, 0x45, 0xd0, 0x14, 0xfe, 0xef, 0xc6, 0xce, 0x7d, 0xbe,
            // 0x66, 0x4e, 0xc3, 0x92, 0x0c, 0xc9, 0x2f, 0x6d, 0x42, 0x1f, 0x38,
            // 0xb2, 0xd2, 0x3c,
            0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x32, 0x45, 0xd0, 0x14, 0x76, 0x0c, 0xf8, 0xe7, 0x32, 0xfd,
            0x4f, 0x95, 0x30, 0x97, 0xa1, 0x4e, 0xd0, 0x2b, 0x5d, 0x10, 0x7c,
            0x93, 0x8f, 0xe2,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                reverse_metric: vec![
                    (0 as u8, (ReverseMetricFlags::H, 0x1234)),
                    (1 as u8, (ReverseMetricFlags::O, 0x4321)),
                ]
                .iter()
                .map(|&entry| entry)
                .collect(),
                reverse_te_metric: Some((ReverseTeMetricFlags::O, 0x5678)),
            }),
        }),
    )
});

static HELLO1_HMAC_SHA256: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xda, 0xbc, 0x49, 0xc0,
                0x9b, 0xc2, 0x3c, 0x5d, 0x58, 0x19, 0xe1, 0x1f, 0xa0, 0xa3,
                0xef, 0x4b, 0xd0, 0xf4, 0xb4, 0xe2, 0x51, 0xea, 0xee, 0xe8,
                0x78, 0x1b, 0x72, 0xd2, 0xa9, 0x9f, 0x0f, 0x91,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA256_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
            0x04, 0x00, 0x01, 0x12, 0x34, 0x00, 0x13, 0x00, 0x04, 0x01, 0x02,
            0x43, 0x21, 0x00, 0x14, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x56, 0x78, 0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0x6e, 0x98, 0x69,
            0xad, 0x05, 0x4c, 0x78, 0x40, 0x17, 0xab, 0xc4, 0x2d, 0x18, 0xca,
            0xe3, 0xb7, 0x3c, 0x2d, 0x38, 0x17, 0xdd, 0xb7, 0x53, 0x3d, 0xe2,
            0x89, 0x4e, 0x79, 0x65, 0x43, 0x56, 0xbd,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                reverse_metric: vec![
                    (0 as u8, (ReverseMetricFlags::H, 0x1234)),
                    (1 as u8, (ReverseMetricFlags::O, 0x4321)),
                ]
                .iter()
                .map(|&entry| entry)
                .collect(),
                reverse_te_metric: Some((ReverseTeMetricFlags::O, 0x5678)),
            }),
        }),
    )
});

static HELLO1_HMAC_SHA384: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xa6, 0x5c, 0xb4, 0x0d,
                0x57, 0x94, 0x5f, 0x3d, 0xad, 0xba, 0x91, 0x4c, 0x52, 0xf1,
                0xc3, 0x6d, 0xeb, 0x5d, 0xa4, 0x49, 0xde, 0x08, 0xa2, 0x75,
                0x5f, 0x23, 0x13, 0x4d, 0x58, 0xf5, 0x29, 0xcf, 0x3a, 0x1c,
                0xa7, 0x87, 0x1c, 0x2f, 0xa7, 0xcc, 0xa8, 0xf1, 0xbd, 0xab,
                0x21, 0x76, 0xa2, 0x65,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA384_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
            0x04, 0x00, 0x01, 0x12, 0x34, 0x00, 0x13, 0x00, 0x04, 0x01, 0x02,
            0x43, 0x21, 0x00, 0x14, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x56, 0x78, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xf3, 0x68, 0x6f,
            0x8a, 0x4e, 0x5b, 0xff, 0xef, 0xd9, 0x05, 0xa1, 0x1d, 0xe9, 0x43,
            0xba, 0x7f, 0x00, 0xff, 0x0c, 0xc2, 0x37, 0x41, 0xc2, 0xfc, 0xa9,
            0xdf, 0xc3, 0x28, 0x6c, 0xbe, 0x89, 0xd9, 0x73, 0xc7, 0x39, 0xf5,
            0x5e, 0x18, 0x9d, 0x18, 0x04, 0xe2, 0xbd, 0x5c, 0xca, 0xd4, 0x3c,
            0xa4,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                reverse_metric: vec![
                    (0 as u8, (ReverseMetricFlags::H, 0x1234)),
                    (1 as u8, (ReverseMetricFlags::O, 0x4321)),
                ]
                .iter()
                .map(|&entry| entry)
                .collect(),
                reverse_te_metric: Some((ReverseTeMetricFlags::O, 0x5678)),
            }),
        }),
    )
});

static HELLO1_HMAC_SHA512: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xae, 0x30, 0x68, 0x54,
                0xbc, 0xd2, 0x7f, 0x76, 0x66, 0x64, 0x6b, 0x6f, 0xb0, 0x15,
                0xf6, 0x42, 0x8d, 0xbd, 0x4e, 0xd7, 0xae, 0x9b, 0x3d, 0xd1,
                0xbc, 0xa2, 0x7d, 0xb6, 0xf8, 0x14, 0xb5, 0xbe, 0xde, 0xb8,
                0x4b, 0x9d, 0x61, 0x76, 0x33, 0xef, 0x55, 0x63, 0x0b, 0x61,
                0x3a, 0x2f, 0x49, 0x7e, 0xe7, 0x08, 0x70, 0xd0, 0x6e, 0xc6,
                0x2c, 0xab, 0xab, 0x92, 0x99, 0x2d, 0xae, 0xec, 0x0c, 0xf7,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA512_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x13, 0x00,
            0x04, 0x00, 0x01, 0x12, 0x34, 0x00, 0x13, 0x00, 0x04, 0x01, 0x02,
            0x43, 0x21, 0x00, 0x14, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x56, 0x78, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0x6c, 0xeb, 0xd1,
            0x49, 0x97, 0xb9, 0x46, 0x03, 0x52, 0x41, 0x96, 0x3a, 0xc1, 0xa6,
            0x9c, 0xdc, 0x6d, 0xe8, 0x1b, 0xc4, 0x35, 0x53, 0xd9, 0xcf, 0xda,
            0xa6, 0x15, 0x8e, 0x9f, 0x7a, 0x40, 0xda, 0x1f, 0x2e, 0x61, 0x24,
            0x6a, 0xb0, 0x6d, 0x33, 0xe1, 0x49, 0xb9, 0x01, 0x21, 0xa9, 0x64,
            0x17, 0xd9, 0x14, 0x28, 0xdd, 0x83, 0x35, 0xdb, 0x43, 0xf3, 0x0c,
            0xa9, 0x10, 0x43, 0xf9, 0x01, 0x86,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                reverse_metric: vec![
                    (0 as u8, (ReverseMetricFlags::H, 0x1234)),
                    (1 as u8, (ReverseMetricFlags::O, 0x4321)),
                ]
                .iter()
                .map(|&entry| entry)
                .collect(),
                reverse_te_metric: Some((ReverseTeMetricFlags::O, 0x5678)),
            }),
        }),
    )
});

static DBDESCR1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x1c, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
                0x05, 0xdc, 0x00, 0x07, 0x00, 0x01, 0x6f, 0x10,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6,
                mtu: 1500,
                dd_flags: DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                dd_seq_no: 93968,
                lsa_hdrs: vec![],
                lls: None,
            }),
        )
    });

static DBDESCR1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x1c, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13,
                0x05, 0xdc, 0x00, 0x07, 0x00, 0x01, 0x6f, 0x10, 0xff, 0xf6,
                0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6 | Options::L,
                mtu: 1500,
                dd_flags: DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                dd_seq_no: 93968,
                lsa_hdrs: vec![],
                lls: Some(holo_ospf::packet::lls::LlsDbDescData {
                    eof: Some(ExtendedOptionsFlags::LR),
                }),
            }),
        )
    });

static DBDESCR2: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x58, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
                0x05, 0xdc, 0x00, 0x01, 0x00, 0x01, 0x6f, 0x11, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x00, 0x04,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0xf4, 0x34, 0x00, 0x18, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6,
                mtu: 1500,
                dd_flags: DbDescFlags::MS,
                dd_seq_no: 93969,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.3"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x163a,
                        length: 44,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0xf434,
                        length: 24,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2003),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x970b,
                        length: 44,
                    },
                ],
                lls: None,
            }),
        )
    });

static DBDESCR2_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x58, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13,
                0x05, 0xdc, 0x00, 0x01, 0x00, 0x01, 0x6f, 0x11, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x00, 0x04,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0xf4, 0x34, 0x00, 0x18, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c, 0xff, 0xf6,
                0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6 | Options::L,
                mtu: 1500,
                dd_flags: DbDescFlags::MS,
                dd_seq_no: 93969,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.3"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x163a,
                        length: 44,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0xf434,
                        length: 24,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2003),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x970b,
                        length: 44,
                    },
                ],
                lls: Some(holo_ospf::packet::lls::LlsDbDescData {
                    eof: Some(ExtendedOptionsFlags::LR),
                }),
            }),
        )
    });

static LSREQUEST1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x03, 0x00, 0x40, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
                0x00, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
                0x01, 0x01, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00, 0x00, 0x01,
                0x01, 0x01, 0x01, 0x01,
            ],
            None,
            Packet::LsRequest(LsRequest {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsRequest,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                entries: vec![
                    LsaKey {
                        lsa_type: LsaType(0x0008),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.4"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x2001),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.0"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x2009),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.0"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x4005),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.1"),
                    },
                ],
            }),
        )
    });

static LSUPDATE1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x04, 0x00, 0x84, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02,
                0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c,
                0x01, 0x00, 0x00, 0x13, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xcc, 0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x20, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0xf4, 0x34, 0x00, 0x18, 0x01, 0x00, 0x00, 0x13, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c, 0x00, 0x00,
                0x00, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
            None,
            Packet::LsUpdate(LsUpdate {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsUpdate,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                lsas: vec![
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.3"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::Link(LsaLink {
                            extended: false,
                            priority: 1,
                            options: Options::R | Options::E | Options::V6,
                            linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                            prefixes: vec![],
                            unknown_tlvs: vec![],
                        }),
                    ),
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.0"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::Router(LsaRouter {
                            extended: false,
                            flags: LsaRouterFlags::B,
                            options: Options::R | Options::E | Options::V6,
                            links: vec![],
                            unknown_tlvs: vec![],
                        }),
                    ),
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.1"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::InterAreaPrefix(LsaInterAreaPrefix {
                            extended: false,
                            metric: 10,
                            prefix_options: PrefixOptions::empty(),
                            prefix: net!("2001:db8:1000::2/128"),
                            prefix_sids: Default::default(),
                            unknown_tlvs: vec![],
                            unknown_stlvs: vec![],
                        }),
                    ),
                ],
            }),
        )
    });

static LSACK1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x05, 0x00, 0x60, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x77, 0x58, 0x00, 0x2c, 0x00, 0x08, 0x20, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x16, 0x16, 0x00, 0x18, 0x00, 0x08, 0x20, 0x09,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x7a, 0xf9, 0x00, 0x34, 0x00, 0x08, 0x40, 0x05,
                0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0xe5, 0x91, 0x00, 0x2c,
            ],
            None,
            Packet::LsAck(LsAck {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsAck,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 7,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.4"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x7758,
                        length: 44,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x1616,
                        length: 24,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x2009),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x7af9,
                        length: 52,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x4005),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0xe591,
                        length: 44,
                    },
                ],
            }),
        )
    });

//
// Test LSAs.
//

static LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x01, 0x00,
            0x00, 0x13, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc,
            0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0, 0x00, 0x00, 0x00, 0x00,
        ],
        Lsa::new(
            4,
            None,
            ip4!("0.0.0.3"),
            ip4!("2.2.2.2"),
            0x80000001,
            LsaBody::Link(LsaLink {
                extended: false,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                prefixes: vec![],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static LSA2: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x0a, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x03, 0xe0, 0xed, 0x00, 0x28, 0x00, 0x01,
            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x20,
            0x02, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
        ],
        Lsa::new(
            10,
            None,
            ip4!("0.0.0.0"),
            ip4!("2.2.2.2"),
            0x80000003,
            LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                extended: false,
                ref_lsa_type: LsaType(8193),
                ref_lsa_id: ip4!("0.0.0.0"),
                ref_adv_rtr: ip4!("2.2.2.2"),
                prefixes: vec![LsaIntraAreaPrefixEntry {
                    options: PrefixOptions::LA,
                    value: net!("2.2.2.2/32"),
                    metric: 0,
                    prefix_sids: Default::default(),
                    bier: vec![],
                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static LSA3: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0xa0, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xab, 0xc4, 0x00, 0x6c, 0x00, 0x01,
            0x00, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0x68,
            0x6f, 0x6c, 0x6f, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00,
            0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x0b, 0x00, 0x1f, 0x40, 0x00, 0x00, 0x01, 0x00, 0x03,
            0x00, 0x3e, 0x80, 0x00, 0x00, 0x0e, 0x00, 0x0b, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x3a, 0x98, 0x00,
        ],
        Lsa::new(
            1,
            None,
            ip4!("0.0.0.0"),
            ip4!("1.1.1.1"),
            0x80000001,
            LsaBody::RouterInfo(LsaRouterInfo {
                scope: LsaScopeCode::Area,
                info_caps: Some(
                    (RouterInfoCaps::GR
                        | RouterInfoCaps::GR_HELPER
                        | RouterInfoCaps::TE)
                        .into(),
                ),
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
                msds: Default::default(),
                srms_pref: None,
                info_hostname: Some(DynamicHostnameTlv::new("holo".to_owned())),
                node_tags: vec![
                    NodeAdminTagTlv::new([1, 2, 3].into()),
                    NodeAdminTagTlv::new([4, 5, 6].into()),
                ],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_ROUTER_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x06, 0xa0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x02, 0x95, 0x65, 0x00, 0x38, 0x01, 0x00,
            0x01, 0x13, 0x00, 0x01, 0x00, 0x1c, 0x01, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x03, 0x03, 0x03, 0x03,
            0x00, 0x05, 0x00, 0x07, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa0,
            0x00,
        ],
        Lsa::new(
            6,
            None,
            ip4!("0.0.0.0"),
            ip4!("6.6.6.6"),
            2147483650,
            LsaBody::Router(LsaRouter {
                extended: true,
                flags: LsaRouterFlags::B,
                options: Options::R | Options::E | Options::V6 | Options::AF,
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::PointToPoint,
                    metric: 10,
                    iface_id: 5,
                    nbr_iface_id: 6,
                    nbr_router_id: ip4!("3.3.3.3"),
                    adj_sids: vec![AdjSid {
                        flags: AdjSidFlags::V | AdjSidFlags::L,
                        weight: 0,
                        nbr_router_id: None,
                        sid: Sid::Label(Label::new(4000)),
                    }],

                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_NETWORK_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x00, 0xa0, 0x22, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x80, 0x00, 0x00, 0x01, 0x07, 0x4f, 0x00, 0x24, 0x00, 0x00,
            0x01, 0x13, 0x00, 0x02, 0x00, 0x08, 0x02, 0x02, 0x02, 0x02, 0x03,
            0x03, 0x03, 0x03,
        ],
        Lsa::new(
            0,
            None,
            ip4!("0.0.0.3"),
            ip4!("3.3.3.3"),
            2147483649,
            LsaBody::Network(LsaNetwork {
                extended: true,
                options: Options::R | Options::E | Options::V6 | Options::AF,
                attached_rtrs: btreeset![ip4!("2.2.2.2"), ip4!("3.3.3.3"),],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_INTER_AREA_PREFIX_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x01, 0xa0, 0x23, 0x00, 0x00, 0x00, 0x02, 0x06, 0x06,
                0x06, 0x06, 0x80, 0x00, 0x00, 0x01, 0x2d, 0x9d, 0x00, 0x30,
                0x00, 0x03, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02,
                0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            ],
            Lsa::new(
                1,
                None,
                ip4!("0.0.0.2"),
                ip4!("6.6.6.6"),
                2147483649,
                LsaBody::InterAreaPrefix(LsaInterAreaPrefix {
                    extended: true,
                    metric: 10,
                    prefix_options: PrefixOptions::LA,
                    prefix: net!("2001:db8:1000::7/128"),
                    prefix_sids: Default::default(),
                    unknown_tlvs: vec![],
                    unknown_stlvs: vec![],
                }),
            ),
        )
    });

static EXT_INTER_AREA_ROUTER_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x0d, 0xa0, 0x24, 0x00, 0x00, 0x00, 0x01, 0x06, 0x06,
                0x06, 0x06, 0x80, 0x00, 0x00, 0x02, 0x5e, 0xce, 0x00, 0x24,
                0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x13, 0x00, 0x00,
                0x00, 0x0a, 0x08, 0x08, 0x08, 0x08,
            ],
            Lsa::new(
                13,
                None,
                ip4!("0.0.0.1"),
                ip4!("6.6.6.6"),
                2147483650,
                LsaBody::InterAreaRouter(LsaInterAreaRouter {
                    extended: true,
                    options: Options::R
                        | Options::E
                        | Options::V6
                        | Options::AF,
                    metric: 10,
                    router_id: ip4!("8.8.8.8"),
                    unknown_tlvs: vec![],
                    unknown_stlvs: vec![],
                }),
            ),
        )
    });

static EXT_AS_EXTERNAL_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0xc0, 0x25, 0x00, 0x00, 0x00, 0x02, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x01, 0x4e, 0x6b, 0x00, 0x4c, 0x00, 0x05,
            0x00, 0x34, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x20,
            0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x30, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64,
        ],
        Lsa::new(
            1,
            None,
            ip4!("0.0.0.2"),
            ip4!("6.6.6.6"),
            2147483649,
            LsaBody::AsExternal(LsaAsExternal {
                extended: true,
                flags: LsaAsExternalFlags::empty(),
                metric: 10,
                prefix_options: PrefixOptions::empty(),
                prefix: net!("2001:db8:1000::10/128"),
                fwd_addr: Some(ip!("3000::1")),
                tag: Some(100),
                ref_lsa_type: None,
                ref_lsa_id: None,
                prefix_sids: Default::default(),
                unknown_tlvs: vec![],
                unknown_stlvs: vec![],
            }),
        ),
    )
});

static EXT_LINK_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x0a, 0x80, 0x28, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x03, 0x45, 0x03, 0x00, 0x40, 0x01, 0x00,
            0x00, 0x13, 0x00, 0x07, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xcc, 0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0,
            0x00, 0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        ],
        Lsa::new(
            10,
            None,
            ip4!("0.0.0.3"),
            ip4!("1.1.1.1"),
            0x80000003,
            LsaBody::Link(LsaLink {
                extended: true,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                prefixes: vec![LsaLinkPrefix {
                    options: PrefixOptions::empty(),
                    value: net!("2001:db8:1::/64"),
                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_INTRA_AREA_PREFIX_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x0a, 0xa0, 0x29, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
                0x02, 0x02, 0x80, 0x00, 0x00, 0x03, 0xfb, 0xe0, 0x00, 0x3c,
                0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
                0x02, 0x02, 0x00, 0x06, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x02, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
            ],
            Lsa::new(
                10,
                None,
                ip4!("0.0.0.0"),
                ip4!("2.2.2.2"),
                0x80000003,
                LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                    extended: true,
                    ref_lsa_type: LsaType(8193),
                    ref_lsa_id: ip4!("0.0.0.0"),
                    ref_adv_rtr: ip4!("2.2.2.2"),
                    prefixes: vec![LsaIntraAreaPrefixEntry {
                        options: PrefixOptions::LA,
                        value: net!("2.2.2.2/32"),
                        metric: 0,
                        prefix_sids: btreemap! {
                            IgpAlgoType::Spf => {
                                PrefixSid {
                                    flags: PrefixSidFlags::empty(),
                                    algo: IgpAlgoType::Spf,
                                    sid: Sid::Index(20),
                                }
                            }
                        },
                        bier: vec![],
                        unknown_stlvs: vec![],
                    }],
                    unknown_tlvs: vec![],
                }),
            ),
        )
    });

static EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x01, 0xa0, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x80, 0x00, 0x00, 0x01, 0x93, 0x0d, 0x00, 0x54,
                0x00, 0x00, 0xa0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x06, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                0x80, 0x22, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x2a, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x2a, 0x00, 0x08, 0x80, 0x00, 0x00, 0x00,
                0x30, 0x00, 0x00, 0x00,
            ],
            Lsa::new(
                1,
                None,
                ip4!("0.0.0.0"),
                ip4!("0.0.0.2"),
                0x80000001,
                LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                    extended: true,
                    ref_lsa_type: LsaType(40993),
                    ref_lsa_id: ip4!("0.0.0.0"),
                    ref_adv_rtr: ip4!("0.0.0.2"),
                    prefixes: vec![LsaIntraAreaPrefixEntry {
                        options: PrefixOptions::LA | PrefixOptions::N,
                        value: net!("fc00::1/128"),
                        metric: 0,
                        prefix_sids: btreemap![],
                        bier: vec![BierStlv {
                            sub_domain_id: 0,
                            mt_id: 0,
                            bfr_id: 2,
                            bar: 0,
                            ipa: 0,
                            encaps: vec![BierEncapSubStlv {
                                max_si: 128,
                                id: BierEncapId::NonMpls(BiftId::new(0)),
                                bs_len: 3,
                            }],
                            unknown_sstlvs: vec![],
                        }],
                        unknown_stlvs: vec![],
                    }],
                    unknown_tlvs: vec![],
                }),
            ),
        )
    });

static GRACE_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x05, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x01, 0x39, 0x78, 0x00, 0x24, 0x00, 0x01,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
        ],
        Lsa::new(
            0,
            None,
            ip4!("0.0.0.5"),
            ip4!("6.6.6.6"),
            0x80000001,
            LsaBody::Grace(LsaGrace {
                grace_period: Some(GracePeriodTlv::new(120)),
                gr_reason: Some(GrReasonTlv::new(0)),
                unknown_tlvs: vec![],
            }),
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
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1_LLS;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1_LLS;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr2() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr2() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr2_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2_LLS;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr2_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2_LLS;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_encode_packet(bytes, auth, request);
}

#[test]
fn test_decode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_decode_packet(bytes, auth, request, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_encode_packet(bytes, auth, lsupdate);
}

#[test]
fn test_decode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_decode_packet(bytes, auth, lsupdate, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_encode_packet(bytes, auth, lsack);
}

#[test]
fn test_decode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_decode_packet(bytes, auth, lsack, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_extended_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_ROUTER_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_ROUTER_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_network_lsa1() {
    let (ref bytes, ref lsa) = *EXT_NETWORK_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_network_lsa1() {
    let (ref bytes, ref lsa) = *EXT_NETWORK_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_inter_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_PREFIX_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_inter_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_PREFIX_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_inter_area_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_ROUTER_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_inter_area_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_ROUTER_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_as_external_lsa1() {
    let (ref bytes, ref lsa) = *EXT_AS_EXTERNAL_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_as_external_lsa1() {
    let (ref bytes, ref lsa) = *EXT_AS_EXTERNAL_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_link_lsa1() {
    let (ref bytes, ref lsa) = *EXT_LINK_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_link_lsa1() {
    let (ref bytes, ref lsa) = *EXT_LINK_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_intra_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_intra_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_extended_intra_are_prefix_lsa_bier_tlv_non_mpls_encap() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_intra_are_prefix_lsa_bier_tlv_non_mpls_encap() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}
