//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock as Lazy};

use bytes::Bytes;
use const_addrs::{ip4, net4};
use holo_ospf::ospfv2::packet::lsa::*;
use holo_ospf::ospfv2::packet::lsa_opaque::*;
use holo_ospf::ospfv2::packet::*;
use holo_ospf::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use holo_ospf::packet::lls::ExtendedOptionsFlags;
use holo_ospf::packet::lsa::{Lsa, LsaKey};
use holo_ospf::packet::tlv::*;
use holo_ospf::packet::{DbDescFlags, Packet, PacketType};
use holo_ospf::version::Ospfv2;
use holo_protocol::assert_eq_hex;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::AddressFamily;
use holo_utils::keychain::Key;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
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
    assert_eq_hex!(bytes_expected, bytes_actual);
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

    // Decode the packet.
    let mut buf = Bytes::copy_from_slice(bytes);
    let packet_actual =
        Packet::decode(AddressFamily::Ipv4, &mut buf, auth).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_lsa(bytes_expected: &[u8], lsa: &Lsa<Ospfv2>) {
    assert_eq_hex!(bytes_expected, lsa.raw);
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
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("1.1.1.1")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x30, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0xe6, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x12, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0xff, 0xf4,
                0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E | Options::L,
                priority: 1,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("1.1.1.1")].into(),
                lls: Some(holo_ospf::packet::lls::LlsHelloData {
                    eof: Some(
                        ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS,
                    ),
                }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_MD5_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x10,
                0x32, 0x45, 0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03,
                0x12, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03,
                0x0a, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
                0x03, 0x03, 0xdc, 0x24, 0x29, 0xe3, 0x8b, 0x02, 0x6c, 0xc6,
                0xb8, 0x74, 0x01, 0x67, 0xf2, 0xb6, 0xff, 0xaf, 0x00, 0x00,
                0x00, 0x09, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
                0x00, 0x02, 0x00, 0x14, 0x32, 0x45, 0xd0, 0x14, 0xb4, 0x6b,
                0x87, 0xd2, 0x53, 0x61, 0x67, 0x51, 0xfc, 0xfc, 0x99, 0xca,
                0x5e, 0xc1, 0x53, 0xcc,
            ],
            Some((
                Key::new(1, CryptoAlgo::Md5, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E | Options::L,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: Some(holo_ospf::packet::lls::LlsHelloData {
                    eof: Some(
                        ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS,
                    ),
                }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA1_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv2>,
)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x14, 0x32, 0x45,
            0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x12, 0x01, 0x00,
            0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03, 0x0a, 0x00, 0x01, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x68, 0x84, 0x76,
            0x39, 0x22, 0xf5, 0x60, 0xe7, 0x6a, 0x1c, 0x5e, 0x91, 0x89, 0x70,
            0x1f, 0x6e, 0x8e, 0x02, 0x18, 0x4c, 0x00, 0x00, 0x00, 0x0a, 0x00,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x18,
            0x32, 0x45, 0xd0, 0x14, 0xd7, 0x37, 0x3d, 0x4b, 0xa7, 0xdd, 0xf5,
            0xe8, 0x12, 0x22, 0x95, 0xa7, 0x9f, 0x1f, 0x19, 0x88, 0x5a, 0xb5,
            0x5d, 0xe3,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.0"),
                auth_seqno: Some(843436052),
            },
            network_mask: ip4!("255.255.255.0"),
            hello_interval: 3,
            options: Options::E | Options::L,
            priority: 1,
            dead_interval: 12,
            dr: Some(ip4!("10.0.1.3").into()),
            bdr: Some(ip4!("10.0.1.2").into()),
            neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
            }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA256_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv2>,
)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x20, 0x32, 0x45,
            0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x12, 0x01, 0x00,
            0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03, 0x0a, 0x00, 0x01, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x86, 0x1b, 0xda,
            0x09, 0xc1, 0xaf, 0xb3, 0x8a, 0x79, 0x99, 0xec, 0x3a, 0x47, 0x00,
            0xfe, 0x39, 0x6e, 0x8f, 0x4d, 0xc1, 0xa6, 0xa9, 0xe5, 0x05, 0x97,
            0x78, 0x4a, 0xef, 0xa7, 0x15, 0xd7, 0x5c, 0x00, 0x00, 0x00, 0x0d,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00,
            0x24, 0x32, 0x45, 0xd0, 0x14, 0xbd, 0x9c, 0xc2, 0xcc, 0xd7, 0x1c,
            0x35, 0xf5, 0x30, 0x84, 0xfe, 0x42, 0x87, 0xd3, 0xb7, 0x39, 0xa6,
            0x6c, 0x06, 0x05, 0xad, 0x3c, 0xf2, 0x6c, 0xe3, 0x39, 0xcf, 0xd7,
            0x0f, 0x4e, 0x5c, 0x3d,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.0"),
                auth_seqno: Some(843436052),
            },
            network_mask: ip4!("255.255.255.0"),
            hello_interval: 3,
            options: Options::E | Options::L,
            priority: 1,
            dead_interval: 12,
            dr: Some(ip4!("10.0.1.3").into()),
            bdr: Some(ip4!("10.0.1.2").into()),
            neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
            }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA384_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv2>,
)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x30, 0x32, 0x45,
            0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x12, 0x01, 0x00,
            0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03, 0x0a, 0x00, 0x01, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x6d, 0x78, 0x1d,
            0x13, 0x37, 0xff, 0xe1, 0x69, 0x95, 0xe7, 0x16, 0x7f, 0xd7, 0xe2,
            0x4a, 0xa7, 0x25, 0x4a, 0x90, 0xf4, 0x62, 0xda, 0x8b, 0x6b, 0x9e,
            0xaf, 0x8d, 0x68, 0xbb, 0xaf, 0x89, 0xd2, 0x90, 0x2d, 0x18, 0xac,
            0x41, 0x74, 0x51, 0x68, 0x1f, 0x86, 0xbd, 0x61, 0xdc, 0x4f, 0x41,
            0x17, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x02, 0x00, 0x34, 0x32, 0x45, 0xd0, 0x14, 0xd4,
            0x7f, 0x8c, 0x26, 0xf7, 0x38, 0x18, 0xa3, 0x95, 0xd8, 0x0a, 0x44,
            0x29, 0x58, 0xd5, 0x6a, 0x86, 0x4c, 0x12, 0x2b, 0x3e, 0x17, 0xb0,
            0xee, 0x77, 0xbf, 0x0d, 0x35, 0xb3, 0xef, 0x0a, 0x29, 0xde, 0x22,
            0x13, 0xb3, 0x28, 0xb3, 0x57, 0xb9, 0x5e, 0x9f, 0x07, 0x2c, 0x16,
            0x2d, 0x94, 0xa4,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.0"),
                auth_seqno: Some(843436052),
            },
            network_mask: ip4!("255.255.255.0"),
            hello_interval: 3,
            options: Options::E | Options::L,
            priority: 1,
            dead_interval: 12,
            dr: Some(ip4!("10.0.1.3").into()),
            bdr: Some(ip4!("10.0.1.2").into()),
            neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
            }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.0"),
                    auth_seqno: Some(843436052),
                },
                network_mask: ip4!("255.255.255.0"),
                hello_interval: 3,
                options: Options::E,
                priority: 1,
                dead_interval: 12,
                dr: Some(ip4!("10.0.1.3").into()),
                bdr: Some(ip4!("10.0.1.2").into()),
                neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA512_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv2>,
)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x01, 0x00, 0x34, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x40, 0x32, 0x45,
            0xd0, 0x14, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x12, 0x01, 0x00,
            0x00, 0x00, 0x0c, 0x0a, 0x00, 0x01, 0x03, 0x0a, 0x00, 0x01, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x65, 0xbb, 0x88,
            0xc9, 0x9e, 0xd9, 0xdd, 0xea, 0x29, 0xe4, 0x93, 0x6a, 0x08, 0x18,
            0x4f, 0xfa, 0xb1, 0xb7, 0x33, 0x55, 0xa4, 0xcf, 0x00, 0x76, 0x7f,
            0x00, 0xa0, 0x8e, 0x0c, 0x42, 0xa7, 0x2c, 0xed, 0x12, 0x3b, 0x16,
            0x38, 0xb7, 0xa7, 0xbd, 0x4f, 0xa9, 0x95, 0xa3, 0x1a, 0xbe, 0x74,
            0xdc, 0x90, 0x8c, 0xa2, 0xd2, 0xe3, 0xdf, 0x82, 0xa8, 0xe4, 0x87,
            0xcd, 0x8c, 0xc1, 0x06, 0xcc, 0x92, 0x00, 0x00, 0x00, 0x15, 0x00,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x44,
            0x32, 0x45, 0xd0, 0x14, 0xf2, 0x38, 0x50, 0x21, 0x95, 0x38, 0xd0,
            0x14, 0x35, 0xf1, 0x6b, 0x01, 0x7e, 0xaf, 0x19, 0x46, 0x2a, 0xa7,
            0xd8, 0x46, 0xc8, 0x22, 0x8a, 0x7a, 0x73, 0x6f, 0x3e, 0xe0, 0xd9,
            0x14, 0xca, 0xb1, 0xdf, 0xf5, 0xe8, 0x5a, 0xce, 0x21, 0xcf, 0x69,
            0x72, 0x48, 0xba, 0xcf, 0x53, 0xd8, 0xc7, 0x17, 0x97, 0xc5, 0x6d,
            0x96, 0x26, 0xf7, 0x69, 0xcd, 0x56, 0xf6, 0xdc, 0x26, 0xcc, 0x20,
            0x08, 0x66,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.0"),
                auth_seqno: Some(843436052),
            },
            network_mask: ip4!("255.255.255.0"),
            hello_interval: 3,
            options: Options::E | Options::L,
            priority: 1,
            dead_interval: 12,
            dr: Some(ip4!("10.0.1.3").into()),
            bdr: Some(ip4!("10.0.1.2").into()),
            neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
            }),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
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
                        lsa_id: ip4!("1.1.1.1"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000002,
                        cksum: 0x48d6,
                        length: 48,
                    },
                    LsaHdr {
                        age: 3,
                        options: Options::E,
                        lsa_type: LsaTypeCode::AsExternal.into(),
                        lsa_id: ip4!("172.16.1.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0xfcff,
                        length: 36,
                    },
                ],
                lls: None,
            }),
        )
    });

static DBDESC1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv2>)> =
    Lazy::new(|| {
        (
            vec![
                0x02, 0x02, 0x00, 0x48, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0xc8, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x52, 0x00, 0x4e, 0xb8,
                0x8f, 0x2e, 0x00, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x02, 0x48, 0xd6,
                0x00, 0x30, 0x00, 0x03, 0x02, 0x05, 0xac, 0x10, 0x01, 0x00,
                0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xfc, 0xff,
                0x00, 0x24, 0xff, 0xf6, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x01,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                mtu: 1500,
                options: Options::E | Options::O | Options::L,
                dd_flags: DbDescFlags::empty(),
                dd_seq_no: 1320718126,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 3,
                        options: Options::E,
                        lsa_type: LsaTypeCode::Router.into(),
                        lsa_id: ip4!("1.1.1.1"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000002,
                        cksum: 0x48d6,
                        length: 48,
                    },
                    LsaHdr {
                        age: 3,
                        options: Options::E,
                        lsa_type: LsaTypeCode::AsExternal.into(),
                        lsa_id: ip4!("172.16.1.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0xfcff,
                        length: 36,
                    },
                ],
                lls: Some(holo_ospf::packet::lls::LlsDbDescData {
                    eof: Some(ExtendedOptionsFlags::LR),
                }),
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
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                entries: vec![
                    LsaKey {
                        lsa_type: LsaTypeCode::Router.into(),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("1.1.1.1"),
                    },
                    LsaKey {
                        lsa_type: LsaTypeCode::AsExternal.into(),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("172.16.1.0"),
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
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                lsas: vec![
                    Lsa::new(
                        49,
                        Some(Options::E),
                        ip4!("2.2.2.2"),
                        ip4!("2.2.2.2"),
                        0x80000002,
                        LsaBody::Router(LsaRouter {
                            flags: LsaRouterFlags::B,
                            links: vec![LsaRouterLink {
                                link_type: LsaRouterLinkType::StubNetwork,
                                link_id: ip4!("10.0.1.0"),
                                link_data: ip4!("255.255.255.0"),
                                metric: 10,
                            }],
                        }),
                    ),
                    Lsa::new(
                        49,
                        Some(Options::E),
                        ip4!("2.2.2.2"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::SummaryNetwork(LsaSummary {
                            mask: ip4!("255.255.255.255"),
                            metric: 0,
                        }),
                    ),
                    Lsa::new(
                        49,
                        Some(Options::E),
                        ip4!("10.0.2.0"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::SummaryNetwork(LsaSummary {
                            mask: ip4!("255.255.255.0"),
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
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    auth_seqno: None,
                },
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: ip4!("3.3.3.3"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x0936,
                        length: 28,
                    },
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: ip4!("10.0.3.0"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x54df,
                        length: 28,
                    },
                    LsaHdr {
                        age: 1,
                        options: Options::E,
                        lsa_type: LsaTypeCode::SummaryNetwork.into(),
                        lsa_id: ip4!("10.0.4.0"),
                        adv_rtr: ip4!("2.2.2.2"),
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
            ip4!("2.2.2.2"),
            ip4!("2.2.2.2"),
            0x80000002,
            LsaBody::Router(LsaRouter {
                flags: LsaRouterFlags::B,
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::StubNetwork,
                    link_id: ip4!("10.0.1.0"),
                    link_data: ip4!("255.255.255.0"),
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
            0x01, 0x80, 0x00, 0x00, 0x01, 0xd5, 0xb7, 0x00, 0x6c, 0x00, 0x01,
            0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0x68,
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
            Some(Options::O | Options::E),
            OpaqueLsaId::new(LsaOpaqueType::RouterInfo as u8, 0).into(),
            ip4!("1.1.1.1"),
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
                node_tags: vec![
                    NodeAdminTagTlv::new([1, 2, 3].into()),
                    NodeAdminTagTlv::new([4, 5, 6].into()),
                ],
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
            ip4!("7.0.0.0"),
            ip4!("1.1.1.1"),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtPrefix(LsaExtPrefix {
                prefixes: btreemap! {
                    net4!("1.1.1.1/32") => {
                        ExtPrefixTlv {
                            route_type: ExtPrefixRouteType::IntraArea,
                            af: 0,
                            flags: LsaExtPrefixFlags::N,
                            prefix: net4!("1.1.1.1/32"),
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
            ip4!("8.0.0.0"),
            ip4!("1.1.1.1"),
            0x80000001,
            LsaBody::OpaqueArea(LsaOpaque::ExtLink(LsaExtLink {
                link: Some(ExtLinkTlv {
                    link_type: LsaRouterLinkType::PointToPoint,
                    link_id: ip4!("2.2.2.2"),
                    link_data: ip4!("10.0.1.1"),
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
            ip4!("3.0.0.0"),
            ip4!("6.6.6.6"),
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
fn test_encode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
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
fn test_encode_hello_md5_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_MD5_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_md5_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_MD5_LLS;
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
fn test_encode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
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
fn test_encode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
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
fn test_encode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
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
fn test_encode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
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
fn test_encode_dbdesc1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESC1_LLS;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdesc1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESC1_LLS;
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
