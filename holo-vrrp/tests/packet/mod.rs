//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use holo_vrrp::interface::{VRRP_MULTICAST_ADDRESS, VRRP_PROTO_NUMBER};
use holo_vrrp::packet::{EthernetHdr, Ipv4Hdr, VrrpHdr};

static VRRPHDR: LazyLock<(Vec<u8>, VrrpHdr)> = LazyLock::new(|| {
    (
        vec![
            0x21, 0x33, 0x1e, 0x01, 0x00, 0x01, 0xb5, 0xc5, 0x0a, 0x00, 0x01,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        VrrpHdr {
            version: 2,
            hdr_type: 1,
            vrid: 51,
            priority: 30,
            count_ip: 1,
            auth_type: 0,
            adver_int: 1,
            checksum: 0xb5c5,
            ip_addresses: vec![Ipv4Addr::new(10, 0, 1, 5)],
            auth_data: 0,
            auth_data2: 0,
        },
    )
});

static IPV4HDR: LazyLock<(Vec<u8>, Ipv4Hdr)> = LazyLock::new(|| {
    (
        vec![
            0x45, 0xc0, 0x00, 0x28, 0x08, 0x9d, 0x00, 0x00, 0xff, 0x70, 0xad,
            0x4b, 0xc0, 0xa8, 0x64, 0x02, 0xe0, 0x00, 0x00, 0x12,
        ],
        Ipv4Hdr {
            version: 4,
            ihl: 5,
            tos: 0xc0,
            total_length: 40,
            identification: 0x089d,
            flags: 0,
            offset: 0,
            ttl: 255,
            protocol: VRRP_PROTO_NUMBER as u8,
            checksum: 0xad4b,
            src_address: Ipv4Addr::new(192, 168, 100, 2),
            dst_address: VRRP_MULTICAST_ADDRESS,
            options: None,
            padding: None,
        },
    )
});

static ETHERNETHDR: LazyLock<(Vec<u8>, EthernetHdr)> = LazyLock::new(|| {
    (
        vec![
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x12, 0x00, 0x00, 0x5e, 0x00, 0x01,
            0x33, 0x08, 0x00,
        ],
        EthernetHdr {
            dst_mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x12],
            src_mac: [0x00, 0x00, 0x5e, 0x00, 0x01, 0x33],
            ethertype: 0x0800,
        },
    )
});

#[test]
fn test_encode_vrrphdr() {
    let (ref bytes, ref vrrphdr) = *VRRPHDR;
    let hdr = vrrphdr.clone();

    let generated_bytes = hdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq!(generated_data, expected_data);
}

#[test]
fn test_decode_vrrphdr() {
    let (ref bytes, ref vrrphdr) = *VRRPHDR;
    let data = bytes.as_ref();
    let generated_hdr = VrrpHdr::decode(data);
    assert!(generated_hdr.is_ok());

    let mut generated_hdr = generated_hdr.unwrap();
    generated_hdr.generate_checksum();
    assert_eq!(vrrphdr, &generated_hdr);
}

#[test]
fn test_encode_ipv4hdr() {
    let (ref bytes, ref iphdr) = *IPV4HDR;
    let hdr = iphdr.clone();

    let generated_bytes = hdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq!(generated_data, expected_data);
}

#[test]
fn test_decode_ipv4hdr() {
    let (ref bytes, ref ipv4hdr) = *IPV4HDR;
    let data = bytes.as_ref();
    let generated_hdr = Ipv4Hdr::decode(data);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(ipv4hdr, &generated_hdr);
}

#[test]
fn test_encode_ethernethdr() {
    let (ref bytes, ref ethernethdr) = *ETHERNETHDR;
    let hdr = ethernethdr.clone();

    let generated_bytes = hdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq!(generated_data, expected_data);
}

#[test]
fn test_decode_ethernethdr() {
    let (ref bytes, ref ethernethdr) = *ETHERNETHDR;
    let data = bytes.as_ref();
    let generated_hdr = EthernetHdr::decode(data);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(ethernethdr, &generated_hdr);
}
