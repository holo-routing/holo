//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use holo_utils::ip::AddressFamily;
use holo_vrrp::consts::{VRRP_PROTO_NUMBER, VRRP_V2_MULTICAST_ADDRESS};
use holo_vrrp::packet::{EthernetHdr, Ipv4Hdr, Ipv6Hdr, VrrpHdr};
use holo_vrrp::version::VrrpVersion;

static VRRPHDR: LazyLock<(Vec<u8>, VrrpHdr)> = LazyLock::new(|| {
    (
        vec![
            0x21, 0x33, 0x1e, 0x01, 0x00, 0x01, 0xb5, 0xc5, 0x0a, 0x00, 0x01,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        VrrpHdr {
            version: VrrpVersion::V2,
            hdr_type: 1,
            vrid: 51,
            priority: 30,
            count_ip: 1,
            auth_type: 0,
            adver_int: 1,
            checksum: 0xb5c5,
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))],
            auth_data: Some(0),
            auth_data2: Some(0),
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
            dst_address: VRRP_V2_MULTICAST_ADDRESS,
            options: None,
            padding: None,
        },
    )
});

static IPV6HDR: LazyLock<(Vec<u8>, Ipv6Hdr)> = LazyLock::new(|| {
    (
        vec![
            0x60, 0x01, 0xbb, 0x1e, 0x00, 0x28, 0x06, 0xff, 0xfe, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x52, 0xd0, 0xb3, 0x7a, 0x4f,
            0x37, 0x11, 0x26, 0x20, 0x00, 0x2d, 0x40, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x98,
        ],
        Ipv6Hdr {
            version: 6,
            traffic_class: 0x00,
            flow_label: 0x1bb1e,
            payload_length: 40,
            next_header: 6,
            hop_limit: 255,
            source_address: Ipv6Addr::new(
                0xfe80, 0x00, 0x00, 0x00, 0x5152, 0xd0b3, 0x7a4f, 0x3711,
            ),
            destination_address: Ipv6Addr::new(
                0x2620, 0x2d, 0x4002, 0x1, 0x00, 0x00, 0x00, 0x198,
            ),
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
            ethertype: libc::ETH_P_IP as _,
        },
    )
});

#[test]
fn test_encode_vrrphdr() {
    let (ref bytes, ref vrrphdr) = *VRRPHDR;
    let mut vrrphdr = vrrphdr.clone();
    vrrphdr.checksum = 0;

    let generated_bytes = vrrphdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
}

#[test]
fn test_decode_vrrphdr() {
    let (ref bytes, ref vrrphdr) = *VRRPHDR;
    let data = bytes.as_ref();
    let generated_hdr = VrrpHdr::decode(data, AddressFamily::Ipv4);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(vrrphdr, &generated_hdr);
}

#[test]
fn test_decode_vrrp_wrong_checksum() {
    let (ref bytes, ref _vrrphdr) = *VRRPHDR;
    let mut data = bytes.clone();
    // 6th and 7th fields are the checksum fields
    data[6] = 0;
    data[7] = 0;
    let generated_hdr = Ipv4Hdr::decode(&data);
    assert_eq!(generated_hdr, Err(DecodeError::ChecksumError));
}

#[test]
fn test_encode_ipv4hdr() {
    let (ref bytes, ref iphdr) = *IPV4HDR;
    let mut iphdr = iphdr.clone();
    iphdr.checksum = 0;

    let generated_bytes = iphdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
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
fn test_encode_ipv6hdr() {
    let (ref bytes, ref iphdr) = *IPV6HDR;

    let generated_bytes = iphdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq!(generated_data, expected_data);
}

#[test]
fn test_decode_ipv6hdr() {
    let (ref bytes, ref ipv6hdr) = *IPV6HDR;
    let data = bytes.as_ref();
    let generated_hdr = Ipv6Hdr::decode(data);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(ipv6hdr, &generated_hdr);

}

#[test]
fn test_encode_ethernethdr() {
    let (ref bytes, ref ethernethdr) = *ETHERNETHDR;

    let generated_bytes = ethernethdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
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
