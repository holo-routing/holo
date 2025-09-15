//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::sync::LazyLock;

use const_addrs::{ip, ip4};
use holo_protocol::assert_eq_hex;
use holo_utils::ip::AddressFamily;
use holo_utils::mac_addr::MacAddr;
use holo_vrrp::instance::Version;
use holo_vrrp::packet::{DecodeError, EthernetHdr, Ipv4Hdr, VrrpHdr};

static VRRPV2HDR: LazyLock<(Vec<u8>, VrrpHdr)> = LazyLock::new(|| {
    (
        vec![
            0x21, 0x33, 0x1e, 0x01, 0x00, 0x01, 0xb5, 0xc5, 0x0a, 0x00, 0x01,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        VrrpHdr {
            version: Version::V2,
            hdr_type: 1,
            vrid: 51,
            priority: 30,
            count_ip: 1,
            adver_int: 1,
            checksum: 0xb5c5,
            ip_addresses: vec![ip!("10.0.1.5")],
        },
    )
});

static VRRPV3HDR_IPV6: LazyLock<(Vec<u8>, VrrpHdr)> = LazyLock::new(|| {
    (
        vec![
            0x31, 0x01, 0x16, 0x01, 0x00, 0x01, 0xb5, 0x7f, 0x20, 0x01, 0x0d,
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x70,
            0x73, 0x34,
        ],
        VrrpHdr {
            version: Version::V3(AddressFamily::Ipv6),
            hdr_type: 1,
            vrid: 1,
            priority: 22,
            count_ip: 1,
            adver_int: 1,
            checksum: 0xb57f,
            ip_addresses: vec![ip!("2001:db8::370:7334")],
        },
    )
});

// Unique identifier for the packet.
static IPV4HDR: LazyLock<(Vec<u8>, Ipv4Hdr)> = LazyLock::new(|| {
    (
        vec![
            0x45, 0xc0, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0xff, 0x70, 0xb5,
            0xe8, 0xc0, 0xa8, 0x64, 0x02, 0xe0, 0x00, 0x00, 0x12,
        ],
        Ipv4Hdr {
            total_length: 40,
            src_address: ip4!("192.168.100.2"),
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
            dst_mac: MacAddr::from([0x01, 0x00, 0x5e, 0x00, 0x00, 0x12]),
            src_mac: MacAddr::from([0x00, 0x00, 0x5e, 0x00, 0x01, 0x33]),
            ethertype: libc::ETH_P_IP as _,
        },
    )
});

#[test]
fn test_encode_vrrp_v2_hdr() {
    let (ref bytes, ref vrrphdr) = *VRRPV2HDR;
    let mut vrrphdr = vrrphdr.clone();
    vrrphdr.checksum = 0;

    let generated_bytes = vrrphdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
}

#[test]
fn test_encode_vrrp_v3_ipv6_hdr() {
    let (ref bytes, ref vrrphdr) = *VRRPV3HDR_IPV6;
    let vrrphdr = vrrphdr.clone();

    let generated_bytes = vrrphdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
}

#[test]
fn test_decode_vrrpv2_hdr() {
    let (ref bytes, ref vrrphdr) = *VRRPV2HDR;
    let data = bytes.as_ref();
    let generated_hdr = VrrpHdr::decode(data, AddressFamily::Ipv4);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(vrrphdr, &generated_hdr);
}

#[test]
fn test_decode_vrrpv3_hdr_ipv6() {
    let (ref bytes, ref vrrphdr) = *VRRPV3HDR_IPV6;
    let data = bytes.as_ref();
    let generated_hdr = VrrpHdr::decode(data, AddressFamily::Ipv6);
    assert!(generated_hdr.is_ok());

    let generated_hdr = generated_hdr.unwrap();
    assert_eq!(vrrphdr, &generated_hdr);
}

#[test]
fn test_decode_vrrpv3_hdr_ipv6_incomplete_hdr() {
    // Try to decode a vrrp header that does not hold
    // even the nonvariant VRRP header fields.
    let generated_hdr = VrrpHdr::decode(&[], AddressFamily::Ipv6);
    assert_eq!(generated_hdr, Err(DecodeError::IncompletePacket));
}

/// Tests for when the packet length is more than the required length
#[test]
fn test_decode_vrrpv3_hdr_ipv6_too_long() {
    let (ref bytes, ref _vrrphdr) = *VRRPV3HDR_IPV6;
    let data: &mut [u8; 1000] = &mut [0u8; 1000];
    data[0] = bytes[0];
    data[1] = bytes[1];

    let generated_hdr = VrrpHdr::decode(data, AddressFamily::Ipv6);
    assert_eq!(
        generated_hdr,
        Err(DecodeError::PacketLengthError {
            vrid: 1,
            version: Version::V3(AddressFamily::Ipv6)
        })
    );
}

#[test]
fn test_decode_vrrpv3_hdr_ipv6_version_error() {
    let (ref bytes, ref _vrrphdr) = *VRRPV3HDR_IPV6;
    let mut data = bytes.clone();
    // Effectively setting the vrrp version as 4.
    data[0] = 0x41;

    let generated_hdr = VrrpHdr::decode(&data, AddressFamily::Ipv6);
    assert_eq!(generated_hdr, Err(DecodeError::VersionError { vrid: 1 }));
}

#[test]
fn test_decode_vrrpv2_wrong_checksum() {
    let (ref bytes, ref _vrrphdr) = *VRRPV2HDR;
    let mut data = bytes.clone();
    // 6th and 7th fields are the checksum fields.
    data[6] = 0;
    data[7] = 0;
    let generated_hdr = VrrpHdr::decode(&data, AddressFamily::Ipv4);
    assert_eq!(generated_hdr, Err(DecodeError::ChecksumError));
}

#[test]
fn test_encode_ipv4hdr() {
    let (ref bytes, ref iphdr) = *IPV4HDR;
    let iphdr = iphdr.clone();

    let generated_bytes = iphdr.encode();
    let generated_data = generated_bytes.as_ref();

    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
}

#[test]
fn test_encode_ethernethdr() {
    let (ref bytes, ref ethernethdr) = *ETHERNETHDR;

    let generated_bytes = ethernethdr.encode();
    let generated_data = generated_bytes.as_ref();
    let expected_data: &[u8] = bytes.as_ref();
    assert_eq_hex!(generated_data, expected_data);
}
