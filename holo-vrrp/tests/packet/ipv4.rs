//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use holo_vrrp::packet::IPv4Paket;
use holo_vrrp::packet::{PacketLengthError, DecodeError};

// the ipv4 Packet header details that will be used in IPV4 tests. 
//  It may have slight modifications based on the specific test
//  but that will be specified beforehand. 
// 
// - version: 4
// - header length: 5
// - tos: 0
// - total length: 52
// - identification: 0x6cb8
// - flags: 0b0100000000000000
// - ttl: 51
// - protocol: 6 [TCP]
// - checksum: 0xfe74
// - source_address: 208.115.231.106
// - destination_address: 192.168.100.16
fn valid_pkt_data() -> [u8; 20] {
    [
        0x45, 0x00, 0x00, 0x34,
        0x6c, 0xb8, 0x40, 0x00, 
        0x33, 0x06, 0xfe, 0x74, 
        0xd0, 0x73, 0xe7, 0x6a, 
        0xc0, 0xa8, 0x64, 0x10
    ]
}


#[test]
fn encode_valid_pkt() {
    let pkt_wrapped = IPv4Paket::decode(&valid_pkt_data());
    assert!(pkt_wrapped.is_ok());
    
    let pkt = pkt_wrapped.unwrap();
    let expected = IPv4Paket {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 52,
        identification: 0x6cb8,
        flags: 0b0100,
        offset: 0b0000000000000000,
        ttl: 51,
        protocol: 6,
        checksum: 0xfe74,
        src_address: Ipv4Addr::new(208, 115, 231, 106),
        dst_address: Ipv4Addr::new(192, 168, 100, 16),
        options: None,
        padding: None
    };
    assert_eq!(expected, pkt);
}


#[test]
fn test_hdr_length_corruption() {
    let data = &mut valid_pkt_data();

    // change length from 4 to 5
    data[0] = 0x44;

    let pkt = IPv4Paket::decode(data);
    assert_eq!(
        pkt,
        Err(DecodeError::PacketLengthError(PacketLengthError::CorruptedLength))
    );
}

#[test]
fn test_header_too_short() {
    let data = [
        0x43, 0x00, 0x00, 0x34,
        0x6c, 0xb8, 0x40, 0x00, 
        0x33, 0x06, 0xfe, 0x74, 
    ];
    let pkt = IPv4Paket::decode(&data);
    assert_eq!(
        pkt,
        Err(DecodeError::PacketLengthError(PacketLengthError::TooShort(12)))
    );
}

#[test]
fn test_header_too_long() {

    let data = &mut [0x00; 28];
    data[0] = 0x47;
    let pkt = IPv4Paket::decode(data);
    assert_eq!(
        pkt,
        Err(DecodeError::PacketLengthError(PacketLengthError::TooLong(28)))
    );
}