//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use bytes::Buf;
use holo_vrrp::packet::{VRRPPacket, DecodeError, PacketLengthError};

/* 
generally in the packet tests we will use the following packet structure
with slight modifications to be done on a per test basis(the changes will 
be specified)

Valid VRRP packet with the following params:
    - ver_type: 21 [version: 2, header_type: 1]
    - vrid: 51
    - priority: 101
    - count_ip: 1
    - auth_type: 0
    - adver_int: 1
    - checksum: 0x54db
    - ip_addresses: [192.168.100.100]
    - auth_data: 0
    - auth_data2: 0
 */
fn valid_pkt_data() -> [u8; 20] {
    [
        0x21, 0x33, 0x65, 0x01,
        0x00, 0x01, 0x54, 0xbd,
        0xc0, 0xa8, 0x64, 0x64,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ]
}

// test the valid packet being decoded
#[test]
fn test_valid_decoding(){
    let vrrp_pkt = VRRPPacket::decode(&valid_pkt_data());
    assert!(vrrp_pkt.is_ok());
}


// make the VRRP packet too short. We will use 10 bytes. 
#[test]
fn test_pkt_too_short() {
    let vrrp_pkt = VRRPPacket::decode(&[0x00; 10]);
    assert_eq!(
        vrrp_pkt, 
        Err(DecodeError::PacketLengthError(PacketLengthError::TooShort(10)))
    );
}

// the length of the entire packet is too long
#[test]
fn test_pkt_too_long() {
    let vrrp_pkt = VRRPPacket::decode(&[0x00; 100]);
    assert_eq!(
        vrrp_pkt, 
        Err(DecodeError::PacketLengthError(PacketLengthError::TooLong(100)))
    );
}

// test when the packet is too long in length
// we set count_ip as 17
#[test] 
fn test_count_ip_too_high() {
    let data: &mut [u8] = &mut valid_pkt_data();
    data[3] = 17;
    let vrrp_pkt = VRRPPacket::decode(data);
    assert_eq!(
        vrrp_pkt, 
        Err(DecodeError::PacketLengthError(PacketLengthError::AddressCount(17)))
    );
}



// let us claim we have 3 ip addresses yet we have only one
// we set count_ip as 17
#[test] 
fn test_count_ip_corrupted() {
    let data: &mut [u8] = &mut valid_pkt_data();
    data[3] = 3;
    let vrrp_pkt = VRRPPacket::decode(data);
    assert_eq!(
        vrrp_pkt, 
        Err(DecodeError::PacketLengthError(PacketLengthError::CorruptedLength))
    );
}

#[test]
fn test_invalid_checksum() {
    let data = &mut valid_pkt_data();
    data[6] = 0x01;
    data[7] = 0xde;

    let pkt = VRRPPacket::decode(data);
    assert_eq!(
        pkt, 
        Err(DecodeError::ChecksumError)
    );
}
