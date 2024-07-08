//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_vrrp::packet::{ArpPacket, DecodeError};

/*
ARP packet =>


hw_type: 1,
proto_type: 0x0800,
hw_length: 6,
proto_length: 4,
operation: 1,
sender_hw_address: [0xd4, 0xb1, 0x08, 0x4c, 0xbb, 0xf9], // src mac
sender_proto_address: [192, 168, 100, 1], // src ip
pub target_hw_address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // src mac
pub target_proto_address: [192, 168, 100, 16] // src ip

*/
fn valid_pkt_data() -> [u8; 28] {
    [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xd4, 0xb1, 0x08, 0x4c,
        0xbb, 0xf9, 0xc0, 0xa8, 0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0xa8, 0x64, 0x10,
    ]
}

#[test]
fn encode_valid_pkt() {
    let pkt_wrapped = ArpPacket::decode(&valid_pkt_data());
    assert!(pkt_wrapped.is_ok());
}

#[test]
fn test_pkt_invalid_length() {
    let pkt = ArpPacket::decode(&[0x01]);
    assert_eq!(pkt, Err(DecodeError::PacketLengthError));
}
