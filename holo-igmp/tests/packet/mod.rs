//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
use std::sync::LazyLock as Lazy;

use bytes::Bytes;
use const_addrs::ip4;
use holo_igmp::packet::{
    IgmpV2Message, LeaveGroupV2, MembershipReportV2, Packet, PacketType,
};
use holo_protocol::assert_eq_hex;

static MEMBERSHIPREQUEST1: Lazy<(Vec<u8>, Packet)> = Lazy::new(|| {
    (
        vec![0x16, 0x00, 0x06, 0xfb, 0xe1, 0x01, 0x02, 0x03],
        Packet::MembershipReport(MembershipReportV2(IgmpV2Message {
            igmp_type: PacketType::MembershipReportV2Type,
            max_resp_time: Some(0x00),
            checksum: 0x06fb,
            group_address: Some(ip4!("225.1.2.3")),
        })),
    )
});

static MEMBERSHIPREQUESTBADCHECKSUM1: Lazy<(Vec<u8>, Packet)> =
    Lazy::new(|| {
        (
            vec![0x16, 0x00, 0x06, 0xfc, 0xe1, 0x01, 0x02, 0x03],
            Packet::MembershipReport(MembershipReportV2(IgmpV2Message {
                igmp_type: PacketType::MembershipReportV2Type,
                max_resp_time: Some(0x00),
                checksum: 0x06fc,
                group_address: Some(ip4!("225.1.2.3")),
            })),
        )
    });

static LEAVEGROUP1: Lazy<(Vec<u8>, Packet)> = Lazy::new(|| {
    (
        vec![0x17, 0x00, 0x05, 0xfb, 0xe1, 0x01, 0x02, 0x03],
        Packet::LeaveGroup(LeaveGroupV2(IgmpV2Message {
            igmp_type: PacketType::LeaveGroupV2Type,
            max_resp_time: Some(0x00),
            checksum: 0x05fb,
            group_address: Some(ip4!("225.1.2.3")),
        })),
    )
});

fn test_decode_packet(bytes: &[u8], packet_expected: &Packet) {
    let mut buf = Bytes::copy_from_slice(bytes);
    let packet_actual = Packet::decode(&mut buf).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_packet(bytes_expected: &[u8], packet: &Packet) {
    let bytes_actual = packet.encode();
    assert_eq_hex!(bytes_expected, bytes_actual);
}

#[test]
fn test_decode_membership_report() {
    let (ref bytes, ref packet_expected) = *MEMBERSHIPREQUEST1;
    test_decode_packet(bytes, packet_expected);
}

#[test]
fn test_encode_membership_report() {
    let (ref bytes_expected, ref packet) = *MEMBERSHIPREQUEST1;
    test_encode_packet(bytes_expected, packet);
}

#[test]
fn test_decode_leave_group() {
    let (ref bytes, ref packet_expected) = *LEAVEGROUP1;
    test_decode_packet(bytes, packet_expected);
}

#[test]
fn test_encode_leave_group() {
    let (ref bytes_expected, ref packet) = *LEAVEGROUP1;
    test_encode_packet(bytes_expected, packet);
}

#[test]
fn test_decode_membership_report_bad_checksum() {
    let (ref bytes, ref _packet_expected) = *MEMBERSHIPREQUESTBADCHECKSUM1;
    // let bytes = MEMBERSHIPREQUESTBADCHECKSUM1.0.clone();
    let result = Packet::decode(&mut Bytes::copy_from_slice(bytes));
    assert!(result.is_err(), "Expected error for bad checksum");
}
