//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::sync::LazyLock as Lazy;

use holo_bfd::packet::{DecodeError, Packet, PacketFlags};
use holo_utils::bfd::State;

//
// Helper functions.
//

fn test_encode_packet(
    bytes_expected: &[u8],
    packet: &Result<Packet, DecodeError>,
) {
    let bytes_actual = packet.as_ref().unwrap().encode();
    assert_eq!(bytes_expected, bytes_actual.as_ref());
}

fn test_decode_packet(
    bytes: &[u8],
    packet_expected: &Result<Packet, DecodeError>,
) {
    let packet_actual = Packet::decode(&bytes);
    assert_eq!(*packet_expected, packet_actual);
}

//
// Test packets.
//

static PACKET1: Lazy<(Vec<u8>, Result<Packet, DecodeError>)> =
    Lazy::new(|| {
        (
            vec![
                0x20, 0xc0, 0x03, 0x18, 0x9f, 0xb2, 0x05, 0xd6, 0x4a, 0x23,
                0x57, 0xdc, 0x00, 0x04, 0x93, 0xe0, 0x00, 0x04, 0x93, 0xe0,
                0x00, 0x00, 0xc3, 0x50,
            ],
            Ok(Packet {
                version: 1,
                diag: 0,
                state: State::Up,
                flags: PacketFlags::empty(),
                detect_mult: 3,
                my_discr: 0x9fb205d6,
                your_discr: 0x4a2357dc,
                desired_min_tx: 300000,
                req_min_rx: 300000,
                req_min_echo_rx: 50000,
            }),
        )
    });

//
// Tests.
//

#[test]
fn test_encode_packet1() {
    let (ref bytes, ref packet) = *PACKET1;
    test_encode_packet(bytes, packet);
}

#[test]
fn test_decode_packet1() {
    let (ref bytes, ref packet) = *PACKET1;
    test_decode_packet(bytes, packet);
}
