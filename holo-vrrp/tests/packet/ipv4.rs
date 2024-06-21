//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//


// the ipv4 Packet header details that will be used in IPV4 tests
// - version: 4
// - header length: 20
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
        0xc0, 0xa8, 0x61, 0x10
    ]
}


