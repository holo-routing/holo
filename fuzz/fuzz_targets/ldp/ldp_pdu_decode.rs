//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//
#![no_main]

use const_addrs::ip;
use holo_ldp::packet::{DecodeCxt, PacketInfo, Pdu};
use libfuzzer_sys::fuzz_target;

const IPV4_CXT: DecodeCxt = DecodeCxt {
    pkt_info: PacketInfo {
        src_addr: ip!("1.1.1.1"),
        multicast: None,
    },
    pdu_max_len: Pdu::DFLT_MAX_LEN,
    validate_pdu_hdr: None,
    validate_msg_hdr: None,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(pdu_size) = Pdu::get_pdu_size(data, &IPV4_CXT) {
        let _ = Pdu::decode(&data[0..pdu_size], &IPV4_CXT);
    }
});
