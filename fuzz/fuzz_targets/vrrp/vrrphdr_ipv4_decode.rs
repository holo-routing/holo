//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//
#![no_main]

use holo_utils::ip::AddressFamily;
use holo_vrrp::packet::VrrpHdr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = VrrpHdr::decode(data, AddressFamily::Ipv4);
});
