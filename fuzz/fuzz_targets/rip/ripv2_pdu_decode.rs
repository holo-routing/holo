//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//
#![no_main]

use bytes::Bytes;
use holo_rip::packet::PduVersion;
use holo_rip::ripng::packet::Pdu;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    let _ = Pdu::decode(&bytes, None);
});
