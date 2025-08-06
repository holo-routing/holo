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
use holo_ospf::packet::lsa::Lsa;
use holo_ospf::version::Ospfv2;
use holo_utils::ip::AddressFamily;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut bytes = Bytes::copy_from_slice(data);
    let _ = Lsa::<Ospfv2>::decode(AddressFamily::Ipv4, &mut bytes);
});
