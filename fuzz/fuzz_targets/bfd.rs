#![no_main]

use holo_bfd::packet::Packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
});
