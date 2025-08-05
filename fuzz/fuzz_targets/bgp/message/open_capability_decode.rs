#![no_main]

use bytes::Bytes;
use holo_bgp::packet::message::Capability;
use holo_utils::bytes::BytesExt;
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = Bytes::arbitrary(&mut u) {
        let _ = Capability::decode(&mut buf);
    }
});
