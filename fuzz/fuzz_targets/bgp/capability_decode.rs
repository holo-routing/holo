#![no_main]

use holo_bgp::packet::message::Capability;
use holo_utils::bytes::BytesWrapper;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // OpenMsg decoding.
    if let Ok(mut buf) = BytesWrapper::arbitrary(&mut u) {
        let _ = Capability::decode(&mut buf.0);
    }
});
