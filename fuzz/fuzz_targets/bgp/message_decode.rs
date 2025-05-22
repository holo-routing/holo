#![no_main]

use holo_bgp::packet::message::{DecodeCxt, Message};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(cxt) = DecodeCxt::arbitrary(&mut u) {
        let _ = Message::decode(data, &cxt);
    }
});
