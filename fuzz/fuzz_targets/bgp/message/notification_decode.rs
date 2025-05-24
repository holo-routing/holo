#![no_main]

use holo_bgp::packet::message::NotificationMsg;
use holo_utils::arbitrary::BytesArbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = BytesArbitrary::arbitrary(&mut u) {
        let _ = NotificationMsg::decode(&mut buf.0);
    }
});
