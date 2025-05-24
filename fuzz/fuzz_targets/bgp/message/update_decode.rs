#![no_main]

use holo_bgp::packet::message::{DecodeCxt, UpdateMsg};
use holo_utils::arbitrary::BytesArbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = BytesArbitrary::arbitrary(&mut u)
        && let Ok(msg_len) = u16::arbitrary(&mut u)
        && let Ok(cxt) = DecodeCxt::arbitrary(&mut u)
    {
        let _ = UpdateMsg::decode(&mut buf.0, msg_len, &cxt);
    }
});
