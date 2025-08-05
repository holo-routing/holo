#![no_main]

use bytes::Bytes;
use holo_bgp::packet::message::{DecodeCxt, UpdateMsg};
use holo_utils::bytes::BytesExt;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = Bytes::arbitrary(&mut u)
        && let Ok(cxt) = DecodeCxt::arbitrary(&mut u)
    {
        let _ = UpdateMsg::decode(&mut buf, &cxt);
    }
});
