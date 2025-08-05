#![no_main]

use bytes::Bytes;
use holo_bgp::packet::attribute::Aggregator;
use holo_bgp::packet::consts::AttrType;
use holo_utils::bytes::BytesExt;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = Bytes::arbitrary(&mut u)
        && let Ok(attr_type) = AttrType::arbitrary(&mut u)
        && let Ok(four_byte_asn_cap) = bool::arbitrary(&mut u)
    {
        let _ = Aggregator::decode(
            &mut buf,
            attr_type,
            four_byte_asn_cap,
            &mut None,
        );
    }
});
