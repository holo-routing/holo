#![no_main]

use std::net::Ipv4Addr;

use holo_bgp::packet::attribute::Attrs;
use holo_bgp::packet::message::DecodeCxt;
use holo_utils::arbitrary::BytesArbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(mut buf) = BytesArbitrary::arbitrary(&mut u)
        && let Ok(cxt) = DecodeCxt::arbitrary(&mut u)
        && let Ok(mut nexthop) = Option::<Ipv4Addr>::arbitrary(&mut u)
        && let Ok(nlri_present) = bool::arbitrary(&mut u)
    {
        let _ = Attrs::decode(
            &mut buf.0,
            &cxt,
            &mut nexthop,
            nlri_present,
            &mut None,
            &mut None,
        );
    }
});
