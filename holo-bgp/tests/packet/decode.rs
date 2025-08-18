use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use holo_bgp::packet::attribute::AsPath;
use holo_bgp::packet::consts::AttrType;
use holo_bgp::packet::message::DecodeCxt;
use holo_utils::bytes::BytesExt;

#[test]
fn small_buffer() {
    // This reproduces a panic found using fuzz testing.
    // It's a proof-of-concept to explore the feasibility of creating
    // unit tests for issues found by fuzzing inputs. It should run much
    // faster than the fuzz tests.
    let mut u = Unstructured::new(&[4u8]);
    let mut v = Unstructured::new(&[0u8]);
    let mut w = Unstructured::new(&[0u8]);
    let mut x = Unstructured::new(&[0u8]);

    if let Ok(mut buf) = Bytes::arbitrary(&mut u)
        && let Ok(cxt) = DecodeCxt::arbitrary(&mut v)
        && let Ok(attr_type) = AttrType::arbitrary(&mut w)
        && let Ok(four_byte_asn_cap) = bool::arbitrary(&mut x)
    {
        let _ = AsPath::decode(
            &mut buf,
            &cxt,
            attr_type,
            four_byte_asn_cap,
            &mut None,
        );
    }
}
