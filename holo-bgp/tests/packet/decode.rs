use std::net::Ipv4Addr;

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use holo_bgp::packet::attribute::{AsPath, Attrs};
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

#[test]
fn test_crash_bgp_as_path_decode_single_byte() {
    // Crash artifact: crash-c4ea21bb365bbeeaf5f2c654883e56d11e43c44e
    // Input: [0x02]
    // Error: advance out of bounds: the len is 0 but advancing by 1
    // Found at commit fe796207 during extended fuzzing session

    let data = &[0x02];
    let mut buf = Bytes::from_static(data);

    let mut u = Unstructured::new(&[]);
    if let Ok(cxt) = DecodeCxt::arbitrary(&mut u) {
        let mut nexthop = None::<Ipv4Addr>;
        let nlri_present = false;

        // This call should not panic - it should either succeed gracefully or fail gracefully
        let result = Attrs::decode(
            &mut buf,
            &cxt,
            &mut nexthop,
            nlri_present,
            &mut None,
            &mut None,
        );

        // The key test is that this does NOT panic - the result can be Ok or Err
        // If we reach this point, the crash has been fixed (no panic occurred)
        println!(
            "Test passed - no panic occurred. Result: {:?}",
            result.is_ok()
        );
    }
}

#[test]
fn test_crash_bgp_attrs_decode_four_bytes() {
    // Crash artifact: crash-a873257739e6a0656db29f3e77fd415004e1c6a3
    // Input: [0x47, 0x02, 0x01, 0x01]
    // Error: advance out of bounds: the len is 0 but advancing by 1
    // Found at commit fe796207 during extended fuzzing session

    let data = &[0x47, 0x02, 0x01, 0x01];
    let mut buf = Bytes::from_static(data);

    let mut u = Unstructured::new(&[]);
    if let Ok(cxt) = DecodeCxt::arbitrary(&mut u) {
        let mut nexthop = None::<Ipv4Addr>;
        let nlri_present = false;

        // This call should not panic - it should either succeed gracefully or fail gracefully
        let result = Attrs::decode(
            &mut buf,
            &cxt,
            &mut nexthop,
            nlri_present,
            &mut None,
            &mut None,
        );

        // The key test is that this does NOT panic - the result can be Ok or Err
        // If we reach this point, the crash has been fixed (no panic occurred)
        println!(
            "Test passed - no panic occurred. Result: {:?}",
            result.is_ok()
        );
    }
}

#[test]
fn test_crash_bgp_empty_input() {
    // Crash artifact: crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
    // Input: [] (empty)
    // Error: advance out of bounds: the len is 0 but advancing by 1
    // Found at commit fe796207 during extended fuzzing session

    let data = &[];
    let mut buf = Bytes::from_static(data);

    let mut u = Unstructured::new(&[]);
    if let Ok(cxt) = DecodeCxt::arbitrary(&mut u) {
        let mut nexthop = None::<Ipv4Addr>;
        let nlri_present = false;

        // This call should not panic - it should either succeed gracefully or fail gracefully
        let result = Attrs::decode(
            &mut buf,
            &cxt,
            &mut nexthop,
            nlri_present,
            &mut None,
            &mut None,
        );

        // The key test is that this does NOT panic - the result can be Ok or Err
        // If we reach this point, the crash has been fixed (no panic occurred)
        println!(
            "Test passed - no panic occurred. Result: {:?}",
            result.is_ok()
        );
    }
}
