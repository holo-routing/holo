#![no_main]

use holo_bgp::packet::message::KeepaliveMsg;
use holo_utils::bytes::BytesWrapper;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // NotificationMsg decoding.
    if let Ok(mut buf) = BytesWrapper::arbitrary(&mut u)
        && let Ok(msg_len) = u16::arbitrary(&mut u)
    {
        let _ = KeepaliveMsg::decode(&mut buf.0, msg_len);
    }
});
