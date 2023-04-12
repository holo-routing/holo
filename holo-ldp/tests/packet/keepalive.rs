use super::*;

static KEEPALIVE_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09],
        KeepaliveMsg { msg_id: 9 }.into(),
    )
});

#[test]
fn test_encode_keepalive() {
    let (ref bytes, ref msg) = *KEEPALIVE_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_keepalive() {
    let (ref bytes, ref msg) = *KEEPALIVE_MSG1;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}
