use super::*;

static CAPABILITY_MSG1: Lazy<(Vec<u8>, Message)> = Lazy::new(|| {
    (
        vec![
            0x02, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x85, 0x0b, 0x00,
            0x01, 0x80,
        ],
        CapabilityMsg {
            msg_id: 1,
            twcard_fec: Some(TlvCapTwcardFec(true)),
            unrec_notif: None,
        }
        .into(),
    )
});

#[test]
fn test_encode_capability1() {
    let (ref bytes, ref msg) = *CAPABILITY_MSG1;
    test_encode_msg(bytes, msg);
}

#[test]
fn test_decode_capability1() {
    let (ref bytes, ref msg) = *CAPABILITY_MSG1;
    IPV4_CXT.with(|cxt| test_decode_msg(cxt, bytes, msg));
}
